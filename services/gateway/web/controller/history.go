/**
 *
 * (c) Copyright Ascensio System SIA 2026
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package controller

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared"
	aclient "github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/client"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/golang-jwt/jwt/v5"
	"go-micro.dev/v4/client"
	"golang.org/x/sync/errgroup"
)

type HistoryController struct {
	client     client.Client
	api        aclient.DropboxClient
	jwtManager crypto.JwtManager
	onlyoffice *shared.OnlyofficeConfig
	config     *config.ServerConfig
	logger     log.Logger
}

func NewHistoryController(
	client client.Client,
	api aclient.DropboxClient,
	jwtManager crypto.JwtManager,
	onlyoffice *shared.OnlyofficeConfig,
	config *config.ServerConfig,
	logger log.Logger,
) HistoryController {
	return HistoryController{
		client:     client,
		api:        api,
		jwtManager: jwtManager,
		onlyoffice: onlyoffice,
		config:     config,
		logger:     logger,
	}
}

func (c HistoryController) getUserID(rw http.ResponseWriter, r *http.Request) (string, bool) {
	uid := rw.Header().Get("X-User")
	if uid == "" {
		c.logger.Errorf("authorization context has no user id")
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return "", false
	}
	return uid, true
}

func (c HistoryController) fetchUser(ctx context.Context, uid string) (response.UserResponse, error) {
	var ures response.UserResponse
	err := c.client.Call(ctx, c.client.NewRequest(
		fmt.Sprintf("%s:auth", c.config.Namespace), "UserSelectHandler.GetUser",
		uid,
	), &ures)
	return ures, err
}

func (c HistoryController) runWithTimeout(r *http.Request, rw http.ResponseWriter, fn func(ctx context.Context)) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	fn(ctx)
}

func (c HistoryController) writeJSONResponse(rw http.ResponseWriter, status int, body []byte) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	rw.Write(body)
}

func (c HistoryController) handleError(rw http.ResponseWriter, msg string, code int, err error) {
	if err != nil {
		c.logger.Errorf("%s: %v", msg, err)
	} else {
		c.logger.Error(msg)
	}
	http.Error(rw, http.StatusText(code), code)
}

func (c HistoryController) BuildGetFileHistory() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		c.runWithTimeout(r, rw, func(ctx context.Context) {
			uid, ok := c.getUserID(rw, r)
			if !ok {
				return
			}

			fid := r.URL.Query().Get("file_id")
			if fid == "" {
				c.handleError(rw, "could not extract file_id from url parameters", http.StatusBadRequest, nil)
				return
			}

			ures, err := c.fetchUser(ctx, uid)
			if err != nil {
				c.handleError(rw, fmt.Sprintf("could not get user with id %s", uid), http.StatusUnauthorized, err)
				return
			}

			var versions response.DropboxFileVersionsResponse
			var user response.DropboxUserResponse

			g, gctx := errgroup.WithContext(ctx)
			g.Go(func() error {
				u, err := c.api.GetUser(gctx, ures.AccessToken)
				if err == nil {
					user = u
				} else {
					c.logger.Errorf("could not get dropbox user: %v", err)
				}
				return err
			})

			g.Go(func() error {
				v, err := c.api.GetFileVersions(gctx, fid, ures.AccessToken)
				if err == nil {
					versions = v
				} else {
					c.logger.Errorf("could not get dropbox file %s revisions: %v", fid, err)
				}
				return err
			})

			if err := g.Wait(); err != nil {
				c.handleError(rw, "error fetching file versions or user", http.StatusBadRequest, err)
				return
			}

			if len(versions.Entries) < 1 {
				res := response.FileHistoryResponse{CurrentVersion: 1}
				c.writeJSONResponse(rw, http.StatusOK, res.ToJSON())
				return
			}

			res := &response.FileHistoryResponse{
				CurrentVersion: len(versions.Entries),
				History:        make([]response.FileHistoryEntry, 0, len(versions.Entries)),
			}

			for idx, val := range versions.Entries {
				res.History = append(res.History, response.FileHistoryEntry{
					Created: val.ClientModified,
					Key:     val.Rev,
					Version: idx + 1,
					User: response.FileHistoryUser{
						ID:    user.AccountID,
						Name:  user.Name.DisplayName,
						Image: user.ProfilePicture,
					},
				})
			}

			c.writeJSONResponse(rw, http.StatusOK, res.ToJSON())
		})
	}
}

func (c HistoryController) BuildGetFileHistoryLinks() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		c.runWithTimeout(r, rw, func(ctx context.Context) {
			uid, ok := c.getUserID(rw, r)
			if !ok {
				return
			}

			current := r.URL.Query().Get("current")
			if current == "" {
				c.handleError(rw, "could not get file history link. Got empty current parameter", http.StatusBadRequest, nil)
				return
			}

			versionStr := r.URL.Query().Get("version")
			version, err := strconv.Atoi(versionStr)
			if err != nil {
				c.handleError(rw, "could not get a valid numeric file version", http.StatusBadRequest, err)
				return
			}

			ures, err := c.fetchUser(ctx, uid)
			if err != nil {
				c.handleError(rw, fmt.Sprintf("could not get user with id %s", uid), http.StatusUnauthorized, err)
				return
			}

			var link response.DropboxDownloadResponse
			var file response.DropboxFileResponse
			g, gctx := errgroup.WithContext(ctx)

			g.Go(func() error {
				l, err := c.api.GetDownloadLink(gctx, fmt.Sprintf("rev:%s", current), ures.AccessToken)
				if err == nil {
					link = l
				} else {
					c.logger.Errorf("could not get dropbox user: %v", err)
				}
				return err
			})

			g.Go(func() error {
				f, err := c.api.GetFile(gctx, fmt.Sprintf("rev:%s", current), ures.AccessToken)
				if err == nil {
					file = f
				} else {
					c.logger.Errorf("could not get dropbox file by revision %s: %v", current, err)
				}
				return err
			})

			if err := g.Wait(); err != nil {
				c.handleError(rw, "error getting file history links", http.StatusBadRequest, err)
				return
			}

			res := response.FileHistoryData{
				Key:     file.Rev,
				URL:     link.Link,
				Version: version,
			}

			res.IssuedAt = jwt.NewNumericDate(time.Now())
			res.ExpiresAt = jwt.NewNumericDate(time.Now().Add(5 * time.Minute))
			token, err := c.jwtManager.Sign(c.onlyoffice.Onlyoffice.Builder.DocumentServerSecret, res)
			if err != nil {
				c.handleError(rw, "could not sign jwt token", http.StatusBadRequest, err)
				return
			}

			res.Token = token
			c.writeJSONResponse(rw, http.StatusOK, res.ToJSON())
		})
	}
}
