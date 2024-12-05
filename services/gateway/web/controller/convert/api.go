/**
 *
 * (c) Copyright Ascensio System SIA 2024
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

package convert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared"
	aclient "github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/client"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/onlyoffice"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"go-micro.dev/v4/client"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
)

type ConvertController struct {
	client      client.Client
	api         aclient.DropboxClient
	jwtManager  crypto.JwtManager
	fileUtil    onlyoffice.OnlyofficeFileUtility
	store       *sessions.CookieStore
	server      *config.ServerConfig
	hasher      crypto.Hasher
	credentials *oauth2.Config
	onlyoffice  *shared.OnlyofficeConfig
	logger      log.Logger
}

func NewConvertController(
	client client.Client, api aclient.DropboxClient, jwtManager crypto.JwtManager,
	fileUtil onlyoffice.OnlyofficeFileUtility, onlyoffice *shared.OnlyofficeConfig, hasher crypto.Hasher,
	server *config.ServerConfig, credentials *oauth2.Config, logger log.Logger,
) ConvertController {
	return ConvertController{
		client:      client,
		api:         api,
		jwtManager:  jwtManager,
		fileUtil:    fileUtil,
		store:       sessions.NewCookieStore([]byte(credentials.ClientSecret)),
		server:      server,
		hasher:      hasher,
		credentials: credentials,
		onlyoffice:  onlyoffice,
		logger:      logger,
	}
}

func (c ConvertController) convertFile(ctx context.Context, uid, fileID string) (*request.ConvertActionRequest, error) {
	uctx, cancel := context.WithTimeout(ctx, time.Duration(c.onlyoffice.Onlyoffice.Callback.UploadTimeout)*time.Second)
	defer cancel()

	var ures response.UserResponse
	if err := c.client.Call(uctx, c.client.NewRequest(
		fmt.Sprintf("%s:auth", c.server.Namespace), "UserSelectHandler.GetUser",
		fmt.Sprint(uid),
	), &ures); err != nil {
		c.logger.Errorf("could not get user %s access info: %s", uid, err.Error())
		return nil, err
	}

	var file response.DropboxFileResponse
	var dres response.DropboxDownloadResponse
	g, gctx := errgroup.WithContext(uctx)
	g.Go(func() error {
		var err error
		file, err = c.api.GetFile(gctx, fileID, ures.AccessToken)
		if err != nil {
			c.logger.Errorf("could not get file: %s", err.Error())
			return err
		}
		return nil
	})

	g.Go(func() error {
		var err error
		dres, err = c.api.GetDownloadLink(gctx, fileID, ures.AccessToken)
		if err != nil {
			c.logger.Errorf("could not get download link: %s", err.Error())
			return err
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	ext := c.fileUtil.GetFileExt(file.Name)
	fType, err := c.fileUtil.GetFileType(ext)
	if err != nil {
		c.logger.Debugf("could not get file type: %s", err.Error())
		return nil, err
	}

	if ext == "csv" {
		return nil, ErrCsvIsNotSupported
	}

	creq := request.ConvertRequest{
		Async:      false,
		Key:        string(c.hasher.Hash(file.CModified + file.ID + time.Now().String())),
		Filetype:   fType,
		Outputtype: "ooxml",
		URL:        dres.Link,
	}
	creq.IssuedAt = jwt.NewNumericDate(time.Now())
	creq.ExpiresAt = jwt.NewNumericDate(time.Now().Add(2 * time.Minute))
	ctok, err := c.jwtManager.Sign(c.onlyoffice.Onlyoffice.Builder.DocumentServerSecret, creq)
	if err != nil {
		return nil, err
	}

	creq.Token = ctok
	reqBody, err := json.Marshal(creq)
	if err != nil {
		c.logger.Errorf("could not marshal convert request: %s", err.Error())
		return nil, err
	}

	req, err := http.NewRequestWithContext(
		uctx,
		http.MethodPost,
		fmt.Sprintf("%s/ConvertService.ashx", c.onlyoffice.Onlyoffice.Builder.DocumentServerURL),
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		c.logger.Errorf("could not build conversion API request: %s", err.Error())
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	resp, err := otelhttp.DefaultClient.Do(req)
	if err != nil {
		c.logger.Errorf("could not send conversion API request: %s", err.Error())
		return nil, err
	}

	defer resp.Body.Close()

	var cresp response.ConvertResponse
	if err := json.NewDecoder(resp.Body).Decode(&cresp); err != nil {
		c.logger.Errorf("could not decode convert response body: %s", err.Error())
		return nil, err
	}

	cfile, err := otelhttp.Get(uctx, cresp.FileURL)
	if err != nil {
		c.logger.Errorf("could not retrieve converted file: %s", err.Error())
		return nil, err
	}

	defer cfile.Body.Close()
	filename := fmt.Sprintf("%s.%s", file.Name[:len(file.Name)-len(filepath.Ext(file.Name))], cresp.FileType)
	newPath := fmt.Sprintf("%s/%s", file.PathLower[:strings.LastIndex(file.PathLower, "/")], filename)
	uplres, err := c.api.CreateFile(ctx, newPath, ures.AccessToken, cfile.Body)
	if err != nil {
		c.logger.Errorf("could not upload converted file %s: %s", fileID, err.Error())
		return nil, err
	}

	return &request.ConvertActionRequest{
		Action:    "edit",
		FileID:    uplres.ID,
		ForceEdit: false,
	}, nil
}

func (c ConvertController) BuildConvertFile() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		uid := rw.Header().Get("X-User")
		if uid == "" {
			c.logger.Errorf("authorization context has no user id")
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		var creq request.ConvertActionRequest
		if err := json.NewDecoder(r.Body).Decode(&creq); err != nil {
			c.logger.Errorf("could not parse conversion request: %s", err.Error())
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		if creq.Action == "edit" {
			creq.ForceEdit = true
		}

		creq.IssuedAt = jwt.NewNumericDate(time.Now())
		creq.ExpiresAt = jwt.NewNumericDate(time.Now().Add(5 * time.Minute))
		token, err := c.jwtManager.Sign(c.credentials.ClientSecret, creq)
		if err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		if creq.Action == "create" {
			ncreq, err := c.convertFile(r.Context(), uid, creq.FileID)
			if err != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				return
			}

			sig, err := c.jwtManager.Sign(c.credentials.ClientSecret, ncreq)
			if err != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				return
			}

			http.Redirect(
				rw, r,
				fmt.Sprintf(
					"/editor?token=%s",
					sig,
				),
				http.StatusMovedPermanently,
			)

			return
		}

		http.Redirect(
			rw, r,
			fmt.Sprintf(
				"/editor?token=%s",
				token,
			),
			http.StatusMovedPermanently,
		)
	}
}
