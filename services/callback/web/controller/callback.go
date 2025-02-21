/**
 *
 * (c) Copyright Ascensio System SIA 2025
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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared"
	aclient "github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/client"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	plog "github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"go-micro.dev/v4/client"
	"go-micro.dev/v4/util/backoff"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
)

var ErrInvalidContentLength = errors.New("content length exceeds the limit")

type CallbackController struct {
	client      client.Client
	api         aclient.DropboxClient
	jwtManger   crypto.JwtManager
	server      *config.ServerConfig
	credentials *oauth2.Config
	onlyoffice  *shared.OnlyofficeConfig
	logger      plog.Logger
}

func NewCallbackController(
	client client.Client,
	api aclient.DropboxClient,
	jwtManger crypto.JwtManager,
	server *config.ServerConfig,
	credentials *oauth2.Config,
	onlyoffice *shared.OnlyofficeConfig,
	logger plog.Logger,
) CallbackController {
	return CallbackController{
		client:      client,
		api:         api,
		jwtManger:   jwtManger,
		server:      server,
		credentials: credentials,
		onlyoffice:  onlyoffice,
		logger:      logger,
	}
}

func (c *CallbackController) validateFileSize(ctx context.Context, limit int64, url string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize a new head request: %w", err)
	}

	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("failed to fetch file metadata: %w", err)
	}
	defer resp.Body.Close()

	contentLength, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid content-length: %w", err)
	}
	if contentLength > limit {
		return ErrInvalidContentLength
	}

	return nil
}

func (c CallbackController) sendErrorResponse(errorText string, rw http.ResponseWriter) {
	c.logger.Error(errorText)
	rw.WriteHeader(http.StatusBadRequest)
	if _, err := rw.Write(response.CallbackResponse{
		Error: 1,
	}.ToJSON()); err != nil {
		c.logger.Errorf("could not send a response: %w", err)
	}
}

func (c CallbackController) BuildPostHandleCallback() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		fileID := strings.TrimSpace(r.URL.Query().Get("id"))
		if fileID == "" {
			c.sendErrorResponse("file id is empty", rw)
			return
		}

		var body request.CallbackRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			c.sendErrorResponse(fmt.Sprintf("could not decode a callback body: %s", err.Error()), rw)
			return
		}

		if err := c.jwtManger.Verify(c.onlyoffice.Onlyoffice.Builder.DocumentServerSecret, body.Token, &body); err != nil {
			c.sendErrorResponse(
				fmt.Sprintf("could not verify callback jwt (%s). Reason: %s", body.Token, err.Error()),
				rw,
			)
			return
		}

		if err := body.Validate(); err != nil {
			c.sendErrorResponse(fmt.Sprintf("invalid callback body: %s", err.Error()), rw)
			return
		}

		if body.Status == 2 {
			tctx, cancel := context.WithTimeout(
				r.Context(),
				time.Duration(c.onlyoffice.Onlyoffice.Callback.UploadTimeout)*time.Second,
			)
			defer cancel()

			if err := c.validateFileSize(tctx, c.onlyoffice.Onlyoffice.Callback.MaxSize, body.URL); err != nil {
				c.sendErrorResponse(fmt.Sprintf("could not send a head request: %s", err.Error()), rw)
				return
			}

			usr := body.Users[0]
			if usr != "" {
				req := c.client.NewRequest(
					fmt.Sprintf("%s:auth", c.server.Namespace), "UserSelectHandler.GetUser", usr,
				)
				var ures response.UserResponse
				if err := c.client.Call(tctx, req, &ures,
					client.WithRetries(3),
					client.WithBackoff(func(ctx context.Context, req client.Request, attempts int) (time.Duration, error) {
						return backoff.Do(attempts), nil
					})); err != nil {
					c.sendErrorResponse(fmt.Sprintf(
						"could not process a callback request with status 2: %s", err.Error(),
					), rw)
					return
				}

				respFile, err := otelhttp.Get(tctx, body.URL)
				if err != nil {
					c.sendErrorResponse(fmt.Sprintf(
						"could not process a callback request with status 2: %s", err.Error(),
					), rw)
					return
				}
				defer respFile.Body.Close()
				fl, err := c.api.GetFile(tctx, fileID, ures.AccessToken)
				if err != nil {
					c.sendErrorResponse(fmt.Sprintf("could not get file info: %s", err.Error()), rw)
					return
				}

				if _, err := c.api.UploadFile(tctx, fl.PathDisplay, ures.AccessToken, respFile.Body); err != nil {
					c.sendErrorResponse(fmt.Sprintf("could not upload file changes: %s", err.Error()), rw)
					return
				}
			}
		}

		rw.WriteHeader(http.StatusOK)
		if _, err := rw.Write(response.CallbackResponse{
			Error: 0,
		}.ToJSON()); err != nil {
			c.logger.Warnf("could not send a response: %w", err)
		}
	}
}
