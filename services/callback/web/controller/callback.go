/**
 *
 * (c) Copyright Ascensio System SIA 2023
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
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared"
	aclient "github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/client"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	plog "github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/onlyoffice"
	"go-micro.dev/v4/client"
	"go-micro.dev/v4/util/backoff"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
)

type CallbackController struct {
	client      client.Client
	api         aclient.DropboxClient
	jwtManger   crypto.JwtManager
	fileUtil    onlyoffice.OnlyofficeFileUtility
	server      *config.ServerConfig
	credentials *oauth2.Config
	onlyoffice  *shared.OnlyofficeConfig
	logger      plog.Logger
}

func NewCallbackController(
	client client.Client,
	api aclient.DropboxClient,
	jwtManger crypto.JwtManager,
	fileUtil onlyoffice.OnlyofficeFileUtility,
	server *config.ServerConfig,
	credentials *oauth2.Config,
	onlyoffice *shared.OnlyofficeConfig,
	logger plog.Logger,
) CallbackController {
	return CallbackController{
		client:      client,
		api:         api,
		jwtManger:   jwtManger,
		fileUtil:    fileUtil,
		server:      server,
		credentials: credentials,
		onlyoffice:  onlyoffice,
		logger:      logger,
	}
}

func (c CallbackController) sendErrorResponse(errorText string, rw http.ResponseWriter) {
	c.logger.Error(errorText)
	rw.WriteHeader(http.StatusBadRequest)
	rw.Write(response.CallbackResponse{
		Error: 1,
	}.ToJSON())
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
			if err := c.fileUtil.ValidateFileSize(
				tctx, c.onlyoffice.Onlyoffice.Callback.MaxSize, body.URL,
			); err != nil {
				c.sendErrorResponse(fmt.Sprintf(
					"file %s size exceeds the limit %d",
					body.Key, c.onlyoffice.Onlyoffice.Callback.MaxSize,
				), rw)
				return
			}

			usr := body.Users[0]
			if usr != "" {
				var wg sync.WaitGroup
				wg.Add(2)
				errChan := make(chan error, 2)
				userChan := make(chan response.UserResponse, 1)
				fileChan := make(chan io.ReadCloser, 1)

				resp, err := otelhttp.Head(tctx, body.URL)
				if err != nil {
					c.sendErrorResponse(fmt.Sprintf("could not send a head request: %s", err.Error()), rw)
					return
				}

				defer resp.Body.Close()
				if resp.ContentLength > c.onlyoffice.Onlyoffice.Callback.MaxSize {
					c.sendErrorResponse(
						fmt.Sprintf("could not proceed with worker: %s",
							onlyoffice.ErrInvalidContentLength.Error()), rw,
					)
					return
				}

				go func() {
					defer wg.Done()
					req := c.client.NewRequest(
						fmt.Sprintf("%s:auth", c.server.Namespace), "UserSelectHandler.GetUser", usr,
					)

					var ures response.UserResponse
					if err := c.client.Call(tctx, req, &ures, client.WithRetries(3), client.WithBackoff(func(ctx context.Context, req client.Request, attempts int) (time.Duration, error) {
						return backoff.Do(attempts), nil
					})); err != nil {
						errChan <- err
						return
					}

					userChan <- ures
				}()

				go func() {
					defer wg.Done()
					resp, err := otelhttp.Get(tctx, body.URL)
					if err != nil {
						errChan <- err
						return
					}

					fileChan <- resp.Body
				}()

				select {
				case err := <-errChan:
					c.sendErrorResponse(fmt.Sprintf(
						"could not process a callback request with status 2: %s", err.Error(),
					), rw)
					return
				case <-tctx.Done():
					c.sendErrorResponse("file upload has timed out", rw)
					return
				default:
				}

				ures := <-userChan
				body := <-fileChan
				defer body.Close()

				fl, err := c.api.GetFile(tctx, fileID, ures.AccessToken)
				if err != nil {
					c.sendErrorResponse(
						fmt.Sprintf("could not get file info: %s", err.Error()), rw,
					)
					return
				}

				if _, err := c.api.UploadFile(tctx, fl.PathDisplay, ures.AccessToken, body); err != nil {
					c.sendErrorResponse(
						fmt.Sprintf("could not upload file changes: %s", err.Error()), rw,
					)
					return
				}
			}
		}

		rw.WriteHeader(http.StatusOK)
		rw.Write(response.CallbackResponse{
			Error: 0,
		}.ToJSON())
	}
}
