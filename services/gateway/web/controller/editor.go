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
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/embeddable"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared"
	aclient "github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/client"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/onlyoffice"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"github.com/mileusna/useragent"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"go-micro.dev/v4/client"
	"golang.org/x/oauth2"
)

type EditorController struct {
	client      client.Client
	api         aclient.DropboxClient
	jwtManager  crypto.JwtManager
	hasher      crypto.Hasher
	fileUtil    onlyoffice.OnlyofficeFileUtility
	store       *sessions.CookieStore
	server      *config.ServerConfig
	onlyoffice  *shared.OnlyofficeConfig
	credentials *oauth2.Config
	logger      log.Logger
}

func NewEditorController(
	client client.Client,
	api aclient.DropboxClient,
	jwtManager crypto.JwtManager,
	hasher crypto.Hasher,
	fileUtil onlyoffice.OnlyofficeFileUtility,
	server *config.ServerConfig,
	onlyoffice *shared.OnlyofficeConfig,
	credentials *oauth2.Config,
	logger log.Logger,
) EditorController {
	return EditorController{
		client:      client,
		api:         api,
		jwtManager:  jwtManager,
		hasher:      hasher,
		fileUtil:    fileUtil,
		store:       sessions.NewCookieStore([]byte(credentials.ClientSecret)),
		server:      server,
		onlyoffice:  onlyoffice,
		credentials: credentials,
		logger:      logger,
	}
}

func (c EditorController) BuildEditorPage() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/html")
		uid := rw.Header().Get("X-User")
		if uid == "" {
			http.Redirect(rw, r, "/oauth/auth", http.StatusMovedPermanently)
			return
		}

		var token jwt.MapClaims
		if err := c.jwtManager.Verify(c.credentials.ClientSecret, r.URL.Query().Get("token"), &token); err != nil {
			http.Redirect(rw, r, "/oauth/auth", http.StatusMovedPermanently)
			return
		}

		fileID, ok := token["file_id"].(string)
		if !ok {
			http.Redirect(rw, r, "/oauth/auth", http.StatusMovedPermanently)
			return
		}

		var ures response.UserResponse
		if err := c.client.Call(r.Context(), c.client.NewRequest(
			fmt.Sprintf("%s:auth", c.server.Namespace), "UserSelectHandler.GetUser",
			uid,
		), &ures); err != nil {
			c.logger.Debugf("could not get user %d access info: %s", uid, err.Error())
			// TODO: Generic error page
			embeddable.ErrorPage.ExecuteTemplate(rw, "error", nil)
			return
		}

		var config response.ConfigResponse
		var wg sync.WaitGroup
		wg.Add(3)
		errChan := make(chan error, 3)
		userChan := make(chan response.DropboxUserResponse, 1)
		fileChan := make(chan response.DropboxFileResponse, 1)
		downloadChan := make(chan response.DropboxDownloadResponse, 1)

		go func() {
			defer wg.Done()
			uresp, err := c.api.GetUser(r.Context(), ures.AccessToken)
			if err != nil {
				errChan <- err
				return
			}

			userChan <- uresp
		}()

		go func() {
			defer wg.Done()
			file, err := c.api.GetFile(r.Context(), fileID, ures.AccessToken)
			if err != nil {
				errChan <- err
				return
			}

			fileChan <- file
		}()

		go func() {
			defer wg.Done()
			dres, err := c.api.GetDownloadLink(r.Context(), fileID, ures.AccessToken)
			if err != nil {
				errChan <- err
				return
			}

			downloadChan <- dres
		}()

		c.logger.Debug("waiting for goroutines to finish")
		wg.Wait()
		c.logger.Debug("goroutines have finished")

		select {
		case err := <-errChan:
			c.logger.Errorf("could not get user/file: %s", err.Error())
			// TODO: Generic error page
			embeddable.ErrorPage.ExecuteTemplate(rw, "error", nil)
			return
		case <-r.Context().Done():
			c.logger.Warn("current request took longer than expected")
			// TODO: Generic error page
			embeddable.ErrorPage.ExecuteTemplate(rw, "error", nil)
			return
		default:
		}

		eType := "desktop"
		ua := useragent.Parse(r.UserAgent())
		if ua.Mobile || ua.Tablet {
			eType = "mobile"
		}

		durl := <-downloadChan
		file := <-fileChan
		usr := <-userChan
		loc := i18n.NewLocalizer(embeddable.Bundle, usr.Locale)
		errMsg := map[string]interface{}{
			"errorMain": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "errorMain",
			}),
			"errorSubtext": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "errorSubtext",
			}),
			"reloadButton": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "reloadButton",
			}),
		}

		config = response.ConfigResponse{
			Document: response.Document{
				Key:   string(c.hasher.Hash(file.ID + file.SModified)),
				Title: file.Name,
				URL:   durl.Link,
			},
			EditorConfig: response.EditorConfig{
				User: response.User{
					ID:   usr.AccountID,
					Name: usr.Name.DisplayName,
				},
				CallbackURL: fmt.Sprintf(
					"%s/callback?id=%s",
					c.onlyoffice.Onlyoffice.Builder.CallbackURL, file.ID,
				),
				Customization: response.Customization{
					Goback: response.Goback{
						RequestClose: false,
					},
					Plugins:       false,
					HideRightMenu: false,
				},
				Lang: usr.Locale,
			},
			Type:      eType,
			ServerURL: c.onlyoffice.Onlyoffice.Builder.DocumentServerURL,
		}

		if strings.TrimSpace(file.Name) != "" {
			var (
				fileType string
				err      error
			)
			ext := c.fileUtil.GetFileExt(file.Name)
			fileType, err = c.fileUtil.GetFileType(ext)
			if err != nil {
				c.logger.Errorf("could not get file type: %s", err.Error())
				embeddable.ErrorPage.ExecuteTemplate(rw, "error", errMsg)
				return
			}

			config.Document.FileType = ext
			config.Document.Permissions = response.Permissions{
				Edit:                 c.fileUtil.IsExtensionEditable(ext) || (c.fileUtil.IsExtensionLossEditable(ext) && token["force_edit"].(bool)),
				Comment:              true,
				Download:             true,
				Print:                false,
				Review:               false,
				Copy:                 true,
				ModifyContentControl: true,
				ModifyFilter:         true,
			}
			config.DocumentType = fileType
		}

		sig, err := c.jwtManager.Sign(c.onlyoffice.Onlyoffice.Builder.DocumentServerSecret, config)
		if err != nil {
			c.logger.Debugf("could not sign document server config: %s", err.Error())
			embeddable.ErrorPage.ExecuteTemplate(rw, "error", errMsg)
			return
		}

		config.Token = sig
		embeddable.EditorPage.Execute(rw, map[string]interface{}{
			"apijs":   fmt.Sprintf("%s/web-apps/apps/api/documents/api.js", config.ServerURL),
			"config":  string(config.ToJSON()),
			"docType": config.DocumentType,
			"cancelButton": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "cancelButton",
			}),
		})
	}
}
