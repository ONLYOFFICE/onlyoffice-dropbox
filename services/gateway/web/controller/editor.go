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
	"fmt"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/embeddable"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared"
	aclient "github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/client"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/format"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/mileusna/useragent"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"go-micro.dev/v4/client"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
)

type EditorController struct {
	client        client.Client
	api           aclient.DropboxClient
	jwtManager    crypto.JwtManager
	hasher        crypto.Hasher
	formatManager format.FormatManager
	store         *sessions.CookieStore
	server        *config.ServerConfig
	onlyoffice    *shared.OnlyofficeConfig
	credentials   *oauth2.Config
	logger        log.Logger
}

func NewEditorController(
	client client.Client,
	api aclient.DropboxClient,
	jwtManager crypto.JwtManager,
	hasher crypto.Hasher,
	formatManager format.FormatManager,
	server *config.ServerConfig,
	onlyoffice *shared.OnlyofficeConfig,
	credentials *oauth2.Config,
	logger log.Logger,
) EditorController {
	return EditorController{
		client:        client,
		api:           api,
		jwtManager:    jwtManager,
		hasher:        hasher,
		formatManager: formatManager,
		store:         sessions.NewCookieStore([]byte(credentials.ClientSecret)),
		server:        server,
		onlyoffice:    onlyoffice,
		credentials:   credentials,
		logger:        logger,
	}
}

func (c *EditorController) errorResponse(
	rw http.ResponseWriter,
	template *template.Template,
	errorMain, errorSubtext, reloadButton string,
) {
	if err := template.ExecuteTemplate(rw, "error", map[string]interface{}{
		"errorMain":    errorMain,
		"errorSubtext": errorSubtext,
		"reloadButton": reloadButton,
	}); err != nil {
		c.logger.Errorf("could not execute error template: %w", err)
	}
}

func (c *EditorController) fetchDropboxData(
	ctx context.Context,
	accessToken string,
	fileID string,
) (
	response.DropboxUserResponse,
	response.DropboxFileResponse,
	response.DropboxDownloadResponse,
	error,
) {
	g, ctx := errgroup.WithContext(ctx)

	var user response.DropboxUserResponse
	var file response.DropboxFileResponse
	var download response.DropboxDownloadResponse

	g.Go(func() error {
		resp, err := c.api.GetUser(ctx, accessToken)
		if err != nil {
			return fmt.Errorf("failed to get user data: %w", err)
		}
		user = resp
		return nil
	})

	g.Go(func() error {
		resp, err := c.api.GetFile(ctx, fileID, accessToken)
		if err != nil {
			return fmt.Errorf("failed to get file data: %w", err)
		}
		file = resp
		return nil
	})

	g.Go(func() error {
		resp, err := c.api.GetDownloadLink(ctx, fileID, accessToken)
		if err != nil {
			return fmt.Errorf("failed to get download link: %w", err)
		}
		download = resp
		return nil
	})

	if err := g.Wait(); err != nil {
		return user, file, download, err
	}

	return user, file, download, nil
}

func determineEditorType(userAgent string) string {
	ua := useragent.Parse(userAgent)
	if ua.Mobile || ua.Tablet {
		return "mobile"
	}
	return "desktop"
}

func (c *EditorController) prepareDocumentConfig(
	file response.DropboxFileResponse,
	user response.DropboxUserResponse,
	downloadLink response.DropboxDownloadResponse,
	token jwt.MapClaims,
	editorType string,
) (response.ConfigResponse, error) {
	config := response.ConfigResponse{
		Document: response.Document{
			Key:   string(c.hasher.Hash(file.ID + file.SModified)),
			Title: file.Name,
			URL:   downloadLink.Link,
		},
		EditorConfig: response.EditorConfig{
			User: response.User{
				ID:    user.AccountID,
				Name:  user.Name.DisplayName,
				Image: user.ProfilePicture,
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
			Lang: user.Locale,
		},
		Type:      editorType,
		ServerURL: c.onlyoffice.Onlyoffice.Builder.DocumentServerURL,
	}

	if strings.TrimSpace(file.Name) != "" {
		format, supported := c.formatManager.GetFormatByName(c.formatManager.GetFileExt(file.Name))
		if !supported {
			return config, fmt.Errorf("file type is not supported for file: %s", file.Name)
		}

		config.Document.FileType = format.Name
		config.Document.Permissions = response.Permissions{
			Edit:                 format.IsEditable() || (format.IsLossyEditable() && token["force_edit"].(bool)),
			Comment:              true,
			Download:             true,
			Print:                true,
			Review:               false,
			Copy:                 true,
			ModifyContentControl: true,
			ModifyFilter:         true,
		}

		if !config.Document.Permissions.Edit {
			config.Document.Key = uuid.NewString()
		}

		config.DocumentType = format.Type
	}

	return config, nil
}

func (c *EditorController) BuildEditorPage() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		rw.Header().Set("Content-Type", "text/html")
		uid := rw.Header().Get("X-User")
		if uid == "" {
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		fid := r.URL.Query().Get("file_id")
		var token jwt.MapClaims
		if err := c.jwtManager.Verify(c.credentials.ClientSecret, r.URL.Query().Get("token"), &token); err != nil {
			if fid == "" {
				http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
				return
			}

			http.Redirect(rw, r, fmt.Sprintf("/convert?file_id=%s", fid), http.StatusMovedPermanently)
			return
		}

		fileID, ok := token["file_id"].(string)
		if !ok {
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		if fileID != fid {
			c.errorResponse(rw, embeddable.ErrorPage,
				"Sorry, the document cannot be opened due to invalid url",
				"Please try again",
				"Reload")
			return
		}

		var ures response.UserResponse
		if err := c.client.Call(ctx, c.client.NewRequest(
			fmt.Sprintf("%s:auth", c.server.Namespace), "UserSelectHandler.GetUser",
			uid,
		), &ures); err != nil {
			c.logger.Debugf("could not get user %d access info: %s", uid, err.Error())
			c.errorResponse(rw, embeddable.ErrorPage,
				"Sorry, the document cannot be opened",
				"Please try again",
				"Reload")
			return
		}

		user, file, downloadLink, fetchErr := c.fetchDropboxData(ctx, ures.AccessToken, fileID)
		if fetchErr != nil {
			if downloadLink.Link == "" {
				loc := i18n.NewLocalizer(embeddable.Bundle, user.Locale)
				if err := embeddable.EmailPage.Execute(rw, map[string]interface{}{
					"titleText": loc.MustLocalize(&i18n.LocalizeConfig{
						MessageID: "emailMain",
					}),
					"subtitleTextOne": loc.MustLocalize(&i18n.LocalizeConfig{
						MessageID: "emailSubtitleOne",
					}),
					"subtitleTextTwo": loc.MustLocalize(&i18n.LocalizeConfig{
						MessageID: "emailSubtitleTwo",
					}),
					"footnote": loc.MustLocalize(&i18n.LocalizeConfig{
						MessageID: "emailFootnote",
					}),
					"file": file.Name,
				}); err != nil {
					c.logger.Errorf("could not execute an email template: %w", err)
				}
				return
			} else if ctx.Err() != nil {
				c.logger.Errorf("timeout while fetching Dropbox data: %s", fetchErr.Error())
				c.errorResponse(rw, embeddable.ErrorPage,
					"Sorry, the request timed out",
					"Please try again",
					"Reload")
			} else {
				c.logger.Errorf("error fetching Dropbox data: %s", fetchErr.Error())
				c.errorResponse(rw, embeddable.ErrorPage,
					"Sorry, the document cannot be opened",
					"Please try again",
					"Reload")
			}
			return
		}

		file.LowerExt()
		editorType := determineEditorType(r.UserAgent())
		loc := i18n.NewLocalizer(embeddable.Bundle, user.Locale)
		config, configErr := c.prepareDocumentConfig(file, user, downloadLink, token, editorType)
		if configErr != nil {
			c.logger.Errorf("could not prepare document config: %s", configErr.Error())
			c.errorResponse(rw, embeddable.ErrorPage,
				loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "errorMain"}),
				loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "errorSubtext"}),
				loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "reloadButton"}))
			return
		}

		config.ExpiresAt = jwt.NewNumericDate(time.Now().Add(5 * time.Minute))
		sig, err := c.jwtManager.Sign(c.onlyoffice.Onlyoffice.Builder.DocumentServerSecret, config)
		if err != nil {
			c.logger.Debugf("could not sign document server config: %s", err.Error())
			c.errorResponse(rw, embeddable.ErrorPage,
				loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "errorMain"}),
				loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "errorSubtext"}),
				loc.MustLocalize(&i18n.LocalizeConfig{MessageID: "reloadButton"}))
			return
		}

		config.Token = sig
		if err := embeddable.EditorPage.Execute(rw, map[string]interface{}{
			"file":    file.ID,
			"apijs":   fmt.Sprintf("%s/web-apps/apps/api/documents/api.js", config.ServerURL),
			"config":  string(config.ToJSON()),
			"docType": config.DocumentType,
			"cancelButton": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "cancelButton",
			}),
		}); err != nil {
			c.logger.Errorf("could not execute an editor template: %w", err)
		}
	}
}
