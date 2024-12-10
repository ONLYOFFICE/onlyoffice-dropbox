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
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/embeddable"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/response"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/csrf"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/sync/errgroup"
)

func (c *ConvertController) renderErrorPage(rw http.ResponseWriter) {
	if err := embeddable.ErrorPage.ExecuteTemplate(rw, "error", map[string]interface{}{
		"errorMain":    "Sorry, the document cannot be opened",
		"errorSubtext": "Please try again",
		"reloadButton": "Reload",
	}); err != nil {
		c.logger.Errorf("could not execute an error template: %w", err)
	}
}

func (c *ConvertController) getLocalizedMessages(loc *i18n.Localizer, messageIDs []string) map[string]string {
	messages := make(map[string]string)
	for _, id := range messageIDs {
		messages[id] = loc.MustLocalize(&i18n.LocalizeConfig{
			MessageID: id,
		})
	}
	return messages
}

func (c ConvertController) BuildConvertPage() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/html")
		fileID := r.URL.Query().Get("file_id")
		uid := rw.Header().Get("X-User")
		if uid == "" {
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		tctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		var ures response.UserResponse
		if err := c.client.Call(tctx, c.client.NewRequest(
			fmt.Sprintf("%s:auth", c.server.Namespace), "UserSelectHandler.GetUser",
			uid,
		), &ures); err != nil {
			c.renderErrorPage(rw)
			return
		}

		g, ctx := errgroup.WithContext(r.Context())
		var usr response.DropboxUserResponse
		var file response.DropboxFileResponse

		g.Go(func() error {
			var err error
			usr, err = c.api.GetUser(ctx, ures.AccessToken)
			return err
		})

		g.Go(func() error {
			var err error
			file, err = c.api.GetFile(ctx, fileID, ures.AccessToken)
			return err
		})

		c.logger.Debug("waiting for goroutines to finish")
		if err := g.Wait(); err != nil {
			c.logger.Errorf("could not get user/file: %s", err.Error())
			c.renderErrorPage(rw)
			return
		}

		c.logger.Debug("goroutines have finished")

		loc := i18n.NewLocalizer(embeddable.Bundle, usr.Locale)
		format, supported := c.formatManager.GetFormatByName(c.formatManager.GetFileExt(file.Name))
		if !supported {
			c.logger.Warnf("file format is not supported: %s", format.Type)
			c.renderErrorPage(rw)
			return
		}

		if format.IsEditable() || format.IsViewOnly() {
			creq := request.ConvertActionRequest{
				Action: "edit",
				FileID: fileID,
			}
			creq.IssuedAt = jwt.NewNumericDate(time.Now())
			creq.ExpiresAt = jwt.NewNumericDate(time.Now().Add(5 * time.Minute))
			token, _ := c.jwtManager.Sign(c.credentials.ClientSecret, creq)
			http.Redirect(rw, r, fmt.Sprintf("/editor?token=%s&file_id=%s", token, fileID), http.StatusMovedPermanently)
			return
		}

		messageIDs := []string{
			"openOnlyoffice",
			"cannotOpen",
			"selectAction",
			"openView",
			"createOOXML",
			"editCopy",
			"openEditing",
			"moreInfo",
			"dataRestrictions",
			"openButton",
			"cancelButton",
			"errorMain",
			"errorSubtext",
			"reloadButton",
			"documentType",
			"spreadsheetType",
			"passwordRequired",
		}

		messages := c.getLocalizedMessages(loc, messageIDs)
		data := map[string]interface{}{
			"CSRF":     csrf.Token(r),
			"OOXML":    format.Name != "csv" && (format.IsOpenXMLConvertable() || format.IsLossyEditable()),
			"IsXML":    format.Name == "xml",
			"LossEdit": format.IsLossyEditable(),
		}

		for k, v := range messages {
			data[k] = v
		}

		if err := embeddable.ConvertPage.Execute(rw, data); err != nil {
			c.logger.Errorf("could not execute a convert template: %w", err)
		}
	}
}
