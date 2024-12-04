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
	"sync"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/embeddable"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/response"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/csrf"
	"github.com/nicksnyder/go-i18n/v2/i18n"
)

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
			// TODO: Generic error page
			if err := embeddable.ErrorPage.ExecuteTemplate(rw, "error", map[string]interface{}{
				"errorMain":    "Sorry, the document cannot be opened",
				"errorSubtext": "Please try again",
				"reloadButton": "Reload",
			}); err != nil {
				c.logger.Errorf("could not execute an error template: %w", err)
			}
			return
		}

		var wg sync.WaitGroup
		wg.Add(2)
		errChan := make(chan error, 2)
		userChan := make(chan response.DropboxUserResponse, 1)
		fileChan := make(chan response.DropboxFileResponse, 1)

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

		c.logger.Debug("waiting for goroutines to finish")
		wg.Wait()
		c.logger.Debug("goroutines have finished")

		select {
		case err := <-errChan:
			c.logger.Errorf("could not get user/file: %s", err.Error())
			// TODO: Generic error page
			if err := embeddable.ErrorPage.ExecuteTemplate(rw, "error", map[string]interface{}{
				"errorMain":    "Sorry, the document cannot be opened",
				"errorSubtext": "Please try again",
				"reloadButton": "Reload",
			}); err != nil {
				c.logger.Errorf("could not execute an error template: %w", err)
			}
			return
		case <-r.Context().Done():
			c.logger.Warn("current request took longer than expected")
			// TODO: Generic error page
			if err := embeddable.ErrorPage.ExecuteTemplate(rw, "error", map[string]interface{}{
				"errorMain":    "Sorry, the document cannot be opened",
				"errorSubtext": "Please try again",
				"reloadButton": "Reload",
			}); err != nil {
				c.logger.Errorf("could not execute an error template: %w", err)
			}
			return
		default:
		}

		usr := <-userChan
		file := <-fileChan
		loc := i18n.NewLocalizer(embeddable.Bundle, usr.Locale)
		ext := c.fileUtil.GetFileExt(file.Name)
		if c.fileUtil.IsExtensionEditable(ext) || c.fileUtil.IsExtensionViewOnly(ext) {
			creq := request.ConvertActionRequest{
				Action: "edit",
				FileID: fileID,
			}
			creq.IssuedAt = jwt.NewNumericDate(time.Now())
			creq.ExpiresAt = jwt.NewNumericDate(time.Now().Add(5 * time.Minute))
			token, _ := c.jwtManager.Sign(c.credentials.ClientSecret, creq)
			http.Redirect(rw, r, fmt.Sprintf("/editor?token=%s", token), http.StatusMovedPermanently)
			return
		}

		if err := embeddable.ConvertPage.Execute(rw, map[string]interface{}{
			"CSRF":     csrf.Token(r),
			"OOXML":    ext != "csv" && (c.fileUtil.IsExtensionOOXMLConvertable(ext) || c.fileUtil.IsExtensionLossEditable(ext)),
			"LossEdit": c.fileUtil.IsExtensionLossEditable(ext),
			"openOnlyoffice": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "openOnlyoffice",
			}),
			"cannotOpen": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "cannotOpen",
			}),
			"selectAction": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "selectAction",
			}),
			"openView": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "openView",
			}),
			"createOOXML": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "createOOXML",
			}),
			"editCopy": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "editCopy",
			}),
			"openEditing": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "openEditing",
			}),
			"moreInfo": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "moreInfo",
			}),
			"dataRestrictions": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "dataRestrictions",
			}),
			"openButton": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "openButton",
			}),
			"cancelButton": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "cancelButton",
			}),
			"errorMain": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "errorMain",
			}),
			"errorSubtext": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "errorSubtext",
			}),
			"reloadButton": loc.MustLocalize(&i18n.LocalizeConfig{
				MessageID: "reloadButton",
			}),
		}); err != nil {
			c.logger.Errorf("could not execute a convert template: %w", err)
		}
	}
}
