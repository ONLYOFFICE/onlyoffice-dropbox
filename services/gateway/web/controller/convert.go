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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/embeddable"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared"
	aclient "github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/client"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/onlyoffice"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"go-micro.dev/v4/client"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
)

var _ErrCsvIsNotSupported = errors.New("csv conversion is not supported")

type ConvertController struct {
	client      client.Client
	api         aclient.DropboxClient
	jwtManager  crypto.JwtManager
	fileUtil    onlyoffice.OnlyofficeFileUtility
	store       *sessions.CookieStore
	server      *config.ServerConfig
	credentials *oauth2.Config
	onlyoffice  *shared.OnlyofficeConfig
	logger      log.Logger
}

func NewConvertController(
	client client.Client, api aclient.DropboxClient, jwtManager crypto.JwtManager,
	fileUtil onlyoffice.OnlyofficeFileUtility, onlyoffice *shared.OnlyofficeConfig,
	server *config.ServerConfig, credentials *oauth2.Config, logger log.Logger,
) ConvertController {
	return ConvertController{
		client:      client,
		api:         api,
		jwtManager:  jwtManager,
		fileUtil:    fileUtil,
		store:       sessions.NewCookieStore([]byte(credentials.ClientSecret)),
		server:      server,
		credentials: credentials,
		onlyoffice:  onlyoffice,
		logger:      logger,
	}
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
			// TODO: Generic error page
			embeddable.ErrorPage.ExecuteTemplate(rw, "error", map[string]interface{}{
				"errorMain":    "Sorry, the document cannot be opened",
				"errorSubtext": "Please try again",
				"reloadButton": "Reload",
			})
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
			embeddable.ErrorPage.ExecuteTemplate(rw, "error", map[string]interface{}{
				"errorMain":    "Sorry, the document cannot be opened",
				"errorSubtext": "Please try again",
				"reloadButton": "Reload",
			})
			return
		case <-r.Context().Done():
			c.logger.Warn("current request took longer than expected")
			// TODO: Generic error page
			embeddable.ErrorPage.ExecuteTemplate(rw, "error", map[string]interface{}{
				"errorMain":    "Sorry, the document cannot be opened",
				"errorSubtext": "Please try again",
				"reloadButton": "Reload",
			})
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

		embeddable.ConvertPage.Execute(rw, map[string]interface{}{
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
		})
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

	var wg sync.WaitGroup
	wg.Add(2)
	errChan := make(chan error, 2)
	fileChan := make(chan response.DropboxFileResponse, 1)
	downloadChan := make(chan response.DropboxDownloadResponse, 1)

	go func() {
		defer wg.Done()
		file, err := c.api.GetFile(uctx, fileID, ures.AccessToken)
		if err != nil {
			c.logger.Errorf("could not initialize a new drive service: %s", err.Error())
			errChan <- err
			return
		}

		fileChan <- file
	}()

	go func() {
		defer wg.Done()
		dres, err := c.api.GetDownloadLink(uctx, fileID, ures.AccessToken)
		if err != nil {
			c.logger.Errorf("could not get download link: %s", err.Error())
			errChan <- err
			return
		}

		downloadChan <- dres
	}()

	wg.Wait()

	select {
	case err := <-errChan:
		return nil, err
	default:
	}

	file := <-fileChan
	dres := <-downloadChan
	ext := c.fileUtil.GetFileExt(file.Name)
	fType, err := c.fileUtil.GetFileType(ext)
	if err != nil {
		c.logger.Debugf("could not get file type: %s", err.Error())
		return nil, err
	}

	if ext == "csv" {
		return nil, _ErrCsvIsNotSupported
	}

	creq := request.ConvertRequest{
		Async:      false,
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
	req, err := http.NewRequestWithContext(
		uctx,
		"POST",
		fmt.Sprintf("%s/ConvertService.ashx", c.onlyoffice.Onlyoffice.Builder.DocumentServerURL),
		bytes.NewBuffer(creq.ToJSON()),
	)

	if err != nil {
		c.logger.Errorf("could not build a conversion api request: %s", err.Error())
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	resp, err := otelhttp.DefaultClient.Do(req)
	if err != nil {
		c.logger.Errorf("could not send a conversion api request: %s", err.Error())
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
		c.logger.Errorf("could not retreive a converted file: %s", err.Error())
		return nil, err
	}

	defer cfile.Body.Close()
	filename := fmt.Sprintf("%s.%s", file.Name[:len(file.Name)-len(filepath.Ext(file.Name))], cresp.FileType)
	newPath := fmt.Sprintf("%s/%s", file.PathLower[:strings.LastIndex(file.PathLower, "/")], filename)
	uplres, err := c.api.CreateFile(ctx, newPath, ures.AccessToken, cfile.Body)
	if err != nil {
		c.logger.Errorf("could not modify file %s: %s", fileID, err.Error())
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

		switch creq.Action {
		case "create":
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
		default:
			http.Redirect(
				rw, r,
				fmt.Sprintf(
					"/editor?token=%s",
					token,
				),
				http.StatusMovedPermanently,
			)
			return
		}
	}
}
