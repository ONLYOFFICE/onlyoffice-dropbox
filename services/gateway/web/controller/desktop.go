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
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/embeddable"
	aclient "github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/client"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"go-micro.dev/v4/client"
)

const desktopPluginOrigin = "onlyoffice://plugin"

type DesktopController struct {
	client client.Client
	api    aclient.DropboxClient
	server *config.ServerConfig
	logger log.Logger
}

func NewDesktopController(
	client client.Client,
	api aclient.DropboxClient,
	server *config.ServerConfig,
	logger log.Logger,
) DesktopController {
	return DesktopController{
		client: client,
		api:    api,
		server: server,
		logger: logger,
	}
}

func (c *DesktopController) BuildEntryPage() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		rw.Header().Set("Content-Type", "text/html")
		uid := rw.Header().Get("X-User")
		if uid == "" {
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		var ures response.UserResponse
		if err := c.client.Call(ctx, c.client.NewRequest(
			fmt.Sprintf("%s:auth", c.server.Namespace), "UserSelectHandler.GetUser",
			uid,
		), &ures); err != nil {
			c.logger.Errorf("could not get user %s access info: %s", uid, err.Error())
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		usr, err := c.api.GetUser(ctx, ures.AccessToken)
		if err != nil {
			c.logger.Errorf("could not get dropbox user profile: %s", err.Error())
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		locale := usr.Locale
		if locale == "" {
			locale = "en"
		}

		loc := i18n.NewLocalizer(embeddable.Bundle, locale)
		loading := loc.MustLocalize(&i18n.LocalizeConfig{
			MessageID: "loading",
		})

		if err := embeddable.DesktopPage.Execute(rw, map[string]any{
			"displayName": usr.Name.DisplayName,
			"email":       usr.Email,
			"domain":      r.Host,
			"provider":    "dropbox",
			"userId":      usr.AccountID,
			"loading":     loading,
		}); err != nil {
			c.logger.Errorf("could not execute desktop template: %s", err.Error())
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
		}
	}
}

// BuildGetToken hands ONLYOFFICE Desktop's AI agent the current Dropbox access
// token of the signed-in user, so the agent can call Dropbox's MCP server
// itself. The auth service refreshes the token before it expires.
//
// The plugin reads it with the session cookie, and a wildcard
// Access-Control-Allow-Origin never exposes a response to a request with
// credentials, so the plugin origin is allowed by name and every other origin
// is denied.
func (c *DesktopController) BuildGetToken() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		if r.Header.Get("Origin") == desktopPluginOrigin {
			rw.Header().Set("Access-Control-Allow-Origin", desktopPluginOrigin)
			rw.Header().Set("Access-Control-Allow-Credentials", "true")
		} else {
			rw.Header().Del("Access-Control-Allow-Origin")
			rw.Header().Del("Access-Control-Allow-Credentials")
		}

		rw.Header().Set("Content-Type", "application/json")
		uid := rw.Header().Get("X-User")
		if uid == "" {
			http.Error(rw, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		var ures response.UserResponse
		if err := c.client.Call(ctx, c.client.NewRequest(
			fmt.Sprintf("%s:auth", c.server.Namespace), "UserSelectHandler.GetUser",
			uid,
		), &ures); err != nil {
			c.logger.Errorf("could not get user %s access info: %s", uid, err.Error())
			http.Error(rw, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		if err := json.NewEncoder(rw).Encode(map[string]string{
			"access_token": ures.AccessToken,
			"expires_at":   ures.Expiry,
		}); err != nil {
			c.logger.Errorf("could not encode the access token of user %s: %s", uid, err.Error())
		}
	}
}
