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
	"net/http"
	"strings"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/embeddable"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/mcp"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/gorilla/csrf"
)

const MCPServerName = "onlyoffice-dropbox"

type MCPController struct {
	keys       mcp.KeyManager
	users      mcp.UserStore
	onlyoffice *shared.OnlyofficeConfig
	logger     log.Logger
}

func NewMCPController(
	keys mcp.KeyManager,
	users mcp.UserStore,
	onlyoffice *shared.OnlyofficeConfig,
	logger log.Logger,
) MCPController {
	return MCPController{
		keys:       keys,
		users:      users,
		onlyoffice: onlyoffice,
		logger:     logger,
	}
}

func (c MCPController) desktopConfig(endpoint, authorization string) ([]byte, error) {
	return json.MarshalIndent(map[string]any{
		"mcpServers": map[string]any{
			MCPServerName: map[string]any{
				"url":     endpoint,
				"headers": map[string]string{"Authorization": authorization},
			},
		},
	}, "", "  ")
}

func maskKey(key string) string {
	if len(key) <= 16 {
		return strings.Repeat("*", len(key))
	}

	return key[:10] + strings.Repeat("*", 12) + key[len(key)-6:]
}

func wantsJSON(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html")
}

func (c MCPController) BuildGetKey() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		uid := rw.Header().Get("X-User")
		if uid == "" {
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		uctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		user, err := c.users.GetUser(uctx, uid)
		cancel()

		if err != nil {
			c.logger.Errorf("could not get mcp key version of user %s: %s", uid, err.Error())
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		key, expiresAt, err := c.keys.Issue(uid, user.KeyVersion, time.Now())
		if err != nil {
			c.logger.Errorf("could not issue an mcp key for user %s: %s", uid, err.Error())
			http.Error(rw, "could not generate an MCP key", http.StatusInternalServerError)
			return
		}

		endpoint := strings.TrimSuffix(c.onlyoffice.Onlyoffice.Builder.GatewayURL, "/") + "/mcp"
		config, err := c.desktopConfig(endpoint, "Bearer "+key)
		if err != nil {
			http.Error(rw, "could not encode the MCP configuration", http.StatusInternalServerError)
			return
		}

		c.logger.Debugf("issued an mcp key for user %s (version %d), expires %s",
			uid, user.KeyVersion, expiresAt.UTC().Format(time.RFC3339))

		rw.Header().Set("Cache-Control", "no-store")
		rw.Header().Set("Referrer-Policy", "same-origin")
		rw.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		rw.Header().Set("X-Frame-Options", "DENY")
		rw.Header().Set("X-MCP-Key-Expires", expiresAt.UTC().Format(time.RFC3339))
		if wantsJSON(r) {
			rw.Header().Set("Content-Type", "application/json")
			_, _ = rw.Write(config)
			return
		}

		masked, err := c.desktopConfig(endpoint, "Bearer "+maskKey(key))
		if err != nil {
			http.Error(rw, "could not encode the MCP configuration", http.StatusInternalServerError)
			return
		}

		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := embeddable.MCPKeyPage.Execute(rw, map[string]any{
			"endpoint":     endpoint,
			"serverName":   MCPServerName,
			"config":       string(config),
			"maskedConfig": string(masked),
			"expiresAt":    expiresAt.UTC().Format("January 2, 2006"),
			"csrfField":    csrf.TemplateField(r),
			"wasRevoked":   r.URL.Query().Get("revoked") == "1",
		}); err != nil {
			c.logger.Errorf("could not execute mcp key template: %s", err.Error())
		}
	}
}

func (c MCPController) BuildRevokeKey() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		uid := rw.Header().Get("X-User")
		if uid == "" {
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		uctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		version, err := c.users.RotateKey(uctx, uid)
		cancel()

		if err != nil {
			c.logger.Errorf("could not revoke the mcp key of user %s: %s", uid, err.Error())
			http.Error(rw, "could not revoke the MCP key", http.StatusInternalServerError)
			return
		}

		c.logger.Debugf("revoked the mcp keys of user %s, key version is now %d", uid, version)
		http.Redirect(rw, r, "/mcp/key?revoked=1", http.StatusSeeOther)
	}
}
