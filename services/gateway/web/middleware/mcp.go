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

package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/mcp"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
)

// MCPMiddleware authenticates MCP requests with a bearer MCP key. MCP clients
// cannot hold a cookie session (ONLYOFFICE Desktop's MCP client sends none),
// and unlike SessionMiddleware it answers 401 instead of redirecting to the
// OAuth flow, which an MCP client cannot follow.
//
// A key is only accepted while its version matches the user's stored key
// version, so revoking the key on /mcp/key invalidates every earlier key.
type MCPMiddleware struct {
	keys    mcp.KeyManager
	users   mcp.UserStore
	keyPage string
	logger  log.Logger
}

func NewMCPMiddleware(
	keys mcp.KeyManager,
	users mcp.UserStore,
	onlyoffice *shared.OnlyofficeConfig,
	logger log.Logger,
) MCPMiddleware {
	return MCPMiddleware{
		keys:    keys,
		users:   users,
		keyPage: strings.TrimSuffix(onlyoffice.Onlyoffice.Builder.GatewayURL, "/") + "/mcp/key",
		logger:  logger,
	}
}

func describeRequest(r *http.Request) string {
	cookies := r.Cookies()
	names := make([]string, 0, len(cookies))
	for _, c := range cookies {
		names = append(names, c.Name)
	}

	return fmt.Sprintf(
		"method=%s remote=%s forwarded_for=%q host=%q origin=%q user_agent=%q content_type=%q cookies=%v has_authorization=%t",
		r.Method, r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Host, r.Header.Get("Origin"),
		r.UserAgent(), r.Header.Get("Content-Type"), names, r.Header.Get("Authorization") != "",
	)
}

func (m MCPMiddleware) missingKeyMessage() string {
	return "ONLYOFFICE for Dropbox needs an MCP key. Open " + m.keyPage + " in a browser and copy the configuration: " +
		"this server needs its \"headers\": {\"Authorization\": \"Bearer <key>\"} in AI agent > MCP Servers > Edit configuration."
}

func (m MCPMiddleware) invalidKeyMessage() string {
	return "The ONLYOFFICE for Dropbox MCP key is invalid, expired or revoked. Open " + m.keyPage +
		" in a browser and copy the current configuration: replace this server's \"Authorization\" header with it " +
		"in AI agent > MCP Servers > Edit configuration."
}

func (m MCPMiddleware) reject(rw http.ResponseWriter, r *http.Request, reason, authError, message string) {
	m.logger.Debugf("mcp request rejected with 401: %s; %s", reason, describeRequest(r))

	challenge := `Bearer realm="onlyoffice-dropbox-mcp"`
	if authError != "" {
		challenge += `, error="` + authError + `"`
	}

	challenge += `, error_description="` + strings.ReplaceAll(message, `"`, `'`) + `"`

	rw.Header().Set("WWW-Authenticate", challenge)
	http.Error(rw, message, http.StatusUnauthorized)
}

func (m MCPMiddleware) Authenticate(next http.Handler) http.Handler {
	fn := func(rw http.ResponseWriter, r *http.Request) {
		scheme, key, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		key = strings.TrimSpace(key)
		if !ok || !strings.EqualFold(scheme, "Bearer") || key == "" {
			m.reject(rw, r, "no bearer mcp key", "", m.missingKeyMessage())
			return
		}

		uid, version, err := m.keys.Verify(key)
		if err != nil {
			m.reject(rw, r, "mcp key is invalid or expired", "invalid_token", m.invalidKeyMessage())
			return
		}

		uctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		user, err := m.users.GetUser(uctx, uid)

		cancel()

		if errors.Is(err, mcp.ErrUserNotFound) {
			m.reject(rw, r, fmt.Sprintf("user %s is not authorized in the integration: %s", uid, err.Error()),
				"invalid_token", m.invalidKeyMessage())
			return
		}

		if err != nil {
			m.logger.Warnf("mcp auth check unavailable for user %s, serving without dropbox access: %s", uid, err.Error())
			ctx := context.WithValue(r.Context(), mcp.UserIDKey, uid)
			next.ServeHTTP(rw, r.WithContext(mcp.WithAuthUnavailable(ctx)))
			return
		}

		if version != user.KeyVersion {
			m.reject(rw, r, fmt.Sprintf("mcp key of user %s was revoked (key version %d, current %d)", uid, version, user.KeyVersion),
				"invalid_token", m.invalidKeyMessage())
			return
		}

		m.logger.Debugf("mcp request authenticated for user %s; %s", uid, describeRequest(r))

		ctx := context.WithValue(r.Context(), mcp.UserIDKey, uid)
		next.ServeHTTP(rw, r.WithContext(mcp.WithAccessToken(ctx, user.AccessToken)))
	}

	return http.HandlerFunc(fn)
}
