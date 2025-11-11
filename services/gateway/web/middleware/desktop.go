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

package middleware

import (
	"net/http"
	"strings"

	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
)

type DesktopMiddleware struct {
	logger log.Logger
}

func NewDesktopMiddleware(logger log.Logger) DesktopMiddleware {
	return DesktopMiddleware{
		logger: logger,
	}
}

func (m DesktopMiddleware) RequireDesktop(next http.Handler) http.Handler {
	fn := func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("desktop") == "true" {
			m.logger.Debug("desktop access granted via query parameter")
			next.ServeHTTP(rw, r)
			return
		}

		userAgent := r.Header.Get("User-Agent")
		if strings.Contains(userAgent, "AscDesktopEditor") {
			m.logger.Debugf("desktop access granted via User-Agent: %s", userAgent)
			next.ServeHTTP(rw, r)
			return
		}

		m.logger.Warnf("desktop access denied - not a desktop application request from %s", r.RemoteAddr)
		http.Error(rw, "Forbidden: This endpoint is only accessible from ONLYOFFICE Desktop Editors", http.StatusForbidden)
	}

	return http.HandlerFunc(fn)
}
