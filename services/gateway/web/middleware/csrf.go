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
	"net/http"
	"slices"

	"github.com/gorilla/csrf"
)

// SkipCSRF exempts exact paths from CSRF protection. Only use it for routes
// that never rely on cookies for authentication
func SkipCSRF(protect func(http.Handler) http.Handler, paths ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		protected := protect(next)
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if slices.Contains(paths, r.URL.Path) {
				r = csrf.UnsafeSkipCheck(r)
			}

			protected.ServeHTTP(rw, r)
		})
	}
}
