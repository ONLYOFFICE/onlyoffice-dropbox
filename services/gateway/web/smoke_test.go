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

package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/controller"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/controller/convert"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/middleware"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared"
	aclient "github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/client"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const (
	smokeSecret    = "smoke-client-secret-0123456789ab"
	smokeClientID  = "smoke-client"
	smokeRedirect  = "https://gateway.example/oauth/redirect"
	desktopUA      = "Mozilla/5.0 AscDesktopEditor/9.0"
	desktopOrigin  = "onlyoffice://plugin"
	installPath    = "/oauth/install"
	smokeAccountID = "dbid:smoke"
)

func smokeOAuth() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     smokeClientID,
		ClientSecret: smokeSecret,
		RedirectURL:  smokeRedirect,
		Scopes:       []string{"files.content.read", "files.content.write"},
	}
}

func newSmokeRouter(t *testing.T) http.Handler {
	t.Helper()

	oauth := smokeOAuth()
	logger := log.NewEmptyLogger()
	jwtManager := crypto.NewJwtManager(&config.CryptoConfig{})

	var onlyoffice shared.OnlyofficeConfig
	onlyoffice.Onlyoffice.Builder.GatewayURL = "https://gateway.example"

	auth := controller.NewAuthController(
		nil, aclient.DropboxClient{}, jwtManager, crypto.NewStateGenerator(),
		&config.ServerConfig{Namespace: "dropbox"}, oauth, logger,
	)
	desktop := controller.NewDesktopController(nil, aclient.DropboxClient{}, &config.ServerConfig{Namespace: "dropbox"}, logger)

	return NewServer(
		auth,
		controller.EditorController{},
		convert.ConvertController{},
		controller.HistoryController{},
		desktop,
		middleware.NewSessionMiddleware(jwtManager, oauth, &onlyoffice, logger),
		middleware.NewDesktopMiddleware(logger),
		oauth,
	).NewHandler()
}

func sessionCookies(t *testing.T) []*http.Cookie {
	t.Helper()

	token, err := crypto.NewJwtManager(&config.CryptoConfig{}).Sign(smokeSecret, jwt.RegisteredClaims{
		ID:        smokeAccountID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	require.NoError(t, err)

	store := sessions.NewCookieStore([]byte(smokeSecret))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	session, err := store.New(req, "authorization")
	require.NoError(t, err)
	session.Values["token"] = token

	rw := httptest.NewRecorder()
	require.NoError(t, store.Save(req, rw, session))

	return rw.Result().Cookies()
}

func serve(router http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rw := httptest.NewRecorder()
	router.ServeHTTP(rw, req)
	return rw
}

func TestSmokeInstall(t *testing.T) {
	router := newSmokeRouter(t)

	t.Run("install redirects to Dropbox OAuth with PKCE, offline access and the configured scopes", func(t *testing.T) {
		rw := serve(router, httptest.NewRequest(http.MethodGet, installPath, nil))

		require.Equal(t, http.StatusMovedPermanently, rw.Code)
		loc, err := url.Parse(rw.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "dropbox.com", loc.Host)
		assert.Equal(t, "/oauth2/authorize", loc.Path)

		q := loc.Query()
		assert.Equal(t, smokeClientID, q.Get("client_id"))
		assert.Equal(t, smokeRedirect, q.Get("redirect_uri"))
		assert.Equal(t, "code", q.Get("response_type"))
		assert.Equal(t, "offline", q.Get("token_access_type"))
		assert.Equal(t, "S256", q.Get("code_challenge_method"))
		assert.NotEmpty(t, q.Get("code_challenge"))
		assert.NotEmpty(t, q.Get("state"))
		assert.Equal(t, "files.content.read files.content.write", q.Get("scope"))

		var hasInstallSession bool
		for _, c := range rw.Result().Cookies() {
			hasInstallSession = hasInstallSession || c.Name == "auth-installation"
		}
		assert.True(t, hasInstallSession, "the PKCE verifier and state must be kept in a session cookie")
	})

	t.Run("redirect without code or state starts the install again", func(t *testing.T) {
		rw := serve(router, httptest.NewRequest(http.MethodGet, "/oauth/redirect", nil))

		assert.Equal(t, http.StatusMovedPermanently, rw.Code)
		assert.Equal(t, installPath, rw.Header().Get("Location"))
	})
}

func TestSmokeProtectedRoutesRequireSession(t *testing.T) {
	router := newSmokeRouter(t)

	for _, target := range []string{
		"/editor?file_id=id:abc",
		"/convert?file_id=id:abc",
		"/api/history?file_id=id:abc",
		"/api/history/links?file_id=id:abc",
	} {
		t.Run(target, func(t *testing.T) {
			rw := serve(router, httptest.NewRequest(http.MethodGet, target, nil))

			assert.Equal(t, http.StatusSeeOther, rw.Code)
			assert.Equal(t, installPath, rw.Header().Get("Location"))
		})
	}
}

func TestSmokeConvertAPIRequiresCSRFToken(t *testing.T) {
	router := newSmokeRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/api/convert", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range sessionCookies(t) {
		req.AddCookie(c)
	}

	rw := serve(router, req)
	assert.Equal(t, http.StatusForbidden, rw.Code)
}

func TestSmokeDesktop(t *testing.T) {
	router := newSmokeRouter(t)

	t.Run("is closed to browsers", func(t *testing.T) {
		rw := serve(router, httptest.NewRequest(http.MethodGet, "/app/ai", nil))
		assert.Equal(t, http.StatusForbidden, rw.Code)
	})

	t.Run("asks Desktop to sign in when there is no session", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/app/ai", nil)
		req.Header.Set("User-Agent", desktopUA)

		rw := serve(router, req)
		assert.Equal(t, http.StatusSeeOther, rw.Code)
		assert.Equal(t, installPath, rw.Header().Get("Location"))
	})

	t.Run("tells a signed-in Desktop AI plugin that Dropbox is supported", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/app/ai", nil)
		req.Header.Set("User-Agent", desktopUA)
		req.Header.Set("Origin", desktopOrigin)
		for _, c := range sessionCookies(t) {
			req.AddCookie(c)
		}

		rw := serve(router, req)
		require.Equal(t, http.StatusOK, rw.Code)
		assert.Equal(t, desktopOrigin, rw.Header().Get("Access-Control-Allow-Origin"))

		var body map[string]any
		require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &body))
		assert.Equal(t, "dropbox", body["provider"])
	})
}

func TestSmokeStaticAndNotFound(t *testing.T) {
	router := newSmokeRouter(t)

	for _, icon := range []string{"favicon", "word", "cell", "slide", "diagram"} {
		rw := serve(router, httptest.NewRequest(http.MethodGet, "/images/"+icon+".ico", nil))
		assert.Equal(t, http.StatusOK, rw.Code, icon)
	}

	rw := serve(router, httptest.NewRequest(http.MethodGet, "/no-such-page", nil))
	assert.Equal(t, http.StatusNotFound, rw.Code)
	assert.Contains(t, rw.Header().Get("Content-Type"), "text/html")
}
