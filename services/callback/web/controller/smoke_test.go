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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared"
	aclient "github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/client"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const dsSecret = "smoke-document-server-secret"

func newSmokeCallback() (CallbackController, crypto.JwtManager) {
	jwtManager := crypto.NewJwtManager(&config.CryptoConfig{})
	var onlyoffice shared.OnlyofficeConfig
	onlyoffice.Onlyoffice.Builder.DocumentServerSecret = dsSecret
	onlyoffice.Onlyoffice.Callback.MaxSize = 1024
	onlyoffice.Onlyoffice.Callback.UploadTimeout = 5

	return NewCallbackController(
		nil, aclient.DropboxClient{}, jwtManager,
		&config.ServerConfig{Namespace: "dropbox"}, &oauth2.Config{},
		&onlyoffice, log.NewEmptyLogger(),
	), jwtManager
}

func postCallback(t *testing.T, c CallbackController, state string, body map[string]any) (*httptest.ResponseRecorder, int) {
	t.Helper()

	buf, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/callback?state="+state, strings.NewReader(string(buf)))
	rw := httptest.NewRecorder()
	c.BuildPostHandleCallback()(rw, req)

	var resp struct {
		Error int `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &resp))

	return rw, resp.Error
}

func TestSmokeCallback(t *testing.T) {
	c, jwtManager := newSmokeCallback()

	state, err := jwtManager.Sign(dsSecret, request.CallbackState{FileID: "id:abc"})
	require.NoError(t, err)

	signedBody := func(secret string, status int) map[string]any {
		token, err := jwtManager.Sign(secret, jwt.MapClaims{
			"key":    "doc-key",
			"status": status,
			"users":  []string{"dbid:smoke"},
		})
		require.NoError(t, err)
		return map[string]any{"token": token}
	}

	t.Run("rejects a forged state", func(t *testing.T) {
		forged, err := jwtManager.Sign("not-the-secret", request.CallbackState{FileID: "id:abc"})
		require.NoError(t, err)

		rw, code := postCallback(t, c, forged, signedBody(dsSecret, 1))
		assert.Equal(t, http.StatusForbidden, rw.Code)
		assert.Equal(t, 1, code)
	})

	t.Run("rejects a body not signed by the Document Server", func(t *testing.T) {
		rw, code := postCallback(t, c, state, signedBody("not-the-secret", 1))
		assert.Equal(t, http.StatusBadRequest, rw.Code)
		assert.Equal(t, 1, code)
	})

	t.Run("rejects an unsigned body", func(t *testing.T) {
		rw, code := postCallback(t, c, state, map[string]any{"key": "doc-key", "status": 1})
		assert.Equal(t, http.StatusBadRequest, rw.Code)
		assert.Equal(t, 1, code)
	})

	for _, status := range []int{1, 4} {
		t.Run("acknowledges status "+map[int]string{1: "1 (editing)", 4: "4 (closed without changes)"}[status], func(t *testing.T) {
			rw, code := postCallback(t, c, state, signedBody(dsSecret, status))
			assert.Equal(t, http.StatusOK, rw.Code)
			assert.Equal(t, 0, code)
		})
	}
}
