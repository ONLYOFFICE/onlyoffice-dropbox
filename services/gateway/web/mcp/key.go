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

package mcp

import (
	"errors"
	"fmt"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

const (
	KeyAudience = "onlyoffice-dropbox-mcp"
	// KeyWindow is how long the same key is handed out: every request in a
	// window gets an identical key instead of a new one per page load.
	KeyWindow = 30 * 24 * time.Hour
	// KeyTTL counts from the start of the window, so a key stays valid for
	// 60 to 90 days and a new one is always issued before the old expires.
	KeyTTL = 90 * 24 * time.Hour
)

var ErrInvalidKey = errors.New("invalid mcp key")

type keyClaims struct {
	Version int `json:"ver"`
	jwt.RegisteredClaims
}

// KeyManager issues and verifies MCP access keys. MCP clients such as
// ONLYOFFICE Desktop can only send fixed headers (no cookies, no OAuth), so a
// key is a JWT bound to the Dropbox account id and the account's key version;
// bumping the version (UserStore.RotateKey) revokes every earlier key.
//
// Keys are deterministic: all claims derive from the user, the version and
// the current window, and HS256 signatures are deterministic, so repeated
// requests return the same key. They are signed with a secret derived from
// the client secret, so session and editor tokens cannot be used as keys.
type KeyManager struct {
	jwtManager crypto.JwtManager
	secret     string
}

func NewKeyManager(jwtManager crypto.JwtManager, credentials *oauth2.Config) KeyManager {
	return KeyManager{
		jwtManager: jwtManager,
		secret:     credentials.ClientSecret + ":" + KeyAudience,
	}
}

func windowStart(now time.Time) time.Time {
	window := int64(KeyWindow / time.Second)
	return time.Unix(now.Unix()/window*window, 0).UTC()
}

func (k KeyManager) Issue(uid string, version int, now time.Time) (string, time.Time, error) {
	start := windowStart(now)
	expiresAt := start.Add(KeyTTL)
	key, err := k.jwtManager.Sign(k.secret, keyClaims{
		Version: version,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        fmt.Sprintf("v%d-w%d", version, start.Unix()),
			Subject:   uid,
			Audience:  jwt.ClaimStrings{KeyAudience},
			IssuedAt:  jwt.NewNumericDate(start),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	})

	return key, expiresAt, err
}

// Verify returns the Dropbox account id and the key version the key was
// issued with. The caller must compare the version with the stored one.
func (k KeyManager) Verify(key string) (string, int, error) {
	var claims jwt.MapClaims
	if err := k.jwtManager.Verify(k.secret, key, &claims); err != nil {
		return "", 0, ErrInvalidKey
	}

	audience, err := claims.GetAudience()
	if err != nil || len(audience) != 1 || audience[0] != KeyAudience {
		return "", 0, ErrInvalidKey
	}

	if exp, err := claims.GetExpirationTime(); err != nil || exp == nil {
		return "", 0, ErrInvalidKey
	}

	uid, err := claims.GetSubject()
	if err != nil || uid == "" {
		return "", 0, ErrInvalidKey
	}

	raw, present := claims["ver"]
	if !present {
		return uid, 0, nil
	}

	version, ok := raw.(float64)
	if !ok || version < 0 || version != float64(int(version)) {
		return "", 0, ErrInvalidKey
	}

	return uid, int(version), nil
}
