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

package adapter_test

import (
	"context"
	"testing"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/adapter"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryKeyVersion(t *testing.T) {
	ctx := context.Background()
	users := adapter.NewMemoryUserAdapter()
	usr := domain.UserAccess{
		ID:           "dbid:user",
		AccessToken:  "access",
		RefreshToken: "refresh",
		TokenType:    "Bearer",
		Scope:        "files.content.read",
		Expiry:       "2030-01-01T00:00:00Z",
	}

	require.NoError(t, users.InsertUser(ctx, usr))

	version, err := users.IncrementKeyVersion(ctx, usr.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, version)

	usr.AccessToken = "refreshed"

	_, err = users.UpsertUser(ctx, usr)

	require.NoError(t, err)

	stored, err := users.SelectUser(ctx, usr.ID)

	require.NoError(t, err)
	assert.Equal(t, "refreshed", stored.AccessToken)
	assert.Equal(t, 1, stored.KeyVersion)

	_, err = users.IncrementKeyVersion(ctx, "dbid:missing")
	assert.Error(t, err)
}
