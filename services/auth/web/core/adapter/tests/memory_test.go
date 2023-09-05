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

package adapter_test

import (
	"context"
	"testing"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/adapter"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/domain"
	"github.com/stretchr/testify/assert"
)

func TestMemoryAdapter(t *testing.T) {
	adapter := adapter.NewMemoryUserAdapter()

	t.Run("save user", func(t *testing.T) {
		assert.NoError(t, adapter.InsertUser(context.Background(), user))
	})

	t.Run("save the same user", func(t *testing.T) {
		assert.NoError(t, adapter.InsertUser(context.Background(), user))
	})

	t.Run("get user by id", func(t *testing.T) {
		u, err := adapter.SelectUser(context.Background(), "mock")
		assert.NoError(t, err)
		assert.Equal(t, user, u)
	})

	t.Run("update user by id", func(t *testing.T) {
		u, err := adapter.UpsertUser(context.Background(), domain.UserAccess{
			ID:          "mock",
			AccessToken: "BRuh",
		})
		assert.NoError(t, err)
		assert.NotNil(t, u)
	})

	t.Run("delete user by id", func(t *testing.T) {
		assert.NoError(t, adapter.DeleteUser(context.Background(), "mock"))
	})

	t.Run("get invalid user", func(t *testing.T) {
		_, err := adapter.SelectUser(context.Background(), "mock")
		assert.Error(t, err)
	})
}
