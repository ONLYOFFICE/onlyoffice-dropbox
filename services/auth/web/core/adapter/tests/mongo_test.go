/**
 *
 * (c) Copyright Ascensio System SIA 2024
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
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/adapter"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/domain"
	"github.com/stretchr/testify/assert"
	"go-micro.dev/v4/logger"
)

var user = domain.UserAccess{
	ID:           "mock",
	AccessToken:  "mock",
	RefreshToken: "mock",
	TokenType:    "mock",
	Scope:        "mock",
	Expiry:       time.Now().Format(time.RFC3339),
}

func TestMongoAdapter(t *testing.T) {
	adapter := adapter.NewMongoUserAdapter("mongodb://localhost:27017")

	t.Run("save user with timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 0*time.Second)
		defer cancel()
		assert.Error(t, adapter.InsertUser(ctx, user))
	})

	t.Run("save user", func(t *testing.T) {
		assert.NoError(t, adapter.InsertUser(context.Background(), user))
	})

	t.Run("save the same user", func(t *testing.T) {
		assert.NoError(t, adapter.InsertUser(context.Background(), user))
	})

	t.Run("get user by id with timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 0*time.Second)
		defer cancel()
		_, err := adapter.SelectUser(ctx, "mock")
		assert.Error(t, err)
	})

	t.Run("get user by id", func(t *testing.T) {
		u, err := adapter.SelectUser(context.Background(), "mock")
		assert.NoError(t, err)
		assert.Equal(t, user, u)
	})

	t.Run("delete user by id with timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 0*time.Second)
		defer cancel()
		assert.Error(t, adapter.DeleteUser(ctx, "mock"))
	})

	t.Run("delete user by id", func(t *testing.T) {
		assert.NoError(t, adapter.DeleteUser(context.Background(), "mock"))
	})

	t.Run("get invalid user", func(t *testing.T) {
		_, err := adapter.SelectUser(context.Background(), "mock")
		assert.Error(t, err)
	})

	t.Run("invald user update", func(t *testing.T) {
		_, err := adapter.UpsertUser(context.Background(), domain.UserAccess{
			ID:          "mock",
			AccessToken: "BRuh",
			Expiry:      time.Now().Format(time.RFC3339),
		})
		assert.Error(t, err)
	})

	t.Run("update user with timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 0*time.Second)
		defer cancel()
		_, err := adapter.UpsertUser(ctx, domain.UserAccess{
			ID:           "mock",
			AccessToken:  "BRuh",
			RefreshToken: "BRUH",
			TokenType:    "mock",
			Scope:        "mock",
			Expiry:       time.Now().Format(time.RFC3339),
		})
		assert.Error(t, err)
	})

	t.Run("update user", func(t *testing.T) {
		_, err := adapter.UpsertUser(context.Background(), domain.UserAccess{
			ID:           "mock",
			AccessToken:  "BRuh",
			RefreshToken: "BRUH",
			TokenType:    "mock",
			Scope:        "mock",
			Expiry:       time.Now().Format(time.RFC3339),
		})
		assert.NoError(t, err)
	})

	t.Run("get updated user", func(t *testing.T) {
		u, err := adapter.SelectUser(context.Background(), "mock")
		assert.NoError(t, err)
		assert.Equal(t, "BRuh", u.AccessToken)
	})

	if err := adapter.DeleteUser(context.Background(), "mock"); err != nil {
		logger.Fatal(err.Error())
	}
}
