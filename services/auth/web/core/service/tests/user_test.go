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

package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/domain"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/service"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/cache"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

type mockEncryptor struct{}

func (e mockEncryptor) Encrypt(text string, key []byte) (string, error) {
	return string(text), nil
}

func (e mockEncryptor) Decrypt(ciphertext string, key []byte) (string, error) {
	return string(ciphertext), nil
}

type mockAdapter struct {
}

var user = domain.UserAccess{
	ID:           "mock",
	AccessToken:  "mock",
	RefreshToken: "mock",
	TokenType:    "mock",
	Scope:        "mock",
	Expiry:       time.Now().Format(time.RFC3339),
}

func (m mockAdapter) InsertUser(ctx context.Context, user domain.UserAccess) error {
	return nil
}

func (m mockAdapter) SelectUser(ctx context.Context, uid string) (domain.UserAccess, error) {
	return user, nil
}

func (m mockAdapter) UpsertUser(ctx context.Context, user domain.UserAccess) (domain.UserAccess, error) {
	return domain.UserAccess{
		ID:          "mock",
		AccessToken: "mock",
		Expiry:      time.Now().Format(time.RFC3339),
	}, nil
}

func (m mockAdapter) DeleteUser(ctx context.Context, uid string) error {
	return nil
}

func TestUserService(t *testing.T) {
	service := service.NewUserService(mockAdapter{}, mockEncryptor{}, cache.NewCache(&config.CacheConfig{}),
		&oauth2.Config{ClientSecret: "mock"}, log.NewEmptyLogger())

	t.Run("save user", func(t *testing.T) {
		assert.NoError(t, service.CreateUser(context.Background(), user))
	})

	t.Run("get user", func(t *testing.T) {
		u, err := service.GetUser(context.Background(), "mock")
		assert.NoError(t, err)
		assert.Equal(t, user, u)
	})

	t.Run("get user with timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 0*time.Second)
		defer cancel()
		_, err := service.GetUser(ctx, "mock")
		assert.Error(t, err)
	})

	t.Run("update user token", func(t *testing.T) {
		_, err := service.UpdateUser(context.Background(), domain.UserAccess{
			ID:           "mock",
			AccessToken:  "mock",
			RefreshToken: "mock",
			TokenType:    "mock",
			Scope:        "mock",
			Expiry:       time.Now().Format(time.RFC3339),
		})
		assert.NoError(t, err)
	})

	t.Run("update user token with timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 0*time.Second)
		defer cancel()
		_, err := service.UpdateUser(ctx, domain.UserAccess{
			ID:           "mock",
			AccessToken:  "mock",
			RefreshToken: "mock",
			TokenType:    "mock",
			Scope:        "mock",
			Expiry:       time.Now().Format(time.RFC3339),
		})
		assert.Error(t, err)
	})

	t.Run("delete user", func(t *testing.T) {
		assert.NoError(t, service.RemoveUser(context.Background(), "mock"))
	})
}
