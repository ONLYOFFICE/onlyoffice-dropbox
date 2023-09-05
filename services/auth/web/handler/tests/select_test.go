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

package handler_test

import (
	"context"
	"testing"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/adapter"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/domain"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/service"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/handler"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/cache"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/stretchr/testify/assert"
	"go-micro.dev/v4/logger"
	"golang.org/x/oauth2"
)

type mockEncryptor struct{}

func (e mockEncryptor) Encrypt(text string, key []byte) (string, error) {
	return string(text), nil
}

func (e mockEncryptor) Decrypt(ciphertext string, key []byte) (string, error) {
	return string(ciphertext), nil
}

func TestSelectCaching(t *testing.T) {
	adapter := adapter.NewMemoryUserAdapter()
	cache := cache.NewCache(&config.CacheConfig{})
	service := service.NewUserService(adapter, mockEncryptor{}, cache,
		&oauth2.Config{ClientSecret: "mock"}, log.NewEmptyLogger())

	sel := handler.NewUserSelectHandler(service, nil, &oauth2.Config{}, log.NewEmptyLogger())

	if err := service.CreateUser(context.Background(), domain.UserAccess{
		ID:           "mock",
		AccessToken:  "mock",
		RefreshToken: "mock",
		TokenType:    "mock",
		Scope:        "mock",
		Expiry:       time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		logger.Fatal(err.Error())
	}

	t.Run("get user", func(t *testing.T) {
		var res domain.UserAccess
		id := "mock"
		assert.NoError(t, sel.GetUser(context.Background(), &id, &res))
		assert.NotEmpty(t, res)
	})
}
