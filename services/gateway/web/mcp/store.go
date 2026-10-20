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
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"go-micro.dev/v4/client"
	merrors "go-micro.dev/v4/errors"
)

var ErrUserNotFound = errors.New("user not found")

func authError(err error, action, uid string) error {
	if merr := merrors.FromError(err); merr != nil && merr.Code == http.StatusNotFound {
		return fmt.Errorf("could not %s user %s: %w", action, uid, ErrUserNotFound)
	}

	return fmt.Errorf("could not %s user %s: %w", action, uid, err)
}

// UserStore reads and rotates the stored state of a Dropbox account: its
// access token and the version its MCP keys must carry.
type UserStore interface {
	GetUser(ctx context.Context, uid string) (response.UserResponse, error)
	RotateKey(ctx context.Context, uid string) (int, error)
}

// authUserStore is backed by the auth service RPC handlers.
type authUserStore struct {
	client client.Client
	server *config.ServerConfig
}

func NewUserStore(client client.Client, server *config.ServerConfig) UserStore {
	return authUserStore{
		client: client,
		server: server,
	}
}

func (s authUserStore) GetUser(ctx context.Context, uid string) (response.UserResponse, error) {
	var ures response.UserResponse
	if err := s.client.Call(ctx, s.client.NewRequest(
		fmt.Sprintf("%s:auth", s.server.Namespace), "UserSelectHandler.GetUser",
		uid,
	), &ures); err != nil {
		return ures, authError(err, "get", uid)
	}

	return ures, nil
}

func (s authUserStore) RotateKey(ctx context.Context, uid string) (int, error) {
	var version int
	if err := s.client.Call(ctx, s.client.NewRequest(
		fmt.Sprintf("%s:auth", s.server.Namespace), "UserKeyHandler.RotateKey",
		uid,
	), &version); err != nil {
		return 0, authError(err, "rotate key of", uid)
	}

	return version, nil
}

type accessTokenKey struct{}

func WithAccessToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, accessTokenKey{}, token)
}

func accessTokenFrom(ctx context.Context) string {
	token, _ := ctx.Value(accessTokenKey{}).(string)
	return token
}

type authUnavailableKey struct{}

func authUnavailable(ctx context.Context) bool {
	unavailable, _ := ctx.Value(authUnavailableKey{}).(bool)
	return unavailable
}

func WithAuthUnavailable(ctx context.Context) context.Context {
	return context.WithValue(ctx, authUnavailableKey{}, true)
}
