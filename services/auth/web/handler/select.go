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

package handler

import (
	"context"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/domain"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/port"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"go-micro.dev/v4/client"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

var group singleflight.Group

type UserSelectHandler struct {
	service     port.UserAccessService
	client      client.Client
	credentials *oauth2.Config
	logger      log.Logger
}

func NewUserSelectHandler(
	service port.UserAccessService,
	client client.Client,
	credentials *oauth2.Config,
	logger log.Logger,
) UserSelectHandler {
	return UserSelectHandler{
		service:     service,
		client:      client,
		credentials: credentials,
		logger:      logger,
	}
}

func (u UserSelectHandler) GetUser(ctx context.Context, uid *string, res *domain.UserAccess) error {
	user, err, _ := group.Do(*uid, func() (interface{}, error) {
		user, err := u.service.GetUser(ctx, *uid)
		if err != nil {
			u.logger.Debugf("could not get user with id: %s. Reason: %s", *uid, err.Error())
			return nil, err
		}

		t, err := time.Parse(time.RFC3339, user.Expiry)
		if err != nil {
			u.logger.Debugf("could not parse time: %s", err.Error())
			return user, err
		}

		t = t.Add(-2 * time.Minute)
		if t.Before(time.Now()) {
			ts := u.credentials.TokenSource(ctx, &oauth2.Token{
				AccessToken:  user.AccessToken,
				TokenType:    user.TokenType,
				RefreshToken: user.RefreshToken,
				Expiry:       time.Now().AddDate(-10, -1, -1),
			})

			nToken, err := ts.Token()
			if err != nil {
				u.logger.Debugf("could not refresh access token: %s", err.Error())
				return user, err
			}

			uctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			user, err = u.service.UpdateUser(uctx, domain.UserAccess{
				ID:           user.ID,
				AccessToken:  nToken.AccessToken,
				RefreshToken: nToken.RefreshToken,
				TokenType:    "Bearer",
				Scope:        user.Scope,
				Expiry:       nToken.Expiry.UTC().Format(time.RFC3339),
			})

			if err != nil {
				u.logger.Debugf("could not update user: %s", err.Error())
				return user, err
			}
		}

		return user, nil
	})

	if usr, ok := user.(domain.UserAccess); ok {
		*res = usr
		return nil
	}

	return err
}
