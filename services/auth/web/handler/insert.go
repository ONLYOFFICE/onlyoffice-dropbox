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
	"fmt"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/domain"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/port"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
)

type UserInsertHandler struct {
	service port.UserAccessService
	logger  log.Logger
}

func NewUserInsertHandler(service port.UserAccessService, logger log.Logger) UserInsertHandler {
	return UserInsertHandler{
		service: service,
		logger:  logger,
	}
}

func (i UserInsertHandler) InsertUser(ctx context.Context, req response.UserResponse, res *domain.UserAccess) error {
	_, err, _ := group.Do(fmt.Sprintf("insert-%s", req.ID), func() (interface{}, error) {
		usr, err := i.service.UpdateUser(ctx, domain.UserAccess{
			ID:           req.ID,
			AccessToken:  req.AccessToken,
			RefreshToken: req.RefreshToken,
			TokenType:    req.TokenType,
			Scope:        req.Scope,
			Expiry:       req.Expiry,
		})

		if err != nil {
			i.logger.Errorf("could not update user: %s", err.Error())
			return nil, err
		}

		return usr, nil
	})

	return err
}
