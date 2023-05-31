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

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/port"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"go-micro.dev/v4/client"
)

type UserDeleteHandler struct {
	service port.UserAccessService
	client  client.Client
	logger  log.Logger
}

func NewUserDeleteHandler(
	service port.UserAccessService,
	client client.Client,
	logger log.Logger,
) UserDeleteHandler {
	return UserDeleteHandler{
		service: service,
		client:  client,
		logger:  logger,
	}
}

func (u UserDeleteHandler) DeleteUser(ctx context.Context, uid *string, res *interface{}) error {
	_, err, _ := group.Do(fmt.Sprintf("remove-%s", *uid), func() (interface{}, error) {
		u.logger.Debugf("removing user %s", *uid)
		if err := u.service.RemoveUser(ctx, *uid); err != nil {
			u.logger.Debugf("could not delete user %s: %s", *uid, err.Error())
			return nil, err
		}

		return nil, nil
	})

	return err
}
