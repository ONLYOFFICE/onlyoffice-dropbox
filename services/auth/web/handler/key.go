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

package handler

import (
	"context"
	"fmt"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/port"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
)

type UserKeyHandler struct {
	service port.UserAccessService
	logger  log.Logger
}

func NewUserKeyHandler(service port.UserAccessService, logger log.Logger) UserKeyHandler {
	return UserKeyHandler{
		service: service,
		logger:  logger,
	}
}

// RotateKey invalidates every MCP key issued to the user and returns the new key version.
func (k UserKeyHandler) RotateKey(ctx context.Context, uid *string, res *int) error {
	version, err, _ := group.Do(fmt.Sprintf("rotate-%s", *uid), func() (interface{}, error) {
		version, err := k.service.RotateKey(ctx, *uid)
		if err != nil {
			k.logger.Debugf("could not rotate key of user %s: %s", *uid, err.Error())
			return nil, err
		}

		return version, nil
	})

	if err != nil {
		return fmt.Errorf("key rotation error: %w", err)
	}

	*res = version.(int)
	return nil
}
