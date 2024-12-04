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

package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/domain"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/port"
)

type memoryUserAdapter struct {
	kvs map[string][]byte
}

func NewMemoryUserAdapter() port.UserAccessServiceAdapter {
	return &memoryUserAdapter{
		kvs: make(map[string][]byte),
	}
}

func (m *memoryUserAdapter) save(user domain.UserAccess) error {
	buffer, err := json.Marshal(user)

	if err != nil {
		return fmt.Errorf("could not marshal a new user: %w", err)
	}

	m.kvs[user.ID] = buffer

	return nil
}

func (m *memoryUserAdapter) InsertUser(ctx context.Context, user domain.UserAccess) error {
	return m.save(user)
}

func (m *memoryUserAdapter) SelectUser(ctx context.Context, uid string) (domain.UserAccess, error) {
	buffer, ok := m.kvs[uid]
	var user domain.UserAccess

	if !ok {
		return user, errors.New("user with this id doesn't exist")
	}

	if err := json.Unmarshal(buffer, &user); err != nil {
		return user, fmt.Errorf("could not unmarshal a user: %w", err)
	}

	return user, nil
}

func (m *memoryUserAdapter) UpsertUser(ctx context.Context, user domain.UserAccess) (domain.UserAccess, error) {
	if err := m.save(user); err != nil {
		return domain.UserAccess{}, err
	}

	return user, nil
}

func (m *memoryUserAdapter) DeleteUser(ctx context.Context, uid string) error {
	if _, ok := m.kvs[uid]; !ok {
		return errors.New("user with this id doesn't exist")
	}

	delete(m.kvs, uid)

	return nil
}
