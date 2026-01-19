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

package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/domain"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/core/port"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	plog "github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/mitchellh/mapstructure"
	"go-micro.dev/v4/cache"
	"golang.org/x/oauth2"
)

type userService struct {
	adapter     port.UserAccessServiceAdapter
	encryptor   crypto.Encryptor
	cache       cache.Cache
	credentials *oauth2.Config
	logger      plog.Logger
}

func NewUserService(
	adapter port.UserAccessServiceAdapter,
	encryptor crypto.Encryptor,
	cache cache.Cache,
	credentials *oauth2.Config,
	logger plog.Logger,
) port.UserAccessService {
	return userService{
		adapter:     adapter,
		encryptor:   encryptor,
		cache:       cache,
		credentials: credentials,
		logger:      logger,
	}
}

func (s userService) CreateUser(ctx context.Context, user domain.UserAccess) error {
	s.logger.Debugf("validating user %s to perform a persist action", user.ID)
	if err := user.Validate(); err != nil {
		return fmt.Errorf("could not validate a new user: %w", err)
	}

	aToken, err := s.encryptor.Encrypt(user.AccessToken, []byte(s.credentials.ClientSecret))
	if err != nil {
		return err
	}
	rToken, err := s.encryptor.Encrypt(user.RefreshToken, []byte(s.credentials.ClientSecret))
	if err != nil {
		return err
	}

	s.logger.Debugf("user %s is valid. Persisting to database: %s", user.ID, user.AccessToken)
	if err := s.adapter.InsertUser(ctx, domain.UserAccess{
		ID:           user.ID,
		AccessToken:  aToken,
		RefreshToken: rToken,
		TokenType:    user.TokenType,
		Scope:        user.Scope,
		Expiry:       user.Expiry,
	}); err != nil {
		return fmt.Errorf("could not insert a new user: %w", err)
	}

	return nil
}

func (s userService) GetUser(ctx context.Context, uid string) (domain.UserAccess, error) {
	s.logger.Debugf("trying to select user with id: %s", uid)
	id := strings.TrimSpace(uid)

	if id == "" {
		s.logger.Debugf("user ID is empty or blank")
		return domain.UserAccess{}, &InvalidServiceParameterError{
			Name:   "UID",
			Reason: "Should not be blank",
		}
	}

	var user domain.UserAccess
	var err error
	if res, _, err := s.cache.Get(ctx, id); err == nil && res != nil {
		s.logger.Debugf("found user %s in the cache", id)
		if err := mapstructure.Decode(res, &user); err != nil {
			s.logger.Errorf("could not decode from cache: %s", err.Error())
		}
	}

	if user.Validate() != nil {
		s.logger.Debugf("user not found in cache or cache entry invalid, querying database for user: %s", id)
		user, err = s.adapter.SelectUser(ctx, id)
		if err != nil {
			s.logger.Debugf("failed to select user %s from database: %v", id, err)
			return user, fmt.Errorf("could not select user: %w", err)
		}

		s.logger.Debugf("successfully retrieved user %s from database", id)

		exp, err := time.Parse(time.RFC3339, user.Expiry)
		if err != nil {
			return user, fmt.Errorf("could not parse user expiration: %w", err)
		}

		if err := s.cache.Put(ctx, id, user, time.Duration((exp.UnixMilli()-10)*1e6/6)); err != nil {
			s.logger.Warnf("could not put user to the cache: %w", err)
		}
	}

	s.logger.Debugf("found a user: %v", user)

	aToken, err := s.encryptor.Decrypt(user.AccessToken, []byte(s.credentials.ClientSecret))
	if err != nil {
		return domain.UserAccess{}, err
	}

	rToken, err := s.encryptor.Decrypt(user.RefreshToken, []byte(s.credentials.ClientSecret))
	if err != nil {
		return domain.UserAccess{}, err
	}

	return domain.UserAccess{
		ID:           user.ID,
		AccessToken:  aToken,
		RefreshToken: rToken,
		TokenType:    user.TokenType,
		Scope:        user.Scope,
		Expiry:       user.Expiry,
	}, nil
}

func (s userService) UpdateUser(ctx context.Context, user domain.UserAccess) (domain.UserAccess, error) {
	s.logger.Debugf("validating user %s to perform an update action", user.ID)
	if err := user.Validate(); err != nil {
		return domain.UserAccess{}, fmt.Errorf("could not validate a user: %w", err)
	}

	aToken, err := s.encryptor.Encrypt(user.AccessToken, []byte(s.credentials.ClientSecret))
	if err != nil {
		return user, err
	}
	rToken, err := s.encryptor.Encrypt(user.RefreshToken, []byte(s.credentials.ClientSecret))
	if err != nil {
		return user, err
	}

	euser := domain.UserAccess{
		ID:           user.ID,
		AccessToken:  aToken,
		RefreshToken: rToken,
		TokenType:    user.TokenType,
		Scope:        user.Scope,
		Expiry:       user.Expiry,
	}

	exp, err := time.Parse(time.RFC3339, user.Expiry)
	if err != nil {
		return user, fmt.Errorf("could not parse user expiration: %w", err)
	}

	if err := s.cache.Put(ctx, euser.ID, euser, time.Duration((exp.UnixMilli()-10)*1e6/6)); err != nil {
		s.logger.Warnf("could not populate cache with a user %s instance: %s", euser.ID, err.Error())
		if err := s.cache.Delete(ctx, euser.ID); err != nil {
			s.logger.Warnf("could not remove user from the cache: %w", err)
		}
	}

	s.logger.Debugf("user %s is valid to perform an update action", user.ID)
	if _, err := s.adapter.UpsertUser(ctx, euser); err != nil {
		return user, fmt.Errorf("could not upsert a user: %w", err)
	}

	return user, nil
}

func (s userService) RemoveUser(ctx context.Context, uid string) error {
	id := strings.TrimSpace(uid)
	s.logger.Debugf("validating uid %s to perform a delete action", id)

	if id == "" {
		return &InvalidServiceParameterError{
			Name:   "UID",
			Reason: "Should not be blank",
		}
	}

	if _, _, err := s.cache.Get(ctx, uid); err == nil {
		if err := s.cache.Delete(ctx, uid); err != nil {
			return fmt.Errorf("could not remove an entry from the cache: %w", err)
		}
	}

	s.logger.Debugf("uid %s is valid to perform a delete action", id)
	return s.adapter.DeleteUser(ctx, uid)
}
