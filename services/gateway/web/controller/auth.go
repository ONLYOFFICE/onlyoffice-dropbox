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

package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/embeddable"
	aclient "github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/client"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	"go-micro.dev/v4/client"
	"golang.org/x/oauth2"
)

type AuthController struct {
	client         client.Client
	api            aclient.DropboxClient
	jwtManager     crypto.JwtManager
	stateGenerator crypto.StateGenerator
	store          *sessions.CookieStore
	config         *config.ServerConfig
	oauth          *oauth2.Config
	logger         log.Logger
}

func NewAuthController(
	client client.Client,
	api aclient.DropboxClient,
	jwtManager crypto.JwtManager,
	stateGenerator crypto.StateGenerator,
	config *config.ServerConfig,
	oauth *oauth2.Config,
	logger log.Logger,
) AuthController {
	return AuthController{
		client:         client,
		api:            api,
		jwtManager:     jwtManager,
		stateGenerator: stateGenerator,
		store:          sessions.NewCookieStore([]byte(oauth.ClientSecret)),
		config:         config,
		oauth:          oauth,
		logger:         logger,
	}
}

func (c AuthController) getRedirectURL(rw http.ResponseWriter, r *http.Request) string {
	session, _ := c.store.Get(r, "url")
	url := "https://www.dropbox.com/home"

	if val, ok := session.Values["redirect"].(string); ok {
		url = val
	}

	session.Options.MaxAge = -1
	if err := session.Save(r, rw); err != nil {
		c.logger.Warnf("could not save a cookie session: %w", err)
	}

	return url
}

func (c AuthController) BuildGetAuth() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		v, _ := cv.CreateCodeVerifier()
		verifier := v.String()

		session, _ := c.store.Get(r, "auth-installation")
		session.Values["verifier"] = verifier
		state, err := c.stateGenerator.GenerateState(verifier)
		if err != nil {
			c.logger.Debugf("could not generate a new state. Reason: %s", err.Error())
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		session.Values["state"] = state
		if err := session.Save(r, rw); err != nil {
			c.logger.Debugf("could not save session. Reason: %s", err.Error())
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		http.Redirect(
			rw, r,
			fmt.Sprintf(
				"https://dropbox.com/oauth2/authorize?response_type=%s&client_id=%s&redirect_uri=%s&token_access_type=%s&state=%s&code_challenge=%s&code_challenge_method=%s&force_reapprove=true&disable_signup=true&include_granted_scopes=user",
				"code",
				c.oauth.ClientID,
				url.QueryEscape(c.oauth.RedirectURL),
				"offline",
				url.QueryEscape(state),
				v.CodeChallengeS256(),
				"S256",
			),
			http.StatusMovedPermanently,
		)
	}
}

func (c AuthController) BuildGetRedirect() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/html")
		tctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		query := r.URL.Query()
		code, state := strings.TrimSpace(query.Get("code")), strings.TrimSpace(query.Get("state"))
		if code == "" || state == "" {
			c.logger.Debug("empty auth code or state parameter")
			http.Redirect(rw, r, "/oauth/install", http.StatusMovedPermanently)
			return
		}

		errMsg := map[string]interface{}{
			"errorMain":    "Installation Failed",
			"errorSubtext": "Please try again or contact admin",
			"closeButton":  "Close",
		}

		session, err := c.store.Get(r, "auth-installation")
		if err != nil {
			c.logger.Debugf("could not get session store: %s", err.Error())
			if err := embeddable.InstallationErrorPage.Execute(rw, errMsg); err != nil {
				c.logger.Errorf("could not execute an installation error template: %w", err)
			}
			return
		}

		token, err, _ := group.Do(code, func() (interface{}, error) {
			state := strings.TrimSpace(query.Get("state"))
			if state != session.Values["state"] {
				c.logger.Errorf("state %s doesn't match %s", state, session.Values["state"])
				return nil, ErrInvalidStateValue
			}

			c.logger.Debugf("auth state is valid: %s", state)

			vefifier, ok := session.Values["verifier"].(string)
			if !ok {
				return nil, err
			}

			c.logger.Debugf("verifier is valid: %s", vefifier)

			session.Options.MaxAge = -1
			if err := session.Save(r, rw); err != nil {
				return nil, fmt.Errorf("could not save a cookie session: %w", err)
			}

			t, err := c.oauth.Exchange(tctx, code, oauth2.SetAuthURLParam("code_verifier", vefifier))
			if err != nil {
				return nil, fmt.Errorf("could not exchange oauth tokens: %w", err)
			}

			return t, nil
		})

		t, ok := token.(*oauth2.Token)
		if err != nil || !ok {
			if err := embeddable.InstallationErrorPage.Execute(rw, errMsg); err != nil {
				c.logger.Errorf("could not execute an installation error template: %w", err)
			}
			return
		}

		usr, err := c.api.GetUser(tctx, t.AccessToken)
		if err != nil {
			if err := embeddable.InstallationErrorPage.Execute(rw, errMsg); err != nil {
				c.logger.Errorf("could not execute an installation error template: %w", err)
			}
			return
		}

		var resp interface{}
		if err := c.client.Call(r.Context(), c.client.NewRequest(
			fmt.Sprintf("%s:auth", c.config.Namespace),
			"UserInsertHandler.InsertUser",
			response.UserResponse{
				ID:           usr.AccountID,
				AccessToken:  t.AccessToken,
				RefreshToken: t.RefreshToken,
				TokenType:    t.TokenType,
				Scope:        t.Extra("scope").(string),
				Expiry:       t.Expiry.UTC().Format(time.RFC3339),
			},
		), &resp, client.WithRetries(3)); err != nil {
			c.logger.Errorf("could not insert a new user: %s", err.Error())
			if err := embeddable.InstallationErrorPage.Execute(rw, errMsg); err != nil {
				c.logger.Errorf("could not execute an installation error template: %w", err)
			}
			return
		}

		session, _ = c.store.Get(r, "authorization")
		tkn, err := c.jwtManager.Sign(c.oauth.ClientSecret, jwt.RegisteredClaims{
			ID:        t.Extra("account_id").(string),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(25 * time.Hour)),
		})

		if err != nil {
			c.logger.Errorf("could not issue a new jwt: %s", err.Error())
			if err := embeddable.InstallationErrorPage.Execute(rw, errMsg); err != nil {
				c.logger.Errorf("could not execute an installation error template: %w", err)
			}
			return
		}

		session.Values["token"] = tkn
		session.Options.MaxAge = 60 * 60 * 24
		if err := session.Save(r, rw); err != nil {
			c.logger.Errorf("could not save current session: %s", err.Error())
			if err := embeddable.InstallationErrorPage.Execute(rw, errMsg); err != nil {
				c.logger.Errorf("could not execute an installation error template: %w", err)
			}
			return
		}

		http.Redirect(rw, r, c.getRedirectURL(rw, r), http.StatusMovedPermanently)
	}
}
