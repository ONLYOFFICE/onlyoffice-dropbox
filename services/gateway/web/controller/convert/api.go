/**
 *
 * (c) Copyright Ascensio System SIA 2025
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

package convert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared"
	aclient "github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/client"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/format"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/config"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/crypto"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"go-micro.dev/v4/client"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
	"golang.org/x/text/language"
)

var (
	errFormatNotSupported              = errors.New("current format is not supported")
	errConversionErrorOccurred         = errors.New("could not convert current file")
	errConversionAutoFormatError       = errors.New("could not detect xml format automatically")
	errConversionPasswordRequiredError = errors.New("could not convert protected file")
)

type ConvertController struct {
	client        client.Client
	api           aclient.DropboxClient
	jwtManager    crypto.JwtManager
	formatManager format.FormatManager
	store         *sessions.CookieStore
	server        *config.ServerConfig
	hasher        crypto.Hasher
	credentials   *oauth2.Config
	onlyoffice    *shared.OnlyofficeConfig
	logger        log.Logger
}

func NewConvertController(
	client client.Client, api aclient.DropboxClient, jwtManager crypto.JwtManager,
	formatManager format.FormatManager, onlyoffice *shared.OnlyofficeConfig, hasher crypto.Hasher,
	server *config.ServerConfig, credentials *oauth2.Config, logger log.Logger,
) ConvertController {
	return ConvertController{
		client:        client,
		api:           api,
		jwtManager:    jwtManager,
		formatManager: formatManager,
		store:         sessions.NewCookieStore([]byte(credentials.ClientSecret)),
		server:        server,
		hasher:        hasher,
		credentials:   credentials,
		onlyoffice:    onlyoffice,
		logger:        logger,
	}
}

func (c ConvertController) convertFile(ctx context.Context, uid string, aRequest request.ConvertActionRequest) (*request.ConvertActionRequest, error) {
	uctx, cancel := context.WithTimeout(ctx, time.Duration(c.onlyoffice.Onlyoffice.Callback.UploadTimeout)*time.Second)
	defer cancel()

	var ures response.UserResponse
	if err := c.client.Call(uctx, c.client.NewRequest(
		fmt.Sprintf("%s:auth", c.server.Namespace), "UserSelectHandler.GetUser",
		fmt.Sprint(uid),
	), &ures); err != nil {
		c.logger.Errorf("could not get user %s access info: %s", uid, err.Error())
		return nil, err
	}

	var dures response.DropboxUserResponse
	var file response.DropboxFileResponse
	var dres response.DropboxDownloadResponse
	g, gctx := errgroup.WithContext(uctx)

	g.Go(func() error {
		var err error
		dures, err = c.api.GetUser(gctx, ures.AccessToken)
		if err != nil {
			c.logger.Errorf("could not get user profile: %s", err.Error())
			return err
		}
		return nil
	})

	g.Go(func() error {
		var err error
		file, err = c.api.GetFile(gctx, aRequest.FileID, ures.AccessToken)
		if err != nil {
			c.logger.Errorf("could not get file: %s", err.Error())
			return err
		}
		return nil
	})

	g.Go(func() error {
		var err error
		dres, err = c.api.GetDownloadLink(gctx, aRequest.FileID, ures.AccessToken)
		if err != nil {
			c.logger.Errorf("could not get download link: %s", err.Error())
			return err
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	ext := c.formatManager.GetFileExt(file.Name)
	if ext == "" || ext == "csv" {
		return nil, errFormatNotSupported
	}

	format, supported := c.formatManager.GetFormatByName(ext)
	if !supported {
		return nil, errFormatNotSupported
	}

	outputType := "ooxml"
	if _, supported := c.formatManager.GetFormatByName(aRequest.XmlType); supported && aRequest.XmlType != "" {
		outputType = aRequest.XmlType
	}

	tag, err := language.Parse(dures.Locale)
	if err != nil {
		return nil, err
	}

	region, _ := tag.Region()
	creq := request.ConvertRequest{
		Async:      false,
		Key:        string(c.hasher.Hash(file.CModified + file.ID + time.Now().String())),
		Filetype:   format.Name,
		Outputtype: outputType,
		URL:        dres.Link,
		Password:   aRequest.Password,
		Region:     fmt.Sprintf("%s-%s", dures.Locale, region),
	}
	creq.IssuedAt = jwt.NewNumericDate(time.Now())
	creq.ExpiresAt = jwt.NewNumericDate(time.Now().Add(2 * time.Minute))
	ctok, err := c.jwtManager.Sign(c.onlyoffice.Onlyoffice.Builder.DocumentServerSecret, creq)
	if err != nil {
		return nil, err
	}

	creq.Token = ctok
	reqBody, err := json.Marshal(creq)
	if err != nil {
		c.logger.Errorf("could not marshal convert request: %s", err.Error())
		return nil, err
	}

	req, err := http.NewRequestWithContext(
		uctx,
		http.MethodPost,
		fmt.Sprintf("%s/converter?shardkey=%s", c.onlyoffice.Onlyoffice.Builder.DocumentServerURL, creq.Key),
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		c.logger.Errorf("could not build conversion API request: %s", err.Error())
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	resp, err := otelhttp.DefaultClient.Do(req)
	if err != nil {
		c.logger.Errorf("could not send conversion API request: %s", err.Error())
		return nil, err
	}

	defer resp.Body.Close()

	var cresp response.ConvertResponse
	if err := json.NewDecoder(resp.Body).Decode(&cresp); err != nil {
		c.logger.Errorf("could not decode convert response body: %s", err.Error())
		return nil, err
	}

	if cresp.Error == -9 {
		return nil, errConversionAutoFormatError
	}

	if cresp.Error == -5 {
		return nil, errConversionPasswordRequiredError
	}

	if cresp.Error < 0 {
		return nil, errConversionErrorOccurred
	}

	cfile, err := otelhttp.Get(uctx, cresp.FileURL)
	if err != nil {
		c.logger.Errorf("could not retrieve converted file: %s", err.Error())
		return nil, err
	}

	defer cfile.Body.Close()
	filename := fmt.Sprintf("%s.%s", file.Name[:len(file.Name)-len(filepath.Ext(file.Name))], cresp.FileType)
	newPath := fmt.Sprintf("%s/%s", file.PathLower[:strings.LastIndex(file.PathLower, "/")], filename)
	uplres, err := c.api.CreateFile(ctx, newPath, ures.AccessToken, cfile.Body)
	if err != nil {
		c.logger.Errorf("could not upload converted file %s: %s", aRequest.FileID, err.Error())
		return nil, err
	}

	return &request.ConvertActionRequest{
		Action:    "edit",
		FileID:    uplres.ID,
		ForceEdit: false,
	}, nil
}

func (c ConvertController) BuildConvertFile() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		uid := rw.Header().Get("X-User")
		if uid == "" {
			c.logger.Errorf("authorization context has no user id")
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		var creq request.ConvertActionRequest
		if err := json.NewDecoder(r.Body).Decode(&creq); err != nil {
			c.logger.Errorf("could not parse conversion request: %s", err.Error())
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		if creq.Action == "edit" {
			creq.ForceEdit = true
		}

		creq.IssuedAt = jwt.NewNumericDate(time.Now())
		creq.ExpiresAt = jwt.NewNumericDate(time.Now().Add(5 * time.Minute))
		token, err := c.jwtManager.Sign(c.credentials.ClientSecret, creq)
		if err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		if creq.Action == "create" {
			ncreq, err := c.convertFile(r.Context(), uid, creq)
			if err != nil {
				if errors.Is(errConversionAutoFormatError, err) {
					rw.WriteHeader(http.StatusBadRequest)
					return
				}

				if errors.Is(errConversionPasswordRequiredError, err) {
					rw.WriteHeader(http.StatusLocked)
					return
				}

				rw.WriteHeader(http.StatusInternalServerError)
				return
			}

			ncreq.IssuedAt = jwt.NewNumericDate(time.Now())
			ncreq.ExpiresAt = jwt.NewNumericDate(time.Now().Add(5 * time.Minute))
			sig, err := c.jwtManager.Sign(c.credentials.ClientSecret, ncreq)
			if err != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				return
			}

			http.Redirect(
				rw, r,
				fmt.Sprintf(
					"/editor?token=%s&file_id=%s",
					sig,
					ncreq.FileID,
				),
				http.StatusMovedPermanently,
			)

			return
		}

		http.Redirect(
			rw, r,
			fmt.Sprintf(
				"/editor?token=%s&file_id=%s",
				token,
				creq.FileID,
			),
			http.StatusMovedPermanently,
		)
	}
}
