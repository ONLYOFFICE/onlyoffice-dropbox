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

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/request"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/response"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/go-resty/resty/v2"
	"github.com/mitchellh/mapstructure"
	"go-micro.dev/v4/cache"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
)

var ErrInvalidResponsePayload = errors.New("invalid response payload")

type DropboxClient struct {
	client      *resty.Client
	cache       cache.Cache
	credentials *oauth2.Config
}

func NewDropboxAuthClient(
	cache cache.Cache,
	credentials *oauth2.Config,
) DropboxClient {
	otelClient := otelhttp.DefaultClient
	otelClient.Transport = otelhttp.NewTransport(&http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		ExpectContinueTimeout: 4 * time.Second,
	})
	return DropboxClient{
		client: resty.NewWithClient(otelClient).
			SetRedirectPolicy(resty.RedirectPolicyFunc(func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			})).
			SetRetryCount(3).
			SetTimeout(10 * time.Second).
			SetRetryWaitTime(120 * time.Millisecond).
			SetRetryMaxWaitTime(900 * time.Millisecond).
			SetLogger(log.NewEmptyLogger()).
			AddRetryCondition(func(r *resty.Response, err error) bool {
				return r.StatusCode() == http.StatusTooManyRequests
			}),
		cache:       cache,
		credentials: credentials,
	}
}

func (c DropboxClient) GetUser(ctx context.Context, token string) (response.DropboxUserResponse, error) {
	var res response.DropboxUserResponse
	if _, err := c.client.R().
		SetAuthToken(token).
		SetResult(&res).
		Post("https://api.dropboxapi.com/2/users/get_current_account"); err != nil {
		return res, err
	}

	if res.AccountID == "" {
		return res, ErrInvalidResponsePayload
	}

	return res, nil
}

func (c DropboxClient) GetFile(ctx context.Context, path, token string) (response.DropboxFileResponse, error) {
	var res response.DropboxFileResponse
	cacheKey := fmt.Sprintf("file:%s", path)

	if val, _, err := c.cache.Get(ctx, cacheKey); err == nil {
		if merr := mapstructure.Decode(val, &res); merr == nil {
			return res, nil
		}
	}

	if _, err := c.client.R().
		SetBody(map[string]interface{}{
			"include_deleted":                     false,
			"include_has_explicit_shared_members": false,
			"include_media_info":                  false,
			"path":                                path,
		}).
		SetAuthToken(token).
		SetResult(&res).
		Post("https://api.dropboxapi.com/2/files/get_metadata"); err != nil {
		return res, err
	}

	if res.ID == "" {
		return res, ErrInvalidResponsePayload
	}

	c.cache.Put(ctx, cacheKey, res, 10*time.Second)

	return res, nil
}

func (c DropboxClient) GetFileVersions(ctx context.Context, path, token string) (response.DropboxFileVersionsResponse, error) {
	var res response.DropboxFileVersionsResponse
	cacheKey := fmt.Sprintf("history:%s", path)

	if val, _, err := c.cache.Get(ctx, cacheKey); err == nil {
		if merr := mapstructure.Decode(val, &res); merr == nil {
			return res, nil
		}
	}

	if _, err := c.client.R().
		SetBody(request.DropboxFileVersionsRequest{
			Limit: 50,
			Mode:  "id",
			Path:  path,
		}).
		SetAuthToken(token).
		SetResult(&res).
		Post("https://api.dropboxapi.com/2/files/list_revisions"); err != nil {
		return res, err
	}

	if len(res.Entries) > 0 {
		c.cache.Put(ctx, cacheKey, res, 10*time.Second)
	}

	res.ExcludeStale()
	res.SortEntries()

	return res, nil
}

func (c DropboxClient) GetDownloadLink(ctx context.Context, path, token string) (response.DropboxDownloadResponse, error) {
	var res response.DropboxDownloadResponse
	cacheKey := fmt.Sprintf("downloadLink:%s", path)

	if val, _, err := c.cache.Get(ctx, cacheKey); err == nil {
		if merr := mapstructure.Decode(val, &res); merr == nil {
			return res, nil
		}
	}

	if _, err := c.client.R().
		SetBody(map[string]string{
			"path": path,
		}).
		SetAuthToken(token).
		SetResult(&res).
		Post("https://api.dropboxapi.com/2/files/get_temporary_link"); err != nil {
		return res, fmt.Errorf("could not get dropbox temporary link: %w", err)
	}

	if res.Link == "" {
		return res, ErrInvalidResponsePayload
	}

	c.cache.Put(ctx, cacheKey, res, 10*time.Second)

	return res, nil
}

func (c DropboxClient) uploadFile(ctx context.Context, path, token, mode string, file io.Reader) (response.DropboxFileResponse, error) {
	var res response.DropboxFileResponse
	req, err := http.NewRequest("POST", "https://content.dropboxapi.com/2/files/upload", file)
	if err != nil {
		return res, fmt.Errorf("could not build a request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Dropbox-API-Arg", fmt.Sprintf("{\"autorename\":true,\"mode\":\"%s\",\"mute\":false,\"path\":\"%s\",\"strict_conflict\":false}", mode, path))
	resp, err := otelhttp.DefaultClient.Do(req)
	if err != nil {
		return res, fmt.Errorf("could not send a request: %w", err)
	}

	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return res, fmt.Errorf("could not decode response: %w", err)
	}

	if res.ID == "" {
		return res, ErrInvalidResponsePayload
	}

	return res, nil
}

func (c DropboxClient) CreateFile(ctx context.Context, path, token string, file io.Reader) (response.DropboxFileResponse, error) {
	return c.uploadFile(ctx, path, token, "add", file)
}

func (c DropboxClient) UploadFile(ctx context.Context, path, token string, file io.Reader) (response.DropboxFileResponse, error) {
	return c.uploadFile(ctx, path, token, "overwrite", file)
}

func (c DropboxClient) SaveFileFromURL(ctx context.Context, path, url, token string) error {
	if _, err := c.client.R().
		SetBody(map[string]string{
			"path": path,
			"url":  url,
		}).
		SetAuthToken(token).
		Post("https://api.dropboxapi.com/2/files/save_url"); err != nil {
		return fmt.Errorf("could not save dropbox file from url: %w", err)
	}

	return nil
}
