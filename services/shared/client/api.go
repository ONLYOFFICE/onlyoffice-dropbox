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

package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

type OperationType int

const (
	GetFile OperationType = iota
	GetFileVersions
	GetDownloadLink
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

func (c DropboxClient) getUser(ctx context.Context, token string) (response.DropboxUserResponse, error) {
	var res response.DropboxUserResponse

	h := sha256.Sum256([]byte(token))
	cacheKey := fmt.Sprintf("user:%s", hex.EncodeToString(h[:])[:16])

	if val, _, err := c.cache.Get(ctx, cacheKey); err == nil {
		if merr := mapstructure.Decode(val, &res); merr == nil {
			return res, nil
		}
	}

	if _, err := c.client.R().
		SetContext(ctx).
		SetAuthToken(token).
		SetHeader("Content-Type", "application/json").
		SetBody([]byte("null")).
		SetResult(&res).
		Post("https://api.dropboxapi.com/2/users/get_current_account"); err != nil {
		return res, err
	}

	if res.AccountID == "" {
		return res, ErrInvalidResponsePayload
	}

	c.cache.Put(ctx, cacheKey, res, 30*time.Second)

	return res, nil
}

func (c DropboxClient) buildTeamHeader(rootNamespaceID string) (string, error) {
	header := request.DropboxPathRootHeader{
		Tag:  "root",
		Root: rootNamespaceID,
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal path root header: %w", err)
	}

	return string(headerBytes), nil
}

func (c DropboxClient) isTeamAccount(userRes response.DropboxUserResponse) bool {
	return userRes.AccountID != "" &&
		userRes.RootInfo != nil &&
		userRes.RootInfo.RootNamespaceID != ""
}

func (c DropboxClient) getFileStandard(
	ctx context.Context,
	path, token string,
	res response.DropboxFileResponse,
	_ string,
) (response.DropboxFileResponse, error) {
	if _, err := c.client.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetBody(map[string]any{
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

	return res, nil
}

func (c DropboxClient) getFileTeam(
	ctx context.Context,
	path, token string,
	userRes response.DropboxUserResponse,
) (response.DropboxFileResponse, error) {
	var res response.DropboxFileResponse

	if userRes.RootInfo == nil || userRes.RootInfo.RootNamespaceID == "" {
		return res, ErrInvalidResponsePayload
	}

	pathRootHeader, err := c.buildTeamHeader(userRes.RootInfo.RootNamespaceID)
	if err != nil {
		return res, err
	}

	if _, err := c.client.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetBody(map[string]any{
			"include_deleted":                     false,
			"include_has_explicit_shared_members": false,
			"include_media_info":                  false,
			"path":                                path,
		}).
		SetAuthToken(token).
		SetHeader("Dropbox-API-Path-Root", pathRootHeader).
		SetResult(&res).
		Post("https://api.dropboxapi.com/2/files/get_metadata"); err != nil {
		return res, err
	}

	return res, nil
}

func (c DropboxClient) getFileVersionsStandard(
	ctx context.Context,
	path, token string,
	res response.DropboxFileVersionsResponse,
	_ string,
) (response.DropboxFileVersionsResponse, error) {
	if _, err := c.client.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
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

	return res, nil
}

func (c DropboxClient) getFileVersionsTeam(
	ctx context.Context,
	path, token string,
	userRes response.DropboxUserResponse,
) (response.DropboxFileVersionsResponse, error) {
	var res response.DropboxFileVersionsResponse

	if userRes.RootInfo == nil || userRes.RootInfo.RootNamespaceID == "" {
		return res, ErrInvalidResponsePayload
	}

	pathRootHeader, err := c.buildTeamHeader(userRes.RootInfo.RootNamespaceID)
	if err != nil {
		return res, err
	}

	if _, err := c.client.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetBody(request.DropboxFileVersionsRequest{
			Limit: 50,
			Mode:  "id",
			Path:  path,
		}).
		SetAuthToken(token).
		SetHeader("Dropbox-API-Path-Root", pathRootHeader).
		SetResult(&res).
		Post("https://api.dropboxapi.com/2/files/list_revisions"); err != nil {
		return res, err
	}

	return res, nil
}

func (c DropboxClient) getDownloadLinkStandard(
	ctx context.Context,
	path, token string,
	res response.DropboxDownloadResponse,
	_ string,
) (response.DropboxDownloadResponse, error) {
	if _, err := c.client.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
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

	return res, nil
}

func (c DropboxClient) getDownloadLinkTeam(
	ctx context.Context,
	path, token string,
	userRes response.DropboxUserResponse,
) (response.DropboxDownloadResponse, error) {
	var res response.DropboxDownloadResponse

	if userRes.RootInfo == nil || userRes.RootInfo.RootNamespaceID == "" {
		return res, ErrInvalidResponsePayload
	}

	pathRootHeader, err := c.buildTeamHeader(userRes.RootInfo.RootNamespaceID)
	if err != nil {
		return res, err
	}

	if _, err := c.client.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetBody(map[string]string{
			"path": path,
		}).
		SetAuthToken(token).
		SetHeader("Dropbox-API-Path-Root", pathRootHeader).
		SetResult(&res).
		Post("https://api.dropboxapi.com/2/files/get_temporary_link"); err != nil {
		return res, fmt.Errorf("could not get dropbox temporary link: %w", err)
	}

	return res, nil
}

func (c DropboxClient) uploadFileTeam(
	ctx context.Context,
	path, token, mode string,
	file io.Reader,
	userRes response.DropboxUserResponse,
) (response.DropboxFileResponse, error) {
	var res response.DropboxFileResponse

	if userRes.RootInfo == nil || userRes.RootInfo.RootNamespaceID == "" {
		return res, ErrInvalidResponsePayload
	}

	pathRootHeader, err := c.buildTeamHeader(userRes.RootInfo.RootNamespaceID)
	if err != nil {
		return res, err
	}

	req, err := http.NewRequest("POST", "https://content.dropboxapi.com/2/files/upload", file)
	if err != nil {
		return res, fmt.Errorf("could not build a request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Dropbox-API-Arg", fmt.Sprintf("{\"autorename\":true,\"mode\":\"%s\",\"mute\":false,\"path\":\"%s\",\"strict_conflict\":false}", mode, path))
	req.Header.Set("Dropbox-API-Path-Root", pathRootHeader)
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

func (c DropboxClient) uploadFileStandard(
	ctx context.Context,
	path, token, mode string,
	file io.Reader,
) (response.DropboxFileResponse, error) {
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

func (c DropboxClient) uploadFile(
	ctx context.Context,
	path, token, mode string,
	file io.Reader,
) (response.DropboxFileResponse, error) {
	userRes, err := c.getUser(ctx, token)
	if err != nil {
		return c.uploadFileStandard(ctx, path, token, mode, file)
	}

	if c.isTeamAccount(userRes) {
		if result, err := c.uploadFileTeam(ctx, path, token, mode, file, userRes); err == nil {
			return result, nil
		}
	}

	return c.uploadFileStandard(ctx, path, token, mode, file)
}

func (c DropboxClient) executeStandard(
	ctx context.Context,
	path, token string,
	opType OperationType,
) (any, error) {
	switch opType {
	case GetFile:
		var res response.DropboxFileResponse
		cacheKey := fmt.Sprintf("file:%s", path)
		return c.getFileStandard(ctx, path, token, res, cacheKey)
	case GetFileVersions:
		var res response.DropboxFileVersionsResponse
		cacheKey := fmt.Sprintf("history:%s", path)
		return c.getFileVersionsStandard(ctx, path, token, res, cacheKey)
	case GetDownloadLink:
		var res response.DropboxDownloadResponse
		cacheKey := fmt.Sprintf("downloadLink:%s", path)
		return c.getDownloadLinkStandard(ctx, path, token, res, cacheKey)
	default:
		return nil, fmt.Errorf("unknown operation type: %d", opType)
	}
}

func (c DropboxClient) executeTeam(
	ctx context.Context,
	path, token string,
	userRes response.DropboxUserResponse,
	opType OperationType,
) (any, error) {
	switch opType {
	case GetFile:
		return c.getFileTeam(ctx, path, token, userRes)
	case GetFileVersions:
		return c.getFileVersionsTeam(ctx, path, token, userRes)
	case GetDownloadLink:
		return c.getDownloadLinkTeam(ctx, path, token, userRes)
	default:
		return nil, fmt.Errorf("unknown operation type: %d", opType)
	}
}

func (c DropboxClient) executeOperation(
	ctx context.Context,
	path, token string,
	opType OperationType,
) (any, error) {
	userRes, err := c.getUser(ctx, token)
	if err != nil {
		return c.executeStandard(ctx, path, token, opType)
	}

	if c.isTeamAccount(userRes) {
		if result, err := c.executeTeam(ctx, path, token, userRes, opType); err == nil {
			return result, nil
		}
	}

	return c.executeStandard(ctx, path, token, opType)
}

func (c DropboxClient) GetUser(ctx context.Context, token string) (response.DropboxUserResponse, error) {
	return c.getUser(ctx, token)
}

func (c DropboxClient) GetFile(ctx context.Context, path, token string) (response.DropboxFileResponse, error) {
	cacheKey := fmt.Sprintf("file:%s", path)

	var res response.DropboxFileResponse
	if val, _, err := c.cache.Get(ctx, cacheKey); err == nil {
		if merr := mapstructure.Decode(val, &res); merr == nil {
			return res, nil
		}
	}

	result, err := c.executeOperation(ctx, path, token, GetFile)
	if err != nil {
		return res, err
	}

	if fileRes, ok := result.(response.DropboxFileResponse); ok {
		if fileRes.ID != "" {
			c.cache.Put(ctx, cacheKey, fileRes, 10*time.Second)
		}
		return fileRes, nil
	}

	return res, fmt.Errorf("unexpected result type from GetFile operation")
}

func (c DropboxClient) GetFileVersions(ctx context.Context, path, token string) (response.DropboxFileVersionsResponse, error) {
	cacheKey := fmt.Sprintf("history:%s", path)

	var res response.DropboxFileVersionsResponse
	if val, _, err := c.cache.Get(ctx, cacheKey); err == nil {
		if merr := mapstructure.Decode(val, &res); merr == nil {
			return res, nil
		}
	}

	result, err := c.executeOperation(ctx, path, token, GetFileVersions)
	if err != nil {
		return res, err
	}

	if versionsRes, ok := result.(response.DropboxFileVersionsResponse); ok {
		if len(versionsRes.Entries) > 0 {
			c.cache.Put(ctx, cacheKey, versionsRes, 10*time.Second)
		}
		versionsRes.ExcludeStale()
		versionsRes.SortEntries()
		return versionsRes, nil
	}

	return res, fmt.Errorf("unexpected result type from GetFileVersions operation")
}

func (c DropboxClient) GetDownloadLink(ctx context.Context, path, token string) (response.DropboxDownloadResponse, error) {
	cacheKey := fmt.Sprintf("downloadLink:%s", path)

	var res response.DropboxDownloadResponse
	if val, _, err := c.cache.Get(ctx, cacheKey); err == nil {
		if merr := mapstructure.Decode(val, &res); merr == nil {
			return res, nil
		}
	}

	result, err := c.executeOperation(ctx, path, token, GetDownloadLink)
	if err != nil {
		return res, err
	}

	if linkRes, ok := result.(response.DropboxDownloadResponse); ok {
		if linkRes.Link != "" {
			c.cache.Put(ctx, cacheKey, linkRes, 10*time.Second)
		}
		return linkRes, nil
	}

	return res, fmt.Errorf("unexpected result type from GetDownloadLink operation")
}

func (c DropboxClient) CreateFile(ctx context.Context, path, token string, file io.Reader) (response.DropboxFileResponse, error) {
	return c.uploadFile(ctx, path, token, "add", file)
}

func (c DropboxClient) UploadFile(ctx context.Context, path, token string, file io.Reader) (response.DropboxFileResponse, error) {
	return c.uploadFile(ctx, path, token, "overwrite", file)
}

func (c DropboxClient) SaveFileFromURL(ctx context.Context, path, url, token string) error {
	if _, err := c.client.R().
		SetHeader("Content-Type", "application/json").
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
