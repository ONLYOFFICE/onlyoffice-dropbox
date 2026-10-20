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

package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	DropboxMCPURL = "https://mcp.dropbox.com/mcp"

	upstreamProtocolVersion = "2025-06-18"
	upstreamMaxResponse     = 16 * 1024 * 1024
	upstreamToolsTTL        = 5 * time.Minute
	upstreamSessionIdle     = 30 * time.Minute
	upstreamMaxToolPages    = 10
)

var (
	ErrUpstreamUnauthorized = errors.New("dropbox mcp rejected the access token")
	errUpstreamSessionGone  = errors.New("dropbox mcp session expired")
)

type UpstreamRPCError struct {
	Code    int
	Message string
}

func (e *UpstreamRPCError) Error() string {
	return fmt.Sprintf("dropbox mcp error %d: %s", e.Code, e.Message)
}

type upstreamSession struct {
	id       string
	tools    []json.RawMessage
	toolsAt  time.Time
	lastUsed time.Time
}

type upstream struct {
	url      string
	client   *http.Client
	lock     sync.Mutex
	sessions map[string]*upstreamSession
	now      func() time.Time
}

func newUpstream(url string, client *http.Client) *upstream {
	return &upstream{
		url:      url,
		client:   client,
		sessions: make(map[string]*upstreamSession),
		now:      time.Now,
	}
}

func tokenKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (u *upstream) forget(token string) {
	u.lock.Lock()
	delete(u.sessions, tokenKey(token))
	u.lock.Unlock()
}

func readUpstreamResponse(resp *http.Response) ([]byte, error) {
	body := io.LimitReader(resp.Body, upstreamMaxResponse)
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mediaType != "text/event-stream" {
		return io.ReadAll(body)
	}

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), upstreamMaxResponse)

	var data strings.Builder
	flush := func() []byte {
		defer data.Reset()

		event := []byte(data.String())
		var probe struct {
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}

		if json.Unmarshal(event, &probe) == nil && (probe.Result != nil || probe.Error != nil) {
			return event
		}

		return nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		case line == "":
			if event := flush(); event != nil {
				return event, nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if event := flush(); event != nil {
		return event, nil
	}

	return nil, errors.New("no response event in stream")
}

func (u *upstream) send(
	ctx context.Context,
	token, sessionID, method string,
	params any,
) (json.RawMessage, string, error) {
	notification := strings.HasPrefix(method, "notifications/")
	msg := map[string]any{"jsonrpc": jsonRPCVersion, "method": method}
	if params != nil {
		msg["params"] = params
	}

	if !notification {
		msg["id"] = 1
	}

	body, err := json.Marshal(msg)
	if err != nil {
		return nil, "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url, bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
		req.Header.Set("MCP-Protocol-Version", upstreamProtocolVersion)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("could not reach dropbox mcp: %w", err)
	}

	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, "", ErrUpstreamUnauthorized
	case resp.StatusCode == http.StatusNotFound && sessionID != "":
		return nil, "", errUpstreamSessionGone
	case resp.StatusCode >= 300:
		return nil, "", fmt.Errorf("dropbox mcp %s failed with status %d", method, resp.StatusCode)
	}

	newSessionID := resp.Header.Get("Mcp-Session-Id")
	if newSessionID == "" {
		newSessionID = sessionID
	}

	if notification {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, upstreamMaxResponse))
		return nil, newSessionID, nil
	}

	payload, err := readUpstreamResponse(resp)
	if err != nil {
		return nil, "", fmt.Errorf("could not read dropbox mcp %s response: %w", method, err)
	}

	var res struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}

	if err := json.Unmarshal(payload, &res); err != nil {
		return nil, "", fmt.Errorf("could not decode dropbox mcp %s response: %w", method, err)
	}

	if res.Error != nil {
		return nil, "", &UpstreamRPCError{Code: res.Error.Code, Message: res.Error.Message}
	}

	return res.Result, newSessionID, nil
}

func (u *upstream) initialize(ctx context.Context, token string) (string, error) {
	_, sessionID, err := u.send(ctx, token, "", "initialize", map[string]any{
		"protocolVersion": upstreamProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "onlyoffice-dropbox",
			"version": serverVersion,
		},
	})

	if err != nil {
		return "", err
	}

	if _, _, err := u.send(ctx, token, sessionID, "notifications/initialized", nil); err != nil {
		return "", err
	}

	return sessionID, nil
}

func (u *upstream) session(ctx context.Context, token string) (*upstreamSession, error) {
	u.lock.Lock()
	now := u.now()

	for k, s := range u.sessions {
		if now.Sub(s.lastUsed) > upstreamSessionIdle {
			delete(u.sessions, k)
		}
	}

	key := tokenKey(token)

	if s, ok := u.sessions[key]; ok {
		s.lastUsed = now
		u.lock.Unlock()
		return s, nil
	}

	u.lock.Unlock()

	id, err := u.initialize(ctx, token)
	if err != nil {
		return nil, err
	}

	s := &upstreamSession{id: id, lastUsed: now}

	u.lock.Lock()
	u.sessions[key] = s
	u.lock.Unlock()

	return s, nil
}

func (u *upstream) call(ctx context.Context, token, method string, params any) (json.RawMessage, error) {
	for attempt := 0; ; attempt++ {
		s, err := u.session(ctx, token)
		if err != nil {
			return nil, err
		}

		result, _, err := u.send(ctx, token, s.id, method, params)
		if errors.Is(err, errUpstreamSessionGone) && attempt == 0 {
			u.forget(token)
			continue
		}

		if errors.Is(err, ErrUpstreamUnauthorized) {
			u.forget(token)
		}

		return result, err
	}
}

func (u *upstream) ListTools(ctx context.Context, token string) ([]json.RawMessage, error) {
	s, err := u.session(ctx, token)
	if err != nil {
		return nil, err
	}

	u.lock.Lock()
	if s.tools != nil && u.now().Sub(s.toolsAt) < upstreamToolsTTL {
		tools := s.tools
		u.lock.Unlock()
		return tools, nil
	}

	u.lock.Unlock()

	var tools []json.RawMessage
	cursor := ""

	for page := 0; page < upstreamMaxToolPages; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}

		raw, err := u.call(ctx, token, "tools/list", params)
		if err != nil {
			return nil, err
		}

		var res struct {
			Tools      []json.RawMessage `json:"tools"`
			NextCursor string            `json:"nextCursor"`
		}

		if err := json.Unmarshal(raw, &res); err != nil {
			return nil, fmt.Errorf("could not decode dropbox mcp tools: %w", err)
		}

		tools = append(tools, res.Tools...)
		if cursor = res.NextCursor; cursor == "" {
			break
		}
	}

	u.lock.Lock()
	s.tools, s.toolsAt = tools, u.now()
	u.lock.Unlock()

	return tools, nil
}

func (u *upstream) CallTool(ctx context.Context, token, name string, arguments json.RawMessage) (json.RawMessage, error) {
	return u.call(ctx, token, "tools/call", map[string]any{
		"name":      name,
		"arguments": arguments,
	})
}
