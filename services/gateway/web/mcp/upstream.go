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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/afex/hystrix-go/hystrix"
	"golang.org/x/sync/singleflight"
)

const (
	DropboxMCPURL = "https://mcp.dropbox.com/mcp"

	upstreamProtocolVersion = "2025-06-18"
	upstreamMaxResponse     = 8 * 1024 * 1024
	upstreamToolsTTL        = 5 * time.Minute
	upstreamSessionIdle     = 10 * time.Minute
	upstreamSweepInterval   = time.Minute
	upstreamCloseTimeout    = 5 * time.Second
	upstreamRetryJitter     = 200 * time.Millisecond
	upstreamMaxToolPages    = 10

	CircuitName          = "dropbox-mcp"
	circuitMaxConcurrent = 64
	circuitVolume        = 20
	circuitErrorPercent  = 50
	circuitSleepWindow   = 15 * time.Second
)

var (
	ErrUpstreamUnauthorized = errors.New("dropbox mcp rejected the access token")
	ErrUpstreamUnavailable  = errors.New("dropbox is unavailable")
	errUpstreamSessionGone  = errors.New("dropbox mcp session expired")
)

type UpstreamRateLimitedError struct {
	RetryAfter time.Duration
}

func (e *UpstreamRateLimitedError) Error() string {
	return fmt.Sprintf("dropbox mcp rate limited the request, retry after %s", e.RetryAfter)
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}

	if seconds, err := strconv.Atoi(value); err == nil {
		return max(time.Duration(seconds)*time.Second, 0)
	}

	if at, err := http.ParseTime(value); err == nil {
		return max(at.Sub(now), 0)
	}

	return 0
}

func isUpstreamOutage(err error) bool {
	var rpcErr *UpstreamRPCError
	var limited *UpstreamRateLimitedError
	switch {
	case err == nil,
		errors.As(err, &rpcErr),
		errors.As(err, &limited),
		errors.Is(err, ErrUpstreamUnauthorized),
		errors.Is(err, errUpstreamSessionGone),
		errors.Is(err, context.Canceled):
		return false
	default:
		return true
	}
}

type UpstreamRPCError struct {
	Code    int
	Message string
}

func (e *UpstreamRPCError) Error() string {
	return fmt.Sprintf("dropbox mcp error %d: %s", e.Code, e.Message)
}

type upstreamSession struct {
	id       string
	token    string
	lastUsed time.Time
}

type upstream struct {
	url       string
	client    *http.Client
	lock      sync.Mutex
	sessions  map[string]*upstreamSession
	starting  singleflight.Group
	now       func() time.Time
	catalog   []json.RawMessage
	catalogAt time.Time
}

func newUpstreamTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

func newUpstream(url string, client *http.Client) *upstream {
	hystrix.ConfigureCommand(CircuitName, hystrix.CommandConfig{
		Timeout:                int(client.Timeout / time.Millisecond),
		MaxConcurrentRequests:  circuitMaxConcurrent,
		RequestVolumeThreshold: circuitVolume,
		ErrorPercentThreshold:  circuitErrorPercent,
		SleepWindow:            int(circuitSleepWindow / time.Millisecond),
	})

	u := &upstream{
		url:      url,
		client:   client,
		sessions: make(map[string]*upstreamSession),
		now:      time.Now,
	}

	go u.sweep(upstreamSweepInterval)

	return u
}

func (u *upstream) closeSession(s *upstreamSession) {
	ctx, cancel := context.WithTimeout(context.Background(), upstreamCloseTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.url, nil)
	if err != nil {
		return
	}

	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Mcp-Session-Id", s.id)
	req.Header.Set("MCP-Protocol-Version", upstreamProtocolVersion)

	if resp, err := u.client.Do(req); err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
	}
}

func (u *upstream) forget(uid string, closeUpstream bool) {
	u.lock.Lock()
	s, ok := u.sessions[uid]

	delete(u.sessions, uid)

	u.lock.Unlock()

	if ok && closeUpstream {
		go u.closeSession(s)
	}
}

func (u *upstream) sweep(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		u.lock.Lock()
		now := u.now()
		var idle []*upstreamSession
		for k, s := range u.sessions {
			if now.Sub(s.lastUsed) > upstreamSessionIdle {
				idle = append(idle, s)
				delete(u.sessions, k)
			}
		}

		u.lock.Unlock()

		for _, s := range idle {
			u.closeSession(s)
		}
	}
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
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, "", &UpstreamRateLimitedError{RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())}
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

func isRetryable(method string) bool {
	return method == "initialize" || method == "tools/list" || strings.HasPrefix(method, "notifications/")
}

func (u *upstream) sendWithRetry(
	ctx context.Context,
	token, sessionID, method string,
	params any,
) (json.RawMessage, string, error) {
	result, newSessionID, err := u.send(ctx, token, sessionID, method, params)
	if !isRetryable(method) || !isUpstreamOutage(err) || ctx.Err() != nil {
		return result, newSessionID, err
	}

	wait := upstreamRetryJitter/2 + rand.N(upstreamRetryJitter)
	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return nil, "", err
	case <-timer.C:
	}

	return u.send(ctx, token, sessionID, method, params)
}

func (u *upstream) initialize(ctx context.Context, token string) (string, error) {
	_, sessionID, err := u.sendWithRetry(ctx, token, "", "initialize", map[string]any{
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

	if _, _, err := u.sendWithRetry(ctx, token, sessionID, "notifications/initialized", nil); err != nil {
		return "", err
	}

	return sessionID, nil
}

func (u *upstream) session(ctx context.Context, uid, token string) (*upstreamSession, error) {
	current := func() *upstreamSession {
		u.lock.Lock()
		s, ok := u.sessions[uid]
		switch {
		case !ok:
			u.lock.Unlock()
			return nil
		case s.token != token:
			delete(u.sessions, uid)
			u.lock.Unlock()
			go u.closeSession(s)
			return nil
		}

		s.lastUsed = u.now()
		u.lock.Unlock()
		return s
	}

	if s := current(); s != nil {
		return s, nil
	}

	started, err, _ := u.starting.Do(uid+"\x00"+token, func() (any, error) {
		if s := current(); s != nil {
			return s, nil
		}

		id, err := u.initialize(context.WithoutCancel(ctx), token)
		if err != nil {
			return nil, err
		}

		s := &upstreamSession{id: id, token: token, lastUsed: u.now()}

		u.lock.Lock()
		previous, replaced := u.sessions[uid]
		u.sessions[uid] = s
		u.lock.Unlock()

		if replaced && previous.id != s.id {
			go u.closeSession(previous)
		}

		return s, nil
	})

	if err != nil {
		return nil, err
	}

	return started.(*upstreamSession), nil
}

func (u *upstream) callInSession(ctx context.Context, uid, token, method string, params any) (json.RawMessage, error) {
	for attempt := 0; ; attempt++ {
		s, err := u.session(ctx, uid, token)
		if err != nil {
			return nil, err
		}

		result, _, err := u.sendWithRetry(ctx, token, s.id, method, params)
		if errors.Is(err, errUpstreamSessionGone) && attempt == 0 {
			u.forget(uid, false)
			continue
		}

		if errors.Is(err, ErrUpstreamUnauthorized) {
			u.forget(uid, false)
		}

		return result, err
	}
}

func recovering(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("dropbox mcp call panicked: %v", r)
		}
	}()

	return fn(ctx)
}

func guarded(
	ctx context.Context,
	command string,
	isOutage func(error) bool,
	fn func(ctx context.Context) error,
) error {
	var outcome error
	err := hystrix.DoC(ctx, command, func(ctx context.Context) error {
		outcome = recovering(ctx, fn)
		if isOutage(outcome) {
			return outcome
		}

		return nil
	}, nil)

	switch {
	case errors.Is(err, hystrix.ErrCircuitOpen),
		errors.Is(err, hystrix.ErrMaxConcurrency),
		errors.Is(err, hystrix.ErrTimeout),
		errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%w: %s", ErrUpstreamUnavailable, err.Error())
	case err != nil:
		return err
	}

	return outcome
}

func (u *upstream) guard(ctx context.Context, fn func(ctx context.Context) error) error {
	return guarded(ctx, CircuitName, isUpstreamOutage, fn)
}

func (u *upstream) call(ctx context.Context, uid, token, method string, params any) (json.RawMessage, error) {
	var result json.RawMessage
	if err := u.guard(ctx, func(ctx context.Context) error {
		var err error
		result, err = u.callInSession(ctx, uid, token, method, params)
		return err
	}); err != nil {
		return nil, err
	}

	return result, nil
}

func (u *upstream) CachedTools() []json.RawMessage {
	u.lock.Lock()
	defer u.lock.Unlock()
	return u.catalog
}

func (u *upstream) fetchTools(ctx context.Context, uid, token string) ([]json.RawMessage, error) {
	if err := u.guard(ctx, func(ctx context.Context) error {
		_, err := u.session(ctx, uid, token)
		return err
	}); err != nil {
		return nil, err
	}

	var tools []json.RawMessage
	cursor := ""

	for page := 0; page < upstreamMaxToolPages; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}

		raw, err := u.call(ctx, uid, token, "tools/list", params)
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

	return tools, nil
}

func (u *upstream) ListTools(ctx context.Context, uid, token string) ([]json.RawMessage, error) {
	u.lock.Lock()
	if u.catalog != nil && u.now().Sub(u.catalogAt) < upstreamToolsTTL {
		tools := u.catalog
		u.lock.Unlock()
		return tools, nil
	}

	u.lock.Unlock()

	tools, err := u.fetchTools(ctx, uid, token)
	if err != nil {
		return u.CachedTools(), err
	}

	u.lock.Lock()
	u.catalog, u.catalogAt = tools, u.now()
	u.lock.Unlock()

	return tools, nil
}

func (u *upstream) CallTool(ctx context.Context, uid, token, name string, arguments json.RawMessage) (json.RawMessage, error) {
	return u.call(ctx, uid, token, "tools/call", map[string]any{
		"name":      name,
		"arguments": arguments,
	})
}
