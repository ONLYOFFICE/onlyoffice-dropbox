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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared"
	aclient "github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/client"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/shared/format"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/sethvargo/go-limiter"
	"github.com/sethvargo/go-limiter/memorystore"
)

const (
	serverVersion   = "1.0.0"
	toolTimeout     = 20 * time.Second
	proxyTimeout    = 90 * time.Second
	upstreamTimeout = proxyTimeout - 5*time.Second

	OpenToolName = "open_in_onlyoffice"

	toolCallBurst    = 20
	toolCallInterval = 2 * time.Second

	serverInstructions = "The user's Dropbox, connected through ONLYOFFICE. All Dropbox tools are available " +
		"(search, list, read, organize, share). To open a Dropbox file for viewing or editing, call " + OpenToolName +
		" with its id or path: the file is edited in place in ONLYOFFICE and every change is saved back to Dropbox automatically. " +
		"Never download a Dropbox file to edit a local copy - those changes never reach Dropbox."
)

var fileIDPattern = regexp.MustCompile(`^id:[A-Za-z0-9_-]+$`)

type Handler struct {
	users         UserStore
	api           aclient.DropboxClient
	formatManager format.FormatManager
	onlyoffice    *shared.OnlyofficeConfig
	logger        log.Logger
	upstream      *upstream
	limiter       limiter.Store
	tools         []Tool
}

func (h Handler) ownTool(name string) (Tool, bool) {
	for _, t := range h.tools {
		if t.Name == name {
			return t, true
		}
	}

	return Tool{}, false
}

type fileEntry struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Size     int64  `json:"size,omitempty"`
	Modified string `json:"modified,omitempty"`
	Editable bool   `json:"editable"`
}

func decodeArgs(args json.RawMessage, target any) error {
	if err := json.Unmarshal(args, target); err != nil {
		return newToolError("Invalid arguments: " + err.Error())
	}

	return nil
}

func fileRef(value, name string) (string, error) {
	value = strings.TrimSpace(value)
	switch {
	case value == "":
		return "", newToolError(fmt.Sprintf("'%s' is required: pass a file id ('id:...') or a full path starting with '/'.", name))
	case strings.HasPrefix(value, "id:"), strings.HasPrefix(value, "/"):
		return value, nil
	default:
		return "", newToolError(fmt.Sprintf(
			"'%s' must be a file id ('id:...') or a full path starting with '/', got %q. Find the file with the Dropbox search tool first.",
			name, value,
		))
	}
}

func dropboxError(err error, ref string) error {
	var apiErr *aclient.DropboxAPIError
	if !errors.As(err, &apiErr) {
		return err
	}

	switch {
	case strings.Contains(apiErr.Summary, "not_found"):
		return newToolError(fmt.Sprintf("Nothing was found in Dropbox at %q. Check the id or path, or find the file with the Dropbox search tool.", ref))
	case strings.Contains(apiErr.Summary, "malformed_path"):
		return newToolError(fmt.Sprintf("%q is not a valid Dropbox path.", ref))
	case apiErr.Status == http.StatusUnauthorized:
		return newToolError("Dropbox rejected ONLYOFFICE's access. The user may have disconnected the app in Dropbox; ask them to sign in again.")
	case apiErr.Status == http.StatusTooManyRequests:
		return newToolError("Dropbox is rate limiting requests. Wait a little and try again.")
	default:
		return err
	}
}

func (h Handler) gatewayURL() string {
	return strings.TrimSuffix(h.onlyoffice.Onlyoffice.Builder.GatewayURL, "/")
}

func (h Handler) openURL(fileID string) (string, string) {
	query := "file_id=" + url.QueryEscape(fileID)
	if fileIDPattern.MatchString(fileID) {
		query = "file_id=" + fileID
	}

	webURL := h.gatewayURL() + "/convert?" + query
	return webURL, "oo-office:" + webURL
}

func (h Handler) reconnectHint() string {
	return "Ask the user to open " + h.gatewayURL() + "/mcp/key, sign in to Dropbox and replace the MCP server configuration with the one it shows."
}

func (h Handler) accessToken(ctx context.Context, uid string) (string, error) {
	if token := accessTokenFrom(ctx); token != "" {
		return token, nil
	}

	ures, err := h.users.GetUser(ctx, uid)
	if err != nil || ures.AccessToken == "" {
		h.logger.Debugf("could not get mcp user %s access info: %v", uid, err)
		return "", newToolError("ONLYOFFICE is no longer authorized to access this Dropbox account. " + h.reconnectHint())
	}

	return ures.AccessToken, nil
}

func (h Handler) listTools(ctx context.Context, uid string) []any {
	tools := make([]any, 0, len(h.tools)+16)
	for _, t := range h.tools {
		tools = append(tools, t)
	}

	var upstreamTools []json.RawMessage
	if authUnavailable(ctx) {
		upstreamTools = h.upstream.CachedTools()
	} else if token, err := h.accessToken(ctx, uid); err != nil {
		h.logger.Warnf("could not list dropbox mcp tools for user %s: %s", uid, err.Error())
		upstreamTools = h.upstream.CachedTools()
	} else {
		var err error
		upstreamTools, err = h.upstream.ListTools(ctx, token)
		if err != nil {
			h.logger.Warnf("could not refresh dropbox mcp tools for user %s, serving %d cached: %s",
				uid, len(upstreamTools), err.Error())
		}
	}

	for _, raw := range upstreamTools {
		var tool struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(raw, &tool) != nil || tool.Name == "" {
			continue
		}

		if _, own := h.ownTool(tool.Name); own {
			continue
		}

		tools = append(tools, raw)
	}

	h.logger.Debugf("mcp tools/list for user %s: %d own and %d dropbox tools", uid, len(h.tools), len(tools)-len(h.tools))
	return tools
}

func waitHint(d time.Duration) string {
	if d <= 0 {
		return "Wait a little"
	}

	return fmt.Sprintf("Wait %d seconds", int((d+time.Second-1)/time.Second))
}

func (h Handler) allowToolCall(ctx context.Context, uid string) (bool, time.Duration) {
	_, _, reset, ok, err := h.limiter.Take(ctx, uid)
	if err != nil {
		h.logger.Warnf("mcp tool call limiter failed for user %s: %s", uid, err.Error())
		return true, 0
	}

	if ok {
		return true, 0
	}

	return false, time.Until(time.Unix(0, int64(reset)))
}

func (h Handler) proxyCall(ctx context.Context, uid, name string, args json.RawMessage) (json.RawMessage, error) {
	token, err := h.accessToken(ctx, uid)
	if err != nil {
		return nil, err
	}

	result, err := h.upstream.CallTool(ctx, token, name, args)

	var limited *UpstreamRateLimitedError
	switch {
	case errors.Is(err, ErrUpstreamUnauthorized):
		return nil, newToolError("Dropbox rejected ONLYOFFICE's access for this tool. " + h.reconnectHint())
	case errors.As(err, &limited):
		return nil, newToolError("Dropbox is rate limiting requests for this account. " + waitHint(limited.RetryAfter) +
			" before calling Dropbox tools again; do not retry immediately.")
	case errors.Is(err, ErrUpstreamUnavailable):
		h.logger.Warnf("dropbox mcp unavailable for tool %s: %s", name, err.Error())
		return nil, newToolError("Dropbox is unavailable right now. Try again later.")
	}

	return result, err
}

func (h Handler) openDesktop(ctx context.Context, uid string, args json.RawMessage) (any, error) {
	var in struct {
		File string `json:"file"`
	}

	if err := decodeArgs(args, &in); err != nil {
		return nil, err
	}

	ref, err := fileRef(in.File, "file")
	if err != nil {
		return nil, err
	}

	token, err := h.accessToken(ctx, uid)
	if err != nil {
		return nil, err
	}

	meta, err := h.api.GetMetadata(ctx, ref, token)
	if err != nil {
		return nil, dropboxError(err, ref)
	}

	if meta.Tag != "file" {
		return nil, newToolError(fmt.Sprintf("%q is a folder. List it with the Dropbox tools, then open one of its files.", meta.PathDisplay))
	}

	format, ok := h.formatManager.GetFormatByName(strings.ToLower(h.formatManager.GetFileExt(meta.Name)))
	if !ok {
		return nil, newToolError(fmt.Sprintf("ONLYOFFICE cannot open %q: its format is not supported.", meta.Name))
	}

	webURL, desktopURL := h.openURL(meta.ID)

	return map[string]any{
		"file": fileEntry{
			ID:       meta.ID,
			Name:     meta.Name,
			Path:     meta.PathDisplay,
			Size:     meta.Size,
			Modified: meta.SModified,
			Editable: format.IsEditable(),
		},
		"web_url":     webURL,
		"desktop_url": desktopURL,
		"open_commands": map[string]string{
			"macos":   fmt.Sprintf("open '%s'", desktopURL),
			"windows": fmt.Sprintf("Start-Process '%s'", desktopURL),
			"linux":   fmt.Sprintf("xdg-open '%s'", desktopURL),
		},
		"note": "Changes made in the opened editor are saved to Dropbox automatically. " +
			"The user must be signed in to Dropbox in ONLYOFFICE Desktop (Connect to cloud -> Dropbox) for desktop_url to open the editor.",
	}, nil
}

func (h Handler) buildTools() []Tool {
	return []Tool{
		{
			Name:  OpenToolName,
			Title: "Open a Dropbox file in ONLYOFFICE",
			Description: "Opens a Dropbox file in the ONLYOFFICE editor so the user edits the Dropbox file itself; " +
				"every change is saved back to Dropbox automatically. Use it whenever the user wants to open, view or edit a Dropbox file " +
				"(documents, spreadsheets, presentations, PDFs). Find the file first with the Dropbox search or list tools and pass its id. " +
				"Returns 'desktop_url' (opens the file in ONLYOFFICE Desktop), 'web_url' (opens it in a browser) and 'open_commands' " +
				"with a ready-made command per operating system. If you can run commands on the user's computer, run the one for their " +
				"system to open the file in ONLYOFFICE Desktop; otherwise give the user the links. " +
				"Never download the file and open a local copy instead: edits to a local copy never reach Dropbox. " +
				"This tool does not return the file's content.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"file": map[string]any{
						"type":        "string",
						"description": "Dropbox file id ('id:...', preferred) or full path starting with '/'.",
					},
				},
				"required": []string{"file"},
			},
			Annotations: map[string]any{
				"readOnlyHint":    true,
				"destructiveHint": false,
				"openWorldHint":   false,
			},
			call: h.openDesktop,
		},
	}
}

func NewHandler(
	users UserStore,
	api aclient.DropboxClient,
	formatManager format.FormatManager,
	onlyoffice *shared.OnlyofficeConfig,
	logger log.Logger,
) (Handler, error) {
	store, err := memorystore.New(&memorystore.Config{
		Tokens:   toolCallBurst,
		Interval: toolCallInterval,
	})
	if err != nil {
		return Handler{}, fmt.Errorf("could not create the mcp tool call limiter: %w", err)
	}

	h := Handler{
		users:         users,
		api:           api,
		formatManager: formatManager,
		onlyoffice:    onlyoffice,
		logger:        logger,
		upstream: newUpstream(DropboxMCPURL, &http.Client{
			Timeout:   upstreamTimeout,
			Transport: newUpstreamTransport(),
		}),
		limiter: store,
	}

	h.tools = h.buildTools()
	return h, nil
}
