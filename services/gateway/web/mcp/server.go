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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"time"
)

const (
	jsonRPCVersion = "2.0"
	maxRequestBody = 1 * 1024 * 1024

	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

var supportedProtocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

type contextKey string

const UserIDKey contextKey = "mcp_user_id"

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (m rpcMessage) isNotification() bool {
	return len(m.ID) == 0 || string(m.ID) == "null"
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type Tool struct {
	Name        string         `json:"name"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`

	call func(ctx context.Context, uid string, args json.RawMessage) (any, error)
}

type textContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolResult struct {
	Content           []textContent `json:"content"`
	StructuredContent any           `json:"structuredContent,omitempty"`
	IsError           bool          `json:"isError"`
}

type ToolError struct {
	Message string
}

func (e *ToolError) Error() string {
	return e.Message
}

func newToolError(message string) error {
	return &ToolError{Message: message}
}

func (h Handler) initialize(params json.RawMessage) map[string]any {
	var req struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &req)

	version := supportedProtocolVersions[0]
	if slices.Contains(supportedProtocolVersions, req.ProtocolVersion) {
		version = req.ProtocolVersion
	}

	return map[string]any{
		"protocolVersion": version,
		"capabilities": map[string]any{
			"tools": map[string]any{"listChanged": false},
		},
		"serverInfo": map[string]any{
			"name":    "onlyoffice-dropbox",
			"title":   "ONLYOFFICE for Dropbox",
			"version": serverVersion,
		},
		"instructions": serverInstructions,
	}
}

func resultResponse(id json.RawMessage, result any) rpcResponse {
	return rpcResponse{JSONRPC: jsonRPCVersion, ID: id, Result: result}
}

func (h Handler) toolFailure(id json.RawMessage, uid, name string, err error) rpcResponse {
	var terr *ToolError
	if !errors.As(err, &terr) {
		h.logger.Errorf("mcp tool %s failed for user %s: %s", name, uid, err.Error())
		terr = &ToolError{Message: "The request to Dropbox failed. Try again later."}
	}

	return resultResponse(id, toolResult{
		Content: []textContent{{Type: "text", Text: terr.Message}},
		IsError: true,
	})
}

func errorResponse(id json.RawMessage, code int, message string) rpcResponse {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}

	return rpcResponse{JSONRPC: jsonRPCVersion, ID: id, Error: &rpcError{Code: code, Message: message}}
}

func (h Handler) callTool(ctx context.Context, uid string, msg rpcMessage) rpcResponse {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}

	if err := json.Unmarshal(msg.Params, &params); err != nil || params.Name == "" {
		return errorResponse(msg.ID, codeInvalidParams, "tools/call requires a tool name")
	}

	if len(params.Arguments) == 0 || string(params.Arguments) == "null" {
		params.Arguments = json.RawMessage("{}")
	}

	started := time.Now()
	tool, own := h.ownTool(params.Name)
	if !own {
		pctx, cancel := context.WithTimeout(ctx, proxyTimeout)
		defer cancel()

		result, err := h.proxyCall(pctx, uid, params.Name, params.Arguments)

		h.logger.Debugf("mcp proxied tool %s for user %s took %s, error: %v", params.Name, uid, time.Since(started), err)

		var rerr *UpstreamRPCError
		if errors.As(err, &rerr) {
			return errorResponse(msg.ID, rerr.Code, rerr.Message)
		}

		if err != nil {
			return h.toolFailure(msg.ID, uid, params.Name, err)
		}

		return resultResponse(msg.ID, result)
	}

	tctx, cancel := context.WithTimeout(ctx, toolTimeout)
	defer cancel()

	out, err := tool.call(tctx, uid, params.Arguments)

	h.logger.Debugf("mcp tool %s for user %s took %s, error: %v", params.Name, uid, time.Since(started), err)

	if err != nil {
		return h.toolFailure(msg.ID, uid, params.Name, err)
	}

	text, err := json.Marshal(out)
	if err != nil {
		return errorResponse(msg.ID, codeInternalError, "could not encode tool result")
	}

	return resultResponse(msg.ID, toolResult{
		Content:           []textContent{{Type: "text", Text: string(text)}},
		StructuredContent: out,
	})
}

func (h Handler) handleMessage(ctx context.Context, uid string, raw json.RawMessage) (rpcResponse, bool) {
	var msg rpcMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return errorResponse(nil, codeParseError, "invalid JSON"), true
	}

	if msg.JSONRPC != jsonRPCVersion || msg.Method == "" {
		if msg.isNotification() {
			return rpcResponse{}, false
		}
		return errorResponse(msg.ID, codeInvalidRequest, "invalid JSON-RPC request"), true
	}

	if msg.isNotification() {
		h.logger.Debugf("mcp notification %s from user %s", msg.Method, uid)
		return rpcResponse{}, false
	}

	h.logger.Debugf("mcp request %s (id %s) from user %s", msg.Method, string(msg.ID), uid)

	switch msg.Method {
	case "initialize":
		return resultResponse(msg.ID, h.initialize(msg.Params)), true
	case "ping":
		return resultResponse(msg.ID, struct{}{}), true
	case "tools/list":
		lctx, cancel := context.WithTimeout(ctx, toolTimeout)
		defer cancel()
		return resultResponse(msg.ID, map[string]any{"tools": h.listTools(lctx, uid)}), true
	case "tools/call":
		return h.callTool(ctx, uid, msg), true
	default:
		return errorResponse(msg.ID, codeMethodNotFound, "method not found: "+msg.Method), true
	}
}

func writeJSON(rw http.ResponseWriter, status int, body any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(body)
}

func (h Handler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		rw.Header().Set("Allow", http.MethodPost)
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	uid, _ := r.Context().Value(UserIDKey).(string)
	if uid == "" {
		http.Error(rw, "unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(rw, r.Body, maxRequestBody))
	if err != nil {
		writeJSON(rw, http.StatusBadRequest, errorResponse(nil, codeParseError, "could not read request body"))
		return
	}

	body = bytes.TrimSpace(body)
	if len(body) > 0 && body[0] == '[' {
		var batch []json.RawMessage
		if err := json.Unmarshal(body, &batch); err != nil || len(batch) == 0 {
			writeJSON(rw, http.StatusBadRequest, errorResponse(nil, codeParseError, "invalid JSON-RPC batch"))
			return
		}

		responses := make([]rpcResponse, 0, len(batch))
		for _, raw := range batch {
			if res, ok := h.handleMessage(r.Context(), uid, raw); ok {
				responses = append(responses, res)
			}
		}

		if len(responses) == 0 {
			rw.WriteHeader(http.StatusAccepted)
			return
		}

		writeJSON(rw, http.StatusOK, responses)
		return
	}

	res, ok := h.handleMessage(r.Context(), uid, body)
	if !ok {
		rw.WriteHeader(http.StatusAccepted)
		return
	}

	writeJSON(rw, http.StatusOK, res)
}
