package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/log"
	"github.com/stretchr/testify/assert"
)

func TestGetCapabilities(t *testing.T) {
	c := &DesktopController{logger: log.NewEmptyLogger()}

	t.Run("names the provider and the interface version", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/app/ai", nil)
		req.Header.Set("Origin", desktopPluginOrigin)
		rw := httptest.NewRecorder()
		c.BuildGetCapabilities()(rw, req)

		assert.Equal(t, http.StatusOK, rw.Code)
		assert.Equal(t, "application/json", rw.Header().Get("Content-Type"))
		assert.Equal(t, desktopPluginOrigin, rw.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", rw.Header().Get("Access-Control-Allow-Credentials"))

		var body map[string]any
		assert.NoError(t, json.Unmarshal(rw.Body.Bytes(), &body))
		assert.Equal(t, map[string]any{"provider": "dropbox", "version": float64(1)}, body)
	})

	t.Run("is not readable by other origins", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/app/ai", nil)
		req.Header.Set("Origin", "https://example.com")
		rw := httptest.NewRecorder()
		rw.Header().Set("Access-Control-Allow-Origin", "*")
		c.BuildGetCapabilities()(rw, req)

		assert.Empty(t, rw.Header().Get("Access-Control-Allow-Origin"))
		assert.Empty(t, rw.Header().Get("Access-Control-Allow-Credentials"))
	})
}
