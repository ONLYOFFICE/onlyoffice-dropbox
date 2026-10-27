package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScopeParam(t *testing.T) {
	t.Run("joins the configured scopes", func(t *testing.T) {
		assert.Equal(t, "&scope=files.content.read+files.content.write",
			scopeParam([]string{"files.content.read", " files.content.write "}))
	})

	t.Run("asks for none when none are configured", func(t *testing.T) {
		assert.Equal(t, "", scopeParam(nil))
		assert.Equal(t, "", scopeParam([]string{""}))
	})
}
