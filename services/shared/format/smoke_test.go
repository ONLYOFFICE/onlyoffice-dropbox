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

package format

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSmokeFormats(t *testing.T) {
	manager, err := NewMapFormatManager()
	require.NoError(t, err)
	require.NotEmpty(t, manager.GetAllFormats(), "formats submodule is empty: run git submodule update --init")

	get := func(t *testing.T, name string) Format {
		t.Helper()
		f, ok := manager.GetFormatByName(name)
		require.True(t, ok, "format %s must be supported", name)
		return f
	}

	t.Run("OOXML opens for editing", func(t *testing.T) {
		for name, kind := range map[string]string{"docx": "word", "xlsx": "cell", "pptx": "slide"} {
			f := get(t, name)
			assert.True(t, f.IsEditable(), name)
			assert.Equal(t, kind, f.Type, name)
		}
	})

	t.Run("open formats are editable only with loss and convert to OOXML", func(t *testing.T) {
		for _, name := range []string{"odt", "csv", "txt"} {
			f := get(t, name)
			assert.False(t, f.IsEditable(), name)
			assert.True(t, f.IsLossyEditable(), name)
			assert.True(t, f.IsOpenXMLConvertable(), name)
		}
	})

	t.Run("legacy binary formats are offered for conversion", func(t *testing.T) {
		f := get(t, "doc")
		assert.False(t, f.IsEditable())
		assert.True(t, f.IsAutoConvertable())
		assert.Equal(t, "docx", f.GetOpenXMLExtension())
	})

	t.Run("view-only formats go straight to the viewer", func(t *testing.T) {
		assert.True(t, get(t, "djvu").IsViewOnly())
	})

	t.Run("unknown extensions are rejected", func(t *testing.T) {
		_, ok := manager.GetFormatByName(manager.GetFileExt("setup.exe"))
		assert.False(t, ok)
	})
}
