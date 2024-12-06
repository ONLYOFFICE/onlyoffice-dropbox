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

package response

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
)

type ConfigResponse struct {
	jwt.RegisteredClaims
	Document     Document     `json:"document"`
	DocumentType string       `json:"documentType"`
	EditorConfig EditorConfig `json:"editorConfig"`
	Type         string       `json:"type"`
	Token        string       `json:"token,omitempty"`
	ServerURL    string       `json:"server_url"`
}

func (r ConfigResponse) ToJSON() []byte {
	buf, _ := json.Marshal(r)
	return buf
}

type Permissions struct {
	Comment                 bool `json:"comment"`
	Copy                    bool `json:"copy"`
	DeleteCommentAuthorOnly bool `json:"deleteCommentAuthorOnly"`
	Download                bool `json:"download"`
	Edit                    bool `json:"edit"`
	EditCommentAuthorOnly   bool `json:"editCommentAuthorOnly"`
	FillForms               bool `json:"fillForms"`
	ModifyContentControl    bool `json:"modifyContentControl"`
	ModifyFilter            bool `json:"modifyFilter"`
	Print                   bool `json:"print"`
	Review                  bool `json:"review"`
}

type Document struct {
	FileType    string      `json:"fileType"`
	Key         string      `json:"key"`
	Title       string      `json:"title"`
	URL         string      `json:"url"`
	Permissions Permissions `json:"permissions"`
}

type EditorConfig struct {
	User          User          `json:"user"`
	CallbackURL   string        `json:"callbackUrl"`
	Customization Customization `json:"customization"`
	Lang          string        `json:"lang,omitempty"`
}

type User struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Image string `json:"image,omitempty"`
}

type Customization struct {
	Goback        Goback `json:"goback"`
	Plugins       bool   `json:"plugins"`
	HideRightMenu bool   `json:"hideRightMenu"`
}

type Goback struct {
	RequestClose bool `json:"requestClose"`
}
