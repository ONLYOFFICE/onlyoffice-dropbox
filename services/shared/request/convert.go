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

package request

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
)

type ConvertActionRequest struct {
	jwt.RegisteredClaims
	Action    string `json:"action"`
	FileID    string `json:"file_id"`
	Password  string `json:"password,omitempty"`
	ForceEdit bool   `json:"force_edit"`
	XmlType   string `json:"xml_type,omitempty"`
}

type ConvertRequest struct {
	jwt.RegisteredClaims
	Async      bool   `json:"async"`
	Key        string `json:"key"`
	Filetype   string `json:"filetype"`
	Outputtype string `json:"outputtype"`
	Password   string `json:"password,omitempty"`
	URL        string `json:"url"`
	Token      string `json:"token,omitempty"`
}

func (r ConvertRequest) ToJSON() []byte {
	buf, _ := json.Marshal(r)
	return buf
}
