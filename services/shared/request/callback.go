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

package request

import (
	"encoding/json"
	"fmt"
	"strings"
)

type MissingRequestFieldsError struct {
	Request string
	Field   string
	Reason  string
}

func (e *MissingRequestFieldsError) Error() string {
	return fmt.Sprintf("missing %s's field %s. Reason: %s", e.Request, e.Field, e.Reason)
}

type CallbackRequest struct {
	Actions []struct {
		Type   int    `json:"type"`
		UserID string `json:"userid"`
	} `json:"actions"`
	Key    string   `json:"key"`
	Status int      `json:"status"`
	Users  []string `json:"users"`
	URL    string   `json:"url"`
	Token  string   `json:"token"`
}

func (cr CallbackRequest) ToJSON() []byte {
	buf, _ := json.Marshal(cr)
	return buf
}

func (c *CallbackRequest) Validate() error {
	c.Key = strings.TrimSpace(c.Key)
	c.Token = strings.TrimSpace(c.Token)

	if c.Key == "" {
		return &MissingRequestFieldsError{
			Request: "Callback",
			Field:   "Key",
			Reason:  "Should not be empty",
		}
	}

	if c.Token == "" {
		return &MissingRequestFieldsError{
			Request: "Callback",
			Field:   "Token",
			Reason:  "Should not be empty",
		}
	}

	if c.Status <= 0 || c.Status > 7 {
		return &MissingRequestFieldsError{
			Request: "Callback",
			Field:   "Status",
			Reason:  "Invalid status. Exptected 0 < status <= 7",
		}
	}

	return nil
}
