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

package response

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type FileHistoryResponse struct {
	CurrentVersion int                `json:"currentVersion"`
	History        []FileHistoryEntry `json:"history"`
}

type FileHistoryUser struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Image string `json:"image"`
}

type FileHistoryEntry struct {
	Created string          `json:"created"`
	Key     string          `json:"key"`
	Version int             `json:"version"`
	User    FileHistoryUser `json:"user"`
}

func (r FileHistoryResponse) ToJSON() []byte {
	buf, _ := json.Marshal(r)
	return buf
}

func (r FileHistoryResponse) Sort() {
	sort.Slice(r.History, func(i, j int) bool {
		timeI, errI := time.Parse(time.RFC3339, r.History[i].Created)
		timeJ, errJ := time.Parse(time.RFC3339, r.History[j].Created)
		if errI != nil || errJ != nil {
			return i < j
		}
		return timeI.Before(timeJ)
	})
}

type FileHistoryData struct {
	jwt.RegisteredClaims `json:"-"`
	Key                  string `json:"key"`
	URL                  string `json:"url"`
	Version              int    `json:"version"`
	Token                string `json:"token,omitempty"`
}

func (r FileHistoryData) ToJSON() []byte {
	buf, _ := json.Marshal(r)
	return buf
}
