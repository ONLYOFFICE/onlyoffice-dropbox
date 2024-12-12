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
	"sort"
	"time"
)

type DropboxUserResponse struct {
	AccountID      string          `json:"account_id"`
	Email          string          `json:"email"`
	Name           DropboxUserName `json:"name"`
	Locale         string          `json:"locale"`
	ProfilePicture string          `json:"profile_photo_url,omitempty"`
}

type DropboxUserName struct {
	DisplayName  string `json:"display_name"`
	FamiliarName string `json:"familiar_name"`
	GivenName    string `json:"given_name"`
	Surname      string `json:"surname"`
}

type DropboxFileResponse struct {
	ID          string `json:"id"`
	CModified   string `json:"client_modified"`
	SModified   string `json:"server_modified"`
	PathLower   string `json:"path_lower"`
	PathDisplay string `json:"path_display"`
	Rev         string `json:"rev"`
	Name        string `json:"name"`
	Size        int    `json:"size"`
}

type DropboxFileVersionsResponse struct {
	Entries []struct {
		ClientModified string `json:"client_modified"`
		Rev            string `json:"rev"`
	} `json:"entries"`
	Deleted bool `json:"is_deleted"`
}

func (r *DropboxFileVersionsResponse) ExcludeStale() {
	cutoffDate := time.Now().AddDate(0, 0, -30)
	var filtered []struct {
		ClientModified string `json:"client_modified"`
		Rev            string `json:"rev"`
	}

	for _, entry := range r.Entries {
		parsedTime, err := time.Parse(time.RFC3339, entry.ClientModified)
		if err != nil {
			continue
		}

		if parsedTime.After(cutoffDate) {
			filtered = append(filtered, entry)
		}
	}

	r.Entries = filtered
}

func (r *DropboxFileVersionsResponse) SortEntries() {
	sort.Slice(r.Entries, func(i, j int) bool {
		timeI, errI := time.Parse(time.RFC3339, r.Entries[i].ClientModified)
		timeJ, errJ := time.Parse(time.RFC3339, r.Entries[j].ClientModified)
		if errI != nil || errJ != nil {
			return i < j
		}
		return timeI.Before(timeJ)
	})
}

type DropboxDownloadResponse struct {
	Link string `json:"link"`
}
