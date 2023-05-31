/**
 *
 * (c) Copyright Ascensio System SIA 2023
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

type DropboxUserResponse struct {
	AccountID string          `json:"account_id"`
	Email     string          `json:"email"`
	Name      DropboxUserName `json:"name"`
	Locale    string          `json:"locale"`
}

type DropboxUserName struct {
	DisplayName  string `json:"display_name"`
	FamiliarName string `json:"familiar_name"`
	GivenName    string `json:"given_name"`
	Surname      string `json:"surname"`
}

type DropboxFileResponse struct {
	ID        string `json:"id"`
	CModified string `json:"client_modified"`
	SModified string `json:"server_modified"`
	PathLower string `json:"path_lower"`
	Rev       string `json:"rev"`
	Name      string `json:"name"`
	Size      int    `json:"size"`
}

type DropboxDownloadResponse struct {
	Link string `json:"link"`
}
