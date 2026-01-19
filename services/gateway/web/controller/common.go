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

package controller

import (
	"errors"

	"golang.org/x/sync/singleflight"
)

var (
	ErrCouldNotCastValue    = errors.New("could not cast value to type")
	ErrSessionTokenCasting  = errors.New("could not cast a session token")
	ErrUserIdMatching       = errors.New("token uid and state uid do not match")
	ErrInvalidStateValue    = errors.New("invalid state value")
	ErrInvalidVerifierValue = errors.New("invalid verifier value")
	group                   singleflight.Group
)
