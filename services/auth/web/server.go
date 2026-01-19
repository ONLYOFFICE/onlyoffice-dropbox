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

package web

import (
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/auth/web/handler"
	"github.com/ONLYOFFICE/onlyoffice-integration-adapters/service/rpc"
)

type AuthRPCServer struct {
	insertHandler handler.UserInsertHandler
	selectHandler handler.UserSelectHandler
	deleteHandler handler.UserDeleteHandler
}

func NewAuthRPCServer(
	insertHandler handler.UserInsertHandler,
	selectHandler handler.UserSelectHandler,
	deleteHandler handler.UserDeleteHandler,
) rpc.RPCEngine {
	return &AuthRPCServer{
		insertHandler: insertHandler,
		selectHandler: selectHandler,
		deleteHandler: deleteHandler,
	}
}

func (a AuthRPCServer) BuildMessageHandlers() []rpc.RPCMessageHandler {
	return nil
}

func (a AuthRPCServer) BuildHandlers() []interface{} {
	return []interface{}{a.selectHandler, a.deleteHandler, a.insertHandler}
}
