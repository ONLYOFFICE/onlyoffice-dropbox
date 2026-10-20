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
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/controller"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/controller/convert"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/embeddable"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/mcp"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/middleware"
	shttp "github.com/ONLYOFFICE/onlyoffice-integration-adapters/service/http"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
)

type DropboxHTTPService struct {
	mux               *mux.Router
	authController    controller.AuthController
	editorController  controller.EditorController
	convertController convert.ConvertController
	historyController controller.HistoryController
	desktopController controller.DesktopController
	mcpController     controller.MCPController
	mcpHandler        mcp.Handler
	sessionMiddleware middleware.SessionMiddleware
	desktopMiddleware middleware.DesktopMiddleware
	mcpMiddleware     middleware.MCPMiddleware
	credentials       *oauth2.Config
}

// NewService initializes http server with options.
func NewServer(
	authController controller.AuthController,
	editorController controller.EditorController,
	convertController convert.ConvertController,
	historyController controller.HistoryController,
	desktopController controller.DesktopController,
	mcpController controller.MCPController,
	mcpHandler mcp.Handler,
	sessionMiddleware middleware.SessionMiddleware,
	desktopMiddleware middleware.DesktopMiddleware,
	mcpMiddleware middleware.MCPMiddleware,
	credentials *oauth2.Config,
) shttp.ServerEngine {
	service := DropboxHTTPService{
		mux:               mux.NewRouter(),
		authController:    authController,
		editorController:  editorController,
		convertController: convertController,
		historyController: historyController,
		desktopController: desktopController,
		mcpController:     mcpController,
		mcpHandler:        mcpHandler,
		sessionMiddleware: sessionMiddleware,
		desktopMiddleware: desktopMiddleware,
		mcpMiddleware:     mcpMiddleware,
		credentials:       credentials,
	}

	return service
}

// ApplyMiddleware useed to apply http server middlewares.
func (s DropboxHTTPService) ApplyMiddleware(middlewares ...func(http.Handler) http.Handler) {
	for _, middleware := range middlewares {
		s.mux.Use(middleware)
	}
}

// NewHandler returns http server engine.
func (s DropboxHTTPService) NewHandler() interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
} {
	return s.InitializeServer()
}

// InitializeServer sets all injected dependencies.
func (s *DropboxHTTPService) InitializeServer() *mux.Router {
	s.InitializeRoutes()
	return s.mux
}

// serves the embedded icons and answers every other unknown
// path with the 404 page.
func notFoundHandler() http.Handler {
	static := http.FileServer(http.FS(embeddable.IconFiles))
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if info, err := fs.Stat(embeddable.IconFiles, name); err == nil && !info.IsDir() {
			static.ServeHTTP(rw, r)
			return
		}

		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.WriteHeader(http.StatusNotFound)
		_ = embeddable.NotFoundPage.Execute(rw, nil)
	})
}

// InitializeRoutes builds all http routes.
func (s *DropboxHTTPService) InitializeRoutes() {
	s.mux.Use(chimiddleware.Recoverer, chimiddleware.NoCache,
		middleware.SkipCSRF(csrf.Protect([]byte(s.credentials.ClientSecret)), "/mcp"))

	sizeMiddleware := middleware.MaxPayloadSizeMiddleware(1 * 1024 * 1024)
	root := s.mux.NewRoute().PathPrefix("/").Subrouter()
	root.Use(s.sessionMiddleware.Protect, sizeMiddleware)
	root.Handle("/editor", s.editorController.BuildEditorPage()).Methods(http.MethodGet)
	root.Handle("/convert", s.convertController.BuildConvertPage()).Methods(http.MethodGet)
	root.Handle("/mcp/key", s.mcpController.BuildGetKey()).Methods(http.MethodGet)
	root.Handle("/mcp/key/revoke", s.mcpController.BuildRevokeKey()).Methods(http.MethodPost)

	s.mux.Handle("/mcp", s.mcpMiddleware.Authenticate(s.mcpHandler))

	desktop := s.mux.NewRoute().PathPrefix("/app").Subrouter().StrictSlash(true)
	desktop.Use(s.desktopMiddleware.RequireDesktop, s.sessionMiddleware.Protect, sizeMiddleware)
	desktop.Handle("/", s.desktopController.BuildEntryPage()).Methods(http.MethodGet)

	auth := s.mux.NewRoute().PathPrefix("/oauth").Subrouter().StrictSlash(true)
	auth.Handle("/install", s.authController.BuildGetAuth()).Methods(http.MethodGet)
	auth.Handle("/redirect", s.authController.BuildGetRedirect()).Methods(http.MethodGet)

	api := s.mux.NewRoute().PathPrefix("/api").Subrouter()
	api.Use(s.sessionMiddleware.Protect, sizeMiddleware)
	api.Handle("/convert", s.convertController.BuildConvertFile()).Methods(http.MethodPost)
	api.Handle("/history", s.historyController.BuildGetFileHistory()).Methods(http.MethodGet)
	api.Handle("/history/links", s.historyController.BuildGetFileHistoryLinks()).Methods(http.MethodGet)

	s.mux.NotFoundHandler = notFoundHandler()
}
