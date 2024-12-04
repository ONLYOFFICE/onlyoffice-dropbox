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

package web

import (
	"net/http"

	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/controller"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/controller/convert"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/embeddable"
	"github.com/ONLYOFFICE/onlyoffice-dropbox/services/gateway/web/middleware"
	shttp "github.com/ONLYOFFICE/onlyoffice-integration-adapters/service/http"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
)

type GdriveHTTPService struct {
	mux               *mux.Router
	authController    controller.AuthController
	editorController  controller.EditorController
	convertController convert.ConvertController
	sessionMiddleware middleware.SessionMiddleware
	credentials       *oauth2.Config
}

// NewService initializes http server with options.
func NewServer(
	authController controller.AuthController,
	editorController controller.EditorController,
	convertController convert.ConvertController,
	sessionMiddleware middleware.SessionMiddleware,
	credentials *oauth2.Config,
) shttp.ServerEngine {
	service := GdriveHTTPService{
		mux:               mux.NewRouter(),
		authController:    authController,
		editorController:  editorController,
		convertController: convertController,
		sessionMiddleware: sessionMiddleware,
		credentials:       credentials,
	}

	return service
}

// ApplyMiddleware useed to apply http server middlewares.
func (s GdriveHTTPService) ApplyMiddleware(middlewares ...func(http.Handler) http.Handler) {
	for _, middleware := range middlewares {
		s.mux.Use(middleware)
	}
}

// NewHandler returns http server engine.
func (s GdriveHTTPService) NewHandler() interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
} {
	return s.InitializeServer()
}

// InitializeServer sets all injected dependencies.
func (s *GdriveHTTPService) InitializeServer() *mux.Router {
	s.InitializeRoutes()
	return s.mux
}

// InitializeRoutes builds all http routes.
func (s *GdriveHTTPService) InitializeRoutes() {
	s.mux.Use(chimiddleware.Recoverer, chimiddleware.NoCache,
		csrf.Protect([]byte(s.credentials.ClientSecret)))

	root := s.mux.NewRoute().PathPrefix("/").Subrouter()
	root.Use(s.sessionMiddleware.Protect)
	root.Handle("/editor", s.editorController.BuildEditorPage()).Methods(http.MethodGet)
	root.Handle("/convert", s.convertController.BuildConvertPage()).Methods(http.MethodGet)

	auth := s.mux.NewRoute().PathPrefix("/oauth").Subrouter()
	auth.Handle("/install", s.authController.BuildGetAuth()).Methods(http.MethodGet)
	auth.Handle("/redirect", s.authController.BuildGetRedirect()).Methods(http.MethodGet)

	api := s.mux.NewRoute().PathPrefix("/api").Subrouter()
	api.Use(s.sessionMiddleware.Protect)
	api.Handle("/convert", s.convertController.BuildConvertFile()).Methods(http.MethodPost)

	var staticFS = http.FS(embeddable.IconFiles)
	s.mux.NotFoundHandler = http.FileServer(staticFS)
}
