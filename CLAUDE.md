# ONLYOFFICE app for Dropbox

A hosted service, not a plugin: three Go microservices that open Dropbox files in ONLYOFFICE Docs Cloud. Background, history and tribal knowledge live in `HANDOVER.md`. Releases are covered by the `/release` skill.

## Commands

```bash
git submodule update --init --recursive   # required: format table in services/shared/format/formats
make build                                # binaries in build/{auth,callback,gateway}
make test                                 # go test -v -race ./...
go test -run Smoke ./services/...         # smoke tests: gateway routing/sessions, callback, format matrix
make lint                                 # golangci-lint (.golangci.yml)
make audit                                # vet, staticcheck, govulncheck, tests
make run/auth | run/gateway | run/callback   # dev run with services/<svc>/config/config.yml
docker compose build                      # images; REGISTRY and PRODUCT_VERSION come from env
```

- `services/auth/web/core/adapter/tests/mongo_test.go` needs MongoDB on `localhost:27017`.
- `TestUserService/update_user_token_with_timeout` is a known failure on `feature/mcp`; it is unrelated to the smoke tests (see HANDOVER §6).
- Running locally requires Consul (`127.0.0.1:8500`), Redis, MongoDB and a public URL (ngrok): the OAuth redirect and the Document Server callback arrive there.

## Layout

- `services/gateway` (:6044) — HTTP: OAuth install (`/oauth/*`), `/editor`, `/convert`, `/api/{convert,history}`, Desktop (`/app`, `/app/token`, `/app/ai`); HTML templates and locales in `web/embeddable`.
- `services/auth` — RPC only (go-micro): stores and refreshes OAuth tokens (Mongo + 2 s cache). Called as `<namespace>:auth` with methods `UserSelectHandler.GetUser`, `UserInsertHandler.InsertUser`, `UserDeleteHandler.DeleteUser`.
- `services/callback` (:5044) — `POST /callback` from Document Server; uploads the saved file to Dropbox.
- `services/shared` — configs, Dropbox API client (`client/api.go`, personal and team accounts), DTOs, format manager.
- DI and bootstrap come from `onlyoffice-integration-adapters` (uber/fx). A new constructor must be added to `pkg.WithModules(...)` in `services/<svc>/cmd/server.go`, or it will never be created.

## Conventions

- Commits: conventional (`feat(gateway): ...`, `fix: ...`, `deps: ...`, `ci: ...`, `docs: ...`).
- New config key: a field with `yaml` and `env` tags, plus an entry in `config/config.example.yml`.
- New UI string: add the key to **all 9** files in `services/gateway/web/embeddable/locales/*.json`.
- New dependencies must pass the license check (`.github/workflows/licenses.yml`); exceptions go into `.check-licenses.yml`.
- The release tag is taken from the **first** version number in `CHANGELOG.md`.

## Don'ts

- Never commit `services/*/config/config.yml` (gitignored, contains real secrets), and never copy values from it into code, docs or tests.
- Don't change how the Dropbox `client_secret` is used without a migration: it is the key for cookie sessions, CSRF, the session JWT **and the encryption of tokens in Mongo**. Changing it forces every user to reinstall the app.
- Don't raise the user cache TTL in `auth/web/core/service/user.go` (2 s); that was the 1.2.2 fix.
- Don't add OAuth scopes without agreement: it changes the consent screen and may trigger a Dropbox review.
- `/app/token` returns a raw Dropbox access token; CORS is open only to `onlyoffice://plugin`. Don't loosen it.
- Don't edit files inside the `formats` submodule; update it only by bumping the submodule.
