# Project handover: ONLYOFFICE app for Dropbox

## 1. Integration type

**A standalone hosted service**, not a module inside Dropbox. The user connects the "ONLYOFFICE" OAuth app to their account. Dropbox then shows **Open in → ONLYOFFICE Docs** in the file context menu and opens our gateway with `file_id` in the query.

Components (Go, go-micro, uber/fx via `github.com/ONLYOFFICE/onlyoffice-integration-adapters` v0.1.6):

| Service | Port | Role |
|---|---|---|
| gateway | 6044 | OAuth install, editor and conversion pages, version history, ONLYOFFICE Desktop entry point |
| auth | RPC | Stores tokens in MongoDB (AES-GCM, key = client_secret), refreshes them 2 min before expiry, 2 s cache |
| callback | 5044 | Receives the Document Server callback and uploads the file to Dropbox (`files/upload`) |

Infrastructure:
- Consul as the service registry; in k8s 🔎 probably the go-micro `kubernetes` registry plugin.
- Redis for caching.
- MongoDB.
- Optional Zipkin tracing.

How it works with ONLYOFFICE products:
- **ONLYOFFICE Docs Cloud.** A pre-configured cloud tenant (per README). The editor loads `api.js?shardkey=<doc key>`, which is Docs Cloud sharding. The editor config is signed with the Document Server JWT secret; the header name comes from `document_server_header`. Conversion uses the Conversion API (with password and region support).
- **ONLYOFFICE Desktop Editors.** Since 1.2.0, Dropbox is available in Desktop as a cloud provider. Desktop opens `/app`, which is reachable with `User-Agent: AscDesktopEditor` or `?desktop=true`. The page calls `AscDesktopEditor.execCommand("portal:login", {provider: "dropbox", ...})`.
- **Desktop AI agent (only on `feature/mcp`).** `/app/ai` returns `{provider: "dropbox", version: 1}`; `/app/token` returns the current Dropbox access token. CORS is open only to `onlyoffice://plugin`. The agent talks to Dropbox's MCP server itself. Our own MCP proxy was built and then **deliberately removed**.

Supported versions:
- Dropbox is a cloud product with no versions. Personal and Business/Team accounts are supported; team folders use the `Dropbox-API-Path-Root` header.
- Docs: 🔎 the current Docs Cloud. Formats come from the `document-formats` submodule (currently `v3.1.0-15`); history mentions "support new formats from DS v9.0".

## 2. Key features (user scenarios)

1. **Install.** `/oauth/install` → Dropbox OAuth (PKCE S256, `token_access_type=offline`, `force_reapprove`, `disable_signup`) → `/oauth/redirect` → user stored in auth → cookie session (25 h JWT, renewed on every request) → back to where the user came from.
2. **Open OOXML for editing** (docx/xlsx/pptx and anything marked `edit` in the formats table): `/convert?file_id=` → `/editor?token=&file_id=`.
3. **Save.** Document Server sends a callback with status 2 → the callback service uploads the file by `PathDisplay` using the token of the first user in `users[]`. This creates a new revision in Dropbox.
4. **Open a non-OOXML format.** For `lossy-edit` / `auto-convert` formats (odt, csv, txt, doc, xls, ppt, …) a dialog offers: open for viewing, create an OOXML copy, or edit with possible loss (`force_edit`). Password-protected files prompt for a password.
5. **View only** (view-only formats such as djvu): the document key is a random UUID.
6. **Version history** in the editor (`/api/history`, `/api/history/links`), based on Dropbox `list_revisions`.
7. **Team folders** in Dropbox Business (since 1.1.1).
8. **Desktop.** Signing in to Dropbox from ONLYOFFICE Desktop (since 1.2.0).
9. User avatar, language and dark theme in the editor; 9 locales (de, en, es, fr, it, ja, pt-BR, ru, zh); mobile editor chosen by User-Agent.

## 3. Build

- Go **1.25.7** (`go.mod`). The license-check CI uses `1.25`. It also builds locally with 1.26.
- The `services/shared/format/formats` submodule (public `github.com/ONLYOFFICE/document-formats`) is **required**. Its JSON is embedded with `go:embed`; the build fails without it.
- No private Go dependencies. `onlyoffice-integration-adapters` is public and maintained by the same team; changes to DI, RPC, crypto and logging go there.
- `Dockerfile` is multi-stage, one file with three targets (`gateway`, `auth`, `callback`). The runtime images install `python3` and `pip install kubernetes requests`: these are DevOps utilities that check k8s API availability (commit `fcbc5d4`). Don't remove them without DevOps.
- `hooks/build` and `hooks/push` are leftovers from Docker Hub automated builds (`DOCKER_TAG`);
- Configuration: YAML (`-c path`) with environment variables layered on top (`CREDENTIALS_*`, `ONLYOFFICE_DS_*`, `ONLYOFFICE_GATEWAY_URL`, `ONLYOFFICE_CALLBACK_URL`, ...). Templates: `services/*/config/config.example.yml`.

### CI (`.github/workflows`)

| Workflow | Trigger | What it does |
|---|---|---|
| `build.yaml` | push to `develop`, manual run (`tag`) | Builds and pushes `onlyoffice/dropbox-{gateway,auth,callback}:<tag>` to Docker Hub (linux/amd64 only). Without a tag it uses `1.3.0-rc.<run>`. Then sends an HMAC-signed webhook to **Flux** (job "Update connector"), which rolls out the new image |
| `create-tag.yml` | push to `master` | Creates tag `v<first version number in CHANGELOG.md>` |
| `release.yml` | tag `v*` | GitHub Release whose body is the top CHANGELOG section |
| `licenses.yml` | push/PR to master/develop | `ONLYOFFICE/check-licenses` |

**CI does not run tests or the linter.**

### Environments and secrets

Secret values are deliberately not included here, only where they live.

- **GitHub Actions secrets** (ONLYOFFICE/onlyoffice-dropbox): `DOCKER_HUB_USERNAME`, `DOCKER_HUB_ACCESS_TOKEN`, `DROPBOX_WEBHOOK_URL`, `DROPBOX_WEBHOOK_TOKEN` (HMAC for Flux).
- **Runtime secrets** (pod env): `CREDENTIALS_CLIENT_ID`, `CREDENTIALS_CLIENT_SECRET`, `ONLYOFFICE_DS_SECRET`, MongoDB and Redis URLs. Stored in k8s secrets / the Flux GitOps repository.
- **Dropbox App Console** — the OAuth app (client id/secret, redirect URI 🔎 `https://dropbox.onlyoffice.com/oauth/redirect` (production domain from the README), scopes, Extensions).

## 4. Marketplace publishing

The service is hosted by us, so **a regular release is an image deployment, not a marketplace submission**. There is no package to upload.

- **Dropbox App Center / app production status.** The app is already in production. "Open in" is the app's Dropbox Extension: the URL is set on the *Extensions* tab in App Console, and Dropbox appends `file_id`. In development status, the app and its extension are available only to a limited number of users (usually up to 50) and to the app's team members.
- **When something has to be done in Dropbox:**
  - OAuth scopes change. Currently only the configured scopes are requested. New scopes force users to re-authorize and 🔎 may require another review;
  - the redirect URI or domain changes;
  - the Extension URL or its supported file extensions change;
  - the App Center branding or description changes.
- **Common Dropbox review rejection reasons**: unjustified extra scopes, branding violations (Dropbox name or logo in the app name or icon), missing privacy policy or ToS, a test scenario that doesn't work for the reviewer.
- **ONLYOFFICE Desktop.** The `dropbox` provider and the AI interface are built into Desktop. Changes to the `/app`, `/app/ai`, `/app/token` contract must be coordinated with the Desktop team.

## 5. Tribal knowledge

- **One secret for everything.** The Dropbox `client_secret` is the cookie-store key (sessions `authorization`, `auth-installation`, `url`), the CSRF key, the HMAC key for session and convert JWTs, and the AES key for access and refresh tokens in Mongo. Rotating it without a migration makes every stored token undecryptable, and every user has to reinstall the app.
- **The auth user cache is 2 seconds.** A longer TTL served stale tokens after a refresh. That was the "fix ttl issue" in 1.2.2.
- **Token refresh** happens in `UserSelectHandler.GetUser` under `singleflight`, 2 minutes before expiry. The TokenSource is deliberately given an "expired" `Expiry` (−10 years) so that `oauth2` always performs the refresh.
- **`userCallTimeout = 15s`.** An auth call may include a Dropbox refresh and a DB write; don't lower it.
- **Document key** is `md5(file.ID + server_modified)`: a new Dropbox revision starts a new co-editing session. View mode uses a random UUID so it never joins someone else's editing session.
- **Callback.** `state` is a JWT with `file_id` signed with the Document Server secret, so the callback URL cannot be forged. Before uploading, a HEAD request checks the file against `max_size`. The upload uses the token of the **first** user in `users[]`.
- **"Verify your email" page.** Dropbox refuses `get_temporary_link` to accounts with an unverified email, so an empty link is treated that way. `fix/email-confirmation` separates this case from team-account errors.
- **The Desktop gate** (`RequireDesktop`) is a UX filter, not security: `?desktop=true` bypasses it. The real protection is the session.
- **CORS on `/app/*`.** Wildcard CORS doesn't work with credentials, so the `onlyoffice://plugin` origin is allowed explicitly and the headers are stripped for everyone else (`allowDesktopPlugin`).
- **MCP.** Our own MCP proxy was tried (commits `0235b25` through `cbf4794`) and removed: the Desktop agent calls Dropbox MCP directly with the token from `/app/token`. Don't bring the proxy back without a team decision.
- **Editor plugins are disabled** (`customization.plugins=false`). `chore/plugins` enables them by turning the field into a pointer with `omitempty`.
- **Python and kubernetes in the Docker images** are for DevOps checks of k8s API availability.
- **Leave alone without a good reason:** `shared/client/api.go` (team-account headers), the cache format and TTL in auth, the signatures and keys in `prepareDocumentConfig`, and the middleware order in `gateway/web/server.go` (CSRF → session → size).

## 6. Known issues, tech debt, unfinished branches

### Issues

1. CI doesn't run tests or the linter. Smoke tests (`go test -run Smoke ./services/...`) were added but aren't wired into a workflow.
2. `TestUserService/update_user_token_with_timeout` fails (`services/auth/web/core/service/tests/user_test.go:110`): `UpdateUser` returns no error for an already expired context. Most likely the memory adapter ignores `ctx`.
3. `callback.go`: with `status == 2` and an empty `users`, `body.Users[0]` panics. In practice Document Server always sends `users`, but there is no validation.
4. `editor.go:212`: unchecked `token["force_edit"].(bool)`. The field is currently always present (no `omitempty`), but the code is fragile.
5. `build.yaml`: the rc prefix `1.3.0` is hard-coded. The manual-run branch checks `$TAG` instead of `$MANUAL_TAG`; harmless, because `inputs.tag` takes precedence anyway.
6. The README says PDF is view-only, but the current formats submodule gives `pdf` the `edit` action, so PDFs open for editing. Decide what we want and fix either the README or the code.
7. `version:` in `config.example.yml` and the `onlyoffice-integration-adapters` version are bumped by hand.
8. The Mongo adapter test needs a local MongoDB and fails or hangs without it.
9. Images are built for `linux/amd64` only.

### Branches (relative to `master`, as of 2026-11-11)

| Branch | Ahead / behind | Last commit | Contents |
|---|---|---|---|
| `feature/mcp` | +23 / −3 | 2026-10-27 | Desktop AI (`/app/ai`, `/app/token`), 404 page, requesting only configured scopes, callback hardening (`state` signed with the DS secret), passing the session user through the context, timeouts. MCP proxy history (added and removed). Not in `develop` |
| `chore/plugins` | +3 / 0 | 2026-10-20 | Enable editor plugins, CHANGELOG 1.2.3. Based on current `master` |
| `fix/plugins` | +1 / −3 | 2026-10-20 | The "enable plugins" commit only, on an older base. 🔎 Superseded by `chore/plugins`, can be deleted |
| `fix/email-confirmation` | +5 / −3 | 2026-10-20 | Page for non-activated profiles, separate error for team accounts (includes the "enable plugins" commit) |
| `dependencies/bump` | +3 / −3 | 2026-10-19 | Move to `onlyoffice-integration-adapters` v0.2.0 (−506 lines), Go in CI synced with go.mod. Conflicts with `feature/mcp` |
| `develop` | 0 / −3 | 2026-06-03 | Release 1.2.2; `master` is ahead only by the issue templates |

## Manual verification checklist (after deploying to staging or production)

The automated smoke tests cover routing, guards, the OAuth redirect, callback signatures and the format matrix. Everything that needs a real Dropbox and Document Server is checked by hand:

- [ ] New account: Dropbox → Apps → ONLYOFFICE (or `/oauth/install`) → the consent screen shows only the expected scopes → back to Dropbox.
- [ ] docx, xlsx, pptx: "Open in → ONLYOFFICE Docs" opens the editor with the user's avatar and language.
- [ ] Edit a docx → close the tab → within 10–30 s a new revision with the changes appears in Dropbox.
- [ ] Co-editing: two users with access to a shared folder see each other.
- [ ] odt: the conversion dialog, all three options (view, OOXML copy, lossy editing).
- [ ] doc, xls, ppt: an OOXML copy is created next to the original.
- [ ] Password-protected file: password prompt; a wrong password shows an error.
- [ ] pdf and djvu: the expected mode (see §6 item 6).
- [ ] Version history in the editor shows Dropbox revisions; an old revision opens.
- [ ] Team folder in a Business account: open and save.
- [ ] Mobile browser: the mobile editor.
- [ ] Account with an unverified email: the "verify your email" page.
- [ ] Disconnect the app in Dropbox and reopen a file: redirect to install.
- [ ] Unknown path: the 404 page with an icon.
- [ ] Desktop: Connect to cloud → Dropbox → sign in; files are listed, open and save work.
- [ ] Desktop AI (once released): Dropbox appears in the AI chat's cloud list and the Dropbox tools work.
- [ ] Logs of all three services show no new ERROR lines; all three services are healthy in Consul.
