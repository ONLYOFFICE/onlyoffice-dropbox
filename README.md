# ONLYOFFICE app for Dropbox

The **ONLYOFFICE app for Dropbox** allows users to **open, view, and edit** office files directly within their [Dropbox](https://www.dropbox.com/) workspace using [ONLYOFFICE online editors](https://www.onlyoffice.com/docs).

## ▶️ How it works

With this integration, Dropbox users can work on their office documents without leaving Dropbox:

1. Click the **three-dots menu (⋮)** to open the file context menu.
2. Select **Open in → ONLYOFFICE Docs**.
3. The selected document, spreadsheet, or presentation will open in a new browser tab using the corresponding ONLYOFFICE editor in full-screen mode.

> ✍️ **Note:** This app uses a **pre-configured ONLYOFFICE Docs Cloud tenant**, so there's no need for manual configuration.

## ⚙️ Installation guide

Easily connect ONLYOFFICE to your Dropbox account by following these steps:

1. Sign in to your [Dropbox](https://www.dropbox.com/) account.
2. Follow the [link](https://dropbox.onlyoffice.com/oauth/redirect).
3. Grant the requested permissions to link your Dropbox with ONLYOFFICE Docs.

Once connected, you can start opening and editing supported files directly from your Dropbox interface.

> ⚠️ **Tip:** To manage or disconnect the integration later, visit **Settings → [Apps](https://www.dropbox.com/account/connected_apps)** in your Dropbox account and select **Disconnect**.

## 📁 Supported file formats

ONLYOFFICE for Dropbox supports a wide range of office file formats:

| Format type                                  | Description                                                             |
| -------------------------------------------- | ----------------------------------------------------------------------- |
| OOXML (DOCX, XLSX, PPTX)                     | Open directly for full editing in ONLYOFFICE.                           |
| ODT, ODP, ODS, TXT, CSV, RTF, EPUB, FB2      | Viewable; editing may require conversion to OOXML to prevent data loss. |
| DOC, XLS, PPT, DOT, ET, FODP, HTM, POT, etc. | View-only or editable after conversion to OOXML.                        |
| PDF, DJVU, OXPS                              | View-only; editing is not supported.                                    |

> ⚠️ **Recommendation:** Convert non-OOXML files before editing to ensure full compatibility and maintain formatting fidelity.

## 🤖 MCP server for AI agents

The app exposes an [MCP](https://modelcontextprotocol.io) server at `https://dropbox.onlyoffice.com/mcp`, so an AI agent (for example the ONLYOFFICE Desktop AI agent) can work with your Dropbox:

- **All Dropbox MCP tools** (search, list, read, organize, share, ...) are proxied from [Dropbox's MCP server](https://help.dropbox.com/integrations/connect-dropbox-mcp-server) with the Dropbox access you granted to ONLYOFFICE.
- **`open_in_onlyoffice`** opens a Dropbox file in the ONLYOFFICE editor, so it is edited in place and every change is saved back to Dropbox. It returns an `oo-office:` link for ONLYOFFICE Desktop and a browser link.

To connect ONLYOFFICE Desktop:

1. Open `https://dropbox.onlyoffice.com/mcp/key` and sign in to Dropbox if asked. The page shows a ready-made configuration with a personal MCP key and a **Copy configuration** button (clients sending `Accept: application/json` get the configuration itself):

   ```json
   {
     "mcpServers": {
       "onlyoffice-dropbox": {
         "url": "https://dropbox.onlyoffice.com/mcp",
         "headers": { "Authorization": "Bearer <key>" }
       }
     }
   }
   ```

2. In ONLYOFFICE Desktop, open **AI agent > MCP Servers > Edit configuration**, add the `onlyoffice-dropbox` entry to `mcpServers` and save.
3. Sign in to Dropbox in ONLYOFFICE Desktop (**Connect to cloud > Dropbox**), so files opened by `open_in_onlyoffice` load in the editor.

The page always shows the same key for your account; a fresh key appears there every 30 days, and each key stays valid for up to 90 days (see the `X-MCP-Key-Expires` response header). Treat it like a password. **Revoke key** on the same page (`POST /mcp/key/revoke`) invalidates every key issued so far and shows a new one.

The gateway signs MCP keys with its own secret, `mcp.key_secret` in its configuration (or `MCP_KEY_SECRET`), a random value of at least 32 characters, e.g. `openssl rand -base64 48`; it does not start without one. To rotate it, set the new value and move the old one to `mcp.previous_key_secret` (`MCP_PREVIOUS_KEY_SECRET`) until users have copied the new configuration from `/mcp/key`.

A reverse proxy in front of the gateway must allow `/mcp` requests to take longer than 90 seconds (for example nginx `proxy_read_timeout 150;`): proxied Dropbox tools such as transcription can run that long, and the gateway answers a slow Dropbox itself after 85 seconds.

Dropbox's sharing tools need the `sharing.read` and `sharing.write` scopes in the app's Dropbox permissions and the `credentials.scopes` configuration.

## Project information

🌐 Official website: [onlyoffice.com](https://www.onlyoffice.com/office-for-dropbox)

💻 Source code: [Repository](https://github.com/ONLYOFFICE/onlyoffice-dropbox)

## 💬 User feedback & support

We welcome community participation, feedback, and collaboration.

If you have questions, issues, or suggestions, reach out through any of the following channels:

- 🐞 **Report issues:** [GitHub Issues](https://github.com/ONLYOFFICE/onlyoffice-dropbox/issues)
- 💬 **Community forum:** [ONLYOFFICE Forum](https://community.onlyoffice.com/)
- 👨‍💻 **Help for developers:** [API documentation](https://api.onlyoffice.com)