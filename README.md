# yeswehack-mcp

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server for the [YesWeHack](https://yeswehack.com) bug bounty platform. Lets Claude query your private and public programs, reports, and the hacktivity feed directly from a conversation.

## Features

- **Flexible authentication** — browser login, email/password API login, copied bearer tokens, and official Personal Access Tokens.
- **Private programs** — returns invite-only programs you have been accepted into, not just public ones.
- **Full program details** — scope, out-of-scope, reward grid, rules, qualifying / non-qualifying vulnerabilities.
- **Report access** — list reports with `filter[status][]`, read reports with CVSS, bug type, scope, description, and bounty.
- **Report comments** — comments and history from `/reports/{id}/logs`.
- **Email aliases** — list your YesWeHack email aliases (web-session JWT only).
- **Program credentials** — hunter view of assigned credentials and pending requests; request credentials from a pool.
- **Hacktivity feed** — the public `/v2/hacktivity` feed.
- **Token caching** — the JWT is stored locally and reused until it expires.

## Requirements

- Python 3.10+
- [uv](https://docs.astral.sh/uv/)
- A YesWeHack account
- **WSL2 users:** WSLg must be enabled so Chromium can open a window (`echo $DISPLAY` should return a value)

## Installation

```bash
git clone https://github.com/youruser/yeswehack-mcp
cd yeswehack-mcp

# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies (also installs the dev group with pytest)
uv sync

# Download the Chromium browser used for login
uv run playwright install chromium
```

## Registering with Claude Code

```bash
claude mcp add yeswehack -- uv --directory /path/to/yeswehack-mcp run server.py
```

Replace `/path/to/yeswehack-mcp` with the actual path where you cloned the repo.

Verify it connected:

```bash
claude mcp list
# yeswehack: ... ✓ Connected
```

## Registering with Claude Desktop

Add the following to your Claude Desktop config file:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "yeswehack": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/yeswehack-mcp",
        "run",
        "server.py"
      ]
    }
  }
}
```

If `uv` is not on PATH when Claude Desktop launches, use the absolute path (e.g. `/home/youruser/.local/bin/uv`).

## Usage

Once registered, start every session by authenticating:

> **You:** Call the authenticate tool

With no arguments, a Chromium window opens. Log in to YesWeHack as normal (email + password + 2FA if enabled). The window closes automatically once your session is detected. The token is saved to `~/.config/yeswehack-mcp/token.json` and reused for all subsequent calls until it expires.

You can also authenticate without a browser:

```text
authenticate(email="you@example.com", password="...", totp="123456")
authenticate(access_token="eyJ...")        # browser/API bearer token
authenticate(access_token="<PAT>")         # Personal Access Token
```

Email/password login follows the official SDK flow: `POST /login` returns a `token`, or a
`totp_token` when 2FA is on; the TOTP code is then sent to `POST /account/totp`.
With 2FA, the first call without `totp` reports that a code is needed; call again with it.

Personal Access Tokens (recommended) are sent as `X-AUTH-TOKEN` and cover the documented
API (`https://api.yeswehack.com/doc.json`). `get_current_user` and `list_email_aliases`
use web-session routes outside that spec and answer 403 for a PAT.

Environment variables are supported too and take precedence over the stored token:

```bash
export YWH_TOKEN="eyJ..."       # browser/API bearer token
export YWH_PAT="<your-pat>"     # Personal Access Token
```

### Available tools

| Tool | Description |
|------|-------------|
| `authenticate` | Browser login, API login, or store a copied bearer token/PAT |
| `get_current_user` | Your profile via `/user` (needs a browser/API JWT; PATs get 403) |
| `list_programs` | Programs you have access to, including private invite-only ones; `all_pages` (default true), `page`, `private_only` |
| `get_program` | Full details for a program: scope, out-of-scope, reward grid, rules, (non-)qualifying vulnerabilities |
| `list_reports` | One page of reports for a program; `status` takes comma-separated workflow states (e.g. `new,accepted`), `page`, `results_per_page` (default 50, API maximum 100) |
| `get_report` | Full details of a report (status, CVSS criticity/score/vector, bug type, scope, description, bounty) |
| `list_report_comments` | Comments of a report from `/reports/{id}/logs`; `include_history=true` adds status/CVSS/reward entries |
| `list_email_aliases` | List your email aliases (needs a browser/API JWT; PATs get 403) |
| `get_program_credentials` | Your assigned credentials and pending requests for a program (`include_secrets=false` by default) |
| `request_program_credentials` | Request credentials (state-changing): `pool_slug` (required), `pool_type` = classic (default) / email / email-alias, `email` (only for `email` pools, sent as `{"emails": [email]}`; classic and email-alias requests have no body) |
| `yeswehack_api_get` | Read-only escape hatch for authenticated API endpoints not wrapped yet; `path`, optional `params_json` |
| `get_hacktivity` | Public `/v2/hacktivity` feed (date, status, bug type, hunter); only `page`, no authentication needed |

`list_report_comments`, `list_email_aliases`, `get_program_credentials` and `request_program_credentials` also accept `raw=true` for the raw JSON. Raw output still hides credential passwords (unless `include_secrets=true`) and the `tracker_token` / `claim_email` values of report logs.

### Example prompts

```
List all my private programs on YesWeHack.

Show me the scope for the program with slug "acme-corp".

List my YesWeHack email aliases.

Get credentials for program "acme-corp".

Show the comments and history of report 12345.

List all accepted reports for program "acme-corp".

Get the full details of report 12345.

Show me the latest hacktivity, page 2.
```

## Token storage

The token is saved to `~/.config/yeswehack-mcp/token.json`. It contains only the token and its expiry timestamp — no account password is ever stored. Browser/API session JWTs use their embedded expiry. Opaque Personal Access Tokens are cached locally until the YesWeHack API rejects them. The browser profile (cookies, localStorage) is kept at `~/.config/yeswehack-mcp/browser-profile` so you do not have to fill in your email every time you re-authenticate.

Browser extensions are loaded only when listed explicitly in `~/.config/yeswehack-mcp/extensions.json` (a JSON list of unpacked-extension directories). Nothing is auto-detected from other browser profiles.

To log out, delete the token file:

```bash
rm ~/.config/yeswehack-mcp/token.json
```

## Project structure

```
yeswehack-mcp/
├── server.py        # FastMCP entry point — all tool definitions
├── auth.py          # API login (TOTP), Playwright browser login, token storage
├── client.py        # httpx async API wrapper with pagination
├── tests/           # offline pytest suite (fake API, real response shapes) + read-only live tests
├── docs/
│   └── API.md       # official API links, auth, pagination, tool-to-endpoint map
├── Makefile         # help, build, test, test-live, clean
└── pyproject.toml   # Dependencies and build config
```

## API documentation

[docs/API.md](docs/API.md) maps each tool to its endpoint and lists the filters and pagination rules. The official OpenAPI spec is at <https://api.yeswehack.com/doc.json>.

## Development

```bash
make help        # list targets
make build       # build wheel and sdist into dist/
make test        # offline test suite, no network after the first uv sync
make test-live   # READ-ONLY tests against the real API; needs YWH_PAT in .env
make clean       # remove dist/, build/, egg-info and caches (keeps .venv, .env, config)
```

`make test-live` loads `./.env` if present. Put `YWH_PAT=<your-pat>` in it; the file is git-ignored. Without `YWH_PAT` the live tests are skipped.

## WSL2 display setup

Playwright needs a display to open the browser window. On WSL2 with WSLg this works out of the box. If you see an error about `DISPLAY` not being set:

```bash
# Check if WSLg is running
echo $DISPLAY        # should print something like :0
ls /mnt/wslg        # should exist

# If not, ensure you are on a recent WSL2 version with WSLg support
wsl --update         # run from Windows PowerShell
```

## License

MIT
