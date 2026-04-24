# yeswehack-mcp

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server for the [YesWeHack](https://yeswehack.com) bug bounty platform. Lets Claude query your private and public programs, reports, and the hacktivity feed directly from a conversation.

## Features

- **Flexible authentication** — browser login, email/password API login, copied bearer tokens, and official Personal Access Tokens.
- **Private programs** — returns invite-only programs you have been accepted into, not just public ones.
- **Full program details** — scope, reward ranges, status.
- **Report access** — list and read reports with severity, CVSS, description, and bounty.
- **Report comments** — list report discussion/messages when your account has access.
- **Email aliases** — list your YesWeHack email aliases.
- **Program credentials** — list credential pools/assigned credentials and request credentials for programs that expose pools.
- **Hacktivity feed** — browse publicly disclosed reports.
- **Token caching** — the JWT is stored locally and reused until it expires.

## Requirements

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (installed automatically by the setup script if missing)
- A YesWeHack account
- **WSL2 users:** WSLg must be enabled so Chromium can open a window (`echo $DISPLAY` should return a value)

## Installation

```bash
git clone https://github.com/youruser/yeswehack-mcp
cd yeswehack-mcp

# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
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
authenticate(access_token="ywh_pat_...")   # Personal Access Token
```

Environment variables are supported too:

```bash
export YWH_TOKEN="eyJ..."       # browser/API bearer token
export YWH_PAT="ywh_pat_..."    # Personal Access Token
```

### Available tools

| Tool | Description |
|------|-------------|
| `authenticate` | Browser login, API login, or store a copied bearer token/PAT |
| `get_current_user` | Show your YesWeHack profile (username, rank, reputation) |
| `list_programs` | List all programs you have access to, including private invite-only ones |
| `get_program` | Full details for a program: scope, reward ranges, status |
| `list_reports` | List reports for a program, with optional status filter |
| `get_report` | Full details of a specific report (title, severity, CVSS, description, bounty) |
| `list_report_comments` | List comments/messages for a report when your token has access |
| `list_email_aliases` | List your YesWeHack email aliases |
| `get_program_credentials` | List credential pools and assigned credentials for a program |
| `request_program_credentials` | Request credentials from a program credential pool |
| `yeswehack_api_get` | Read-only escape hatch for authenticated API endpoints not wrapped yet |
| `get_hacktivity` | Browse the public hacktivity (disclosed reports) feed |

### Example prompts

```
List all my private programs on YesWeHack.

Show me the scope for the program with slug "acme-corp".

List my YesWeHack email aliases.

Get credentials for program "acme-corp".

List all accepted reports for program "acme-corp".

Get the full details of report 12345.

Show me the latest hacktivity, page 2.
```

## Token storage

The token is saved to `~/.config/yeswehack-mcp/token.json`. It contains only the token and its expiry timestamp — no account password is ever stored. Browser/API session JWTs use their embedded expiry. Opaque Personal Access Tokens are cached locally until the YesWeHack API rejects them. The browser profile (cookies, localStorage) is kept at `~/.config/yeswehack-mcp/browser-profile` so you do not have to fill in your email every time you re-authenticate.

To log out, delete the token file:

```bash
rm ~/.config/yeswehack-mcp/token.json
```

## Project structure

```
yeswehack-mcp/
├── server.py        # FastMCP entry point — all tool definitions
├── auth.py          # Playwright browser login + token storage
├── client.py        # httpx async API wrapper with pagination
└── pyproject.toml   # Dependencies and build config
```

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
