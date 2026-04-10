# yeswehack-mcp

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server for the [YesWeHack](https://yeswehack.com) bug bounty platform. Lets Claude query your private and public programs, reports, and the hacktivity feed directly from a conversation.

## Features

- **Browser-based authentication** — opens a real Chromium window so you log in through the YesWeHack UI (2FA supported). No passwords stored anywhere.
- **Private programs** — returns invite-only programs you have been accepted into, not just public ones.
- **Full program details** — scope, reward ranges, status.
- **Report access** — list and read reports with severity, CVSS, description, and bounty.
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

A Chromium window opens. Log in to YesWeHack as normal (email + password + 2FA if enabled). The window closes automatically once your session is detected. The token is saved to `~/.config/yeswehack-mcp/token.json` and reused for all subsequent calls until it expires.

### Available tools

| Tool | Description |
|------|-------------|
| `authenticate` | Open browser login, capture and store your session token |
| `get_current_user` | Show your YesWeHack profile (username, rank, reputation) |
| `list_programs` | List all programs you have access to, including private invite-only ones |
| `get_program` | Full details for a program: scope, reward ranges, status |
| `list_reports` | List reports for a program, with optional status filter |
| `get_report` | Full details of a specific report (title, severity, CVSS, description, bounty) |
| `get_hacktivity` | Browse the public hacktivity (disclosed reports) feed |

### Example prompts

```
List all my private programs on YesWeHack.

Show me the scope for the program with slug "acme-corp".

List all accepted reports for program "acme-corp".

Get the full details of report 12345.

Show me the latest hacktivity, page 2.
```

## Token storage

The JWT is saved to `~/.config/yeswehack-mcp/token.json`. It contains only the token and its expiry timestamp — no credentials are ever stored. The browser profile (cookies, localStorage) is kept at `~/.config/yeswehack-mcp/browser-profile` so you do not have to fill in your email every time you re-authenticate.

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
