# HackerOne MCP Server

> **Disclaimer:** This is an unofficial, community-built project. It is not affiliated with, endorsed by, or maintained by HackerOne. "HackerOne" is a trademark of HackerOne, Inc. This project simply integrates with their publicly documented [Hacker API](https://api.hackerone.com/hacker-resources/).

MCP server that gives Claude Code (or any MCP client) full access to your HackerOne reports, programs, and scope data via the HackerOne API. **Read-only by default** — write tools (`submit_report`, `add_comment`, `close_report`) are only enabled when you set `H1_ALLOW_WRITES=true`, and HAI report drafts (`create_report_draft` & co.) with `H1_ALLOW_DRAFTS=true`.

## Setup

### 1. Get your HackerOne API token

Go to **HackerOne > Settings > API Token** and generate one.

### 2. Install and build

```bash
git clone https://github.com/Sicks3c/hackerone-mcp-server.git
cd hackerone-mcp-server
npm install
npm run build
```

### 3. Add to Claude Code

```bash
claude mcp add hackerone \
  -e H1_USERNAME=your-username \
  -e H1_API_TOKEN=your-api-token \
  -s user \
  -- node /path/to/hackerone-mcp-server/dist/index.js
```

Or add manually to `~/.claude.json`:

```json
{
  "mcpServers": {
    "hackerone": {
      "command": "node",
      "args": ["/path/to/hackerone-mcp-server/dist/index.js"],
      "env": {
        "H1_USERNAME": "your-username",
        "H1_API_TOKEN": "your-api-token"
      }
    }
  }
}
```

### 4. Verify

```bash
claude
> /mcp
# You should see "hackerone" listed with 10 tools (+3 writes, +8 HAI drafts)
```

## Enabling write operations

The server is read-only by default. To enable `submit_report`, `add_comment`, and `close_report`, set `H1_ALLOW_WRITES=true` in the server environment:

```bash
claude mcp add hackerone \
  -e H1_USERNAME=your-username \
  -e H1_API_TOKEN=your-api-token \
  -e H1_ALLOW_WRITES=true \
  -s user \
  -- node /path/to/hackerone-mcp-server/dist/index.js
```

## Enabling HAI report drafts

To let HAI (HackerOne's Report Assistant) review draft reports, set `H1_ALLOW_DRAFTS=true`. This enables the `create_report_draft`, `update_report_draft`, `delete_report_draft`, `get_report_draft`, `list_report_drafts`, `upload_draft_attachments`, `list_draft_attachments`, and `delete_draft_attachment` tools. Drafts (report intents) are private to you — they are never submitted to the program by these tools, and the program must have Report Assistant enabled:

```bash
claude mcp add hackerone \
  -e H1_USERNAME=your-username \
  -e H1_API_TOKEN=your-api-token \
  -e H1_ALLOW_DRAFTS=true \
  -s user \
  -- node /path/to/hackerone-mcp-server/dist/index.js
```

## Tools

### Read

| Tool | Description |
|------|-------------|
| `search_reports` | Search and filter your reports by keyword, program, severity, or state |
| `get_report` | Get full report details including CVSS vector and attachments |
| `get_report_with_conversation` | Get a report with its triage conversation thread |
| `get_report_activities` | Get activity timeline (comments, state changes, bounties) |
| `list_programs` | List all bug bounty programs you have access to (auto-paginates) |
| `get_program_details` | Get single program info: policy, response times, metrics |
| `get_program_scope` | Get all in-scope assets for a program (auto-paginates) |
| `get_program_weaknesses` | Get accepted CWE/weakness types for a program (auto-paginates) |
| `analyze_report_patterns` | Analyze your hunting patterns (severity distribution, top programs, weakness types) |
| `search_disclosed_reports` | Search publicly disclosed reports on hacktivity — great for recon and learning |

### Write (requires `H1_ALLOW_WRITES=true`)

| Tool | Description |
|------|-------------|
| `submit_report` | Submit a new vulnerability report to a program |
| `add_comment` | Add a comment to an existing report (respond to triage) |
| `close_report` | Withdraw/close one of your own reports |

### HAI drafts (requires `H1_ALLOW_DRAFTS=true`)

| Tool | Description |
|------|-------------|
| `create_report_draft` | Create a draft report (report intent) for HAI to review — never submitted to the program |
| `update_report_draft` | Replace a draft with a new one carrying the new description; returns immediately with the new ID — the old draft is kept, delete it with `delete_report_draft` once the new one is `ready_to_submit` (attachments are not carried over) |
| `delete_report_draft` | Delete a draft by ID (only before submission) |
| `get_report_draft` | Get a draft by ID; poll until HAI's jobs finish and state is `ready_to_submit` |
| `list_report_drafts` | List your HAI report drafts and their states |
| `upload_draft_attachments` | Upload files (screenshots, logs, PoC) to a draft; returns `{F<id>}` link and `!{F<id>}` embed syntax |
| `list_draft_attachments` | List attachments on a draft with their markdown references |
| `delete_draft_attachment` | Delete an attachment from a draft (only before submission) |

## Usage Examples

**Submit a report directly** (requires `H1_ALLOW_WRITES=true`):
```
Submit this SSRF finding to the uber program with critical severity. Here's my writeup: [paste]
```

**Respond to triage** (requires `H1_ALLOW_WRITES=true`):
```
Add a comment to report #2345678: "Here's the updated PoC with the new endpoint..."
```

**Get HAI feedback on a draft** (requires `H1_ALLOW_DRAFTS=true`):
```
Create a HAI draft for the uber program with this finding: [paste]. Poll it until it's ready_to_submit and show me HAI's improved write-up.
```

**Add screenshots to a draft** (requires `H1_ALLOW_DRAFTS=true`):
```
Upload poc-screenshot.png and request-log.txt to draft #1234, then embed the screenshot in the description.
```

**Draft a report matching your style:**
```
Find my resolved critical reports and use the same structure to draft a new report for this SSRF I found.
```

**Learn from triage conversations:**
```
Show me the triage conversation on report #2345678. What questions did they ask?
```

**Research what gets paid:**
```
Search disclosed reports on the uber program for SSRF — what did they pay?
```

**Check program details before hunting:**
```
Show me the uber program details — what are their response times?
```

**Analyze patterns:**
```
Analyze my report patterns — what severity gets resolved most?
```

## How It Works

- Connects to the [HackerOne Hacker API v1](https://api.hackerone.com/hacker-resources/) using your personal API token
- Runs locally over stdio — your credentials never leave your machine
- Read-only by default; write operations (submit reports, add comments, close reports) are only registered when `H1_ALLOW_WRITES=true`, and the HTTP layer refuses POST requests otherwise
- HAI report drafts (report intents) are gated separately behind `H1_ALLOW_DRAFTS=true` — drafts stay private and are never submitted to the program
- Auto-paginates programs, scope, and weakness endpoints so nothing gets silently truncated
- Uses server-side API filters where available (program, severity, state) for faster searches
- Built-in retry with exponential backoff for rate limit handling
- 60-second response cache to reduce redundant API calls

## License

MIT
