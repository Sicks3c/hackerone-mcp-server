# HackerOne MCP Server

> **Disclaimer:** This is an unofficial, community-built project. It is not affiliated with, endorsed by, or maintained by HackerOne. "HackerOne" is a trademark of HackerOne, Inc. This project simply integrates with their publicly documented [Hacker API](https://api.hackerone.com/hacker-resources/).

MCP server that gives Claude Code (or any MCP client) full access to your HackerOne reports, programs, earnings, payouts, and scope data via the HackerOne API — including drafting reports as report intents, submitting them, and responding to triage.

## Setup

### Requirements

Node.js 20 or newer (the server uses the built-in `fetch`/`FormData`).

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
# You should see "hackerone" listed with 26 tools
```

## Tools

### Reports

| Tool | Description |
|------|-------------|
| `search_reports` | Search and filter your reports by keyword, program, severity, or state |
| `get_report` | Full report details: CVSS vector, CVE IDs, bounties, summaries, campaign, attachments |
| `get_report_with_conversation` | A report plus its triage conversation thread |
| `get_report_activities` | Activity timeline (comments, state changes, bounties, activity attachments) |
| `analyze_report_patterns` | Analyze your hunting patterns (severity distribution, top programs, weakness types) |
| `submit_report` | Submit a new vulnerability report to a program |
| `add_comment` | Add a comment to an existing report (respond to triage) |
| `close_report` | Withdraw/close one of your own reports |

### Report intents (drafts)

Report intents are HackerOne's draft-report workflow: you create a draft, attach files, HackerOne runs analysis jobs on it (asset type, bug class, completeness), and then you submit it as a real report.

| Tool | Description |
|------|-------------|
| `create_report_intent` | Create a draft report for a program, with optional bug-class/URL/parameter metadata |
| `list_report_intents` | List your drafts |
| `get_report_intent` | Get one draft with its `state`, analysis job status, and attachments |
| `update_report_intent` | Edit a draft's title, description, or metadata |
| `submit_report_intent` | Turn the draft (and its attachments) into a real report |
| `delete_report_intent` | Delete an unsubmitted draft |
| `list_report_intent_attachments` | List a draft's attachments |
| `upload_report_intent_attachments` | Upload local files (screenshots, PoC, HTTP logs) to a draft |
| `delete_report_intent_attachment` | Remove an attachment from a draft |

### Programs

| Tool | Description |
|------|-------------|
| `list_programs` | List all programs you have access to (auto-paginates) |
| `get_program_details` | Policy, currency, response times, safe harbor, and your own stats on the program |
| `get_program_scope` | All in-scope assets, with CIA requirements and incremental-sync filters (auto-paginates) |
| `get_program_scope_exclusions` | Report categories explicitly excluded from rewards |
| `get_program_weaknesses` | Accepted CWE/weakness types (auto-paginates) |

### Payments

| Tool | Description |
|------|-------------|
| `get_earnings` | Bounty earnings history (amounts, dates, programs) |
| `get_payouts` | Payout history — money actually sent to you (provider, reference, status) |
| `get_balance` | Current unpaid bounty balance |

### Recon

| Tool | Description |
|------|-------------|
| `search_disclosed_reports` | Search hacktivity by program, severity, CWE, CVE, asset type, reporter, minimum bounty, or disclosure date |

## Usage Examples

**Submit a report directly:**
```
Submit this SSRF finding to the uber program with critical severity. Here's my writeup: [paste]
```

**Draft with attachments, then submit:**
```
Create a report intent on the uber program for this IDOR, attach ~/poc/screenshot.png
and ~/poc/request.txt, then show me the analysis before submitting.
```

**Check what's excluded before hunting:**
```
Show me the uber program's scope exclusions and in-scope assets.
```

**Research what gets paid:**
```
Find disclosed SSRF reports (CWE-918) on uber that paid at least $1000, sorted by bounty.
```

**Sync only what changed:**
```
Show me uber scope items updated since 2026-06-01.
```

**Respond to triage:**
```
Add a comment to report #2345678: "Here's the updated PoC with the new endpoint..."
```

**Track money:**
```
Show my recent earnings, my payout history, and current balance.
```

## How It Works

- Connects to the [HackerOne Hacker API v1](https://api.hackerone.com/hacker-resources/) using your personal API token
- Runs locally over stdio — your credentials never leave your machine
- Auto-paginates programs, scope, exclusions, and weaknesses, following `links.next`
- Hacktivity filters compile into the API's Lucene `queryString`, so they run server-side
- Respects documented rate limits (reads 600/min, writes 25/20s, structured scopes 50/min) with retry, exponential backoff, and `Retry-After` handling
- 60-second response cache to reduce redundant API calls, invalidated on writes

### Notes on API coverage

- `search_reports` filters client-side. `GET /hackers/me/reports` documents only `page[number]`/`page[size]` — it has no server-side filters, and filter params sent to it are silently ignored.
- `add_comment` and `close_report` use `POST /hackers/reports/{id}/activities`, which is **not** part of the documented Hacker API surface. They work against the live platform today but may break without notice.
- There is no hacker-profile endpoint. `GET /hackers/me` returns 401 even for tokens that work elsewhere, so reputation/signal/impact are not available through the API.
- Undisclosed hacktivity entries omit `title`; for those, `hacktivity_summary` is the only description the API returns.

## License

MIT
