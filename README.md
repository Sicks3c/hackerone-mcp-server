# HackerOne MCP Server

> **Disclaimer:** This is an unofficial, community-built project. It is not affiliated with, endorsed by, or maintained by HackerOne. "HackerOne" is a trademark of HackerOne, Inc. This project simply integrates with their publicly documented [Hacker API](https://api.hackerone.com/hacker-resources/).

MCP server that gives Claude Code (or any MCP client) full access to your HackerOne reports, programs, earnings, and scope data via the HackerOne API — including submitting reports and responding to triage.

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
# You should see "hackerone" listed with 16 tools
```

## Tools

### Read

| Tool | Description |
|------|-------------|
| `search_reports` | Search and filter your reports by keyword, program, severity, or state |
| `get_report` | Get full report details including CVSS vector, bounty amounts, and attachments |
| `get_report_with_conversation` | Get a report with its triage conversation thread |
| `get_report_activities` | Get activity timeline (comments, state changes, bounties) |
| `list_programs` | List all bug bounty programs you have access to (auto-paginates) |
| `get_program_details` | Get single program info: policy, response times, metrics |
| `get_program_scope` | Get all in-scope assets for a program (auto-paginates) |
| `get_program_weaknesses` | Get accepted CWE/weakness types for a program (auto-paginates) |
| `get_earnings` | Get your bounty earnings history (amounts, dates, programs) |
| `get_hacker_profile` | Get your reputation, signal, impact, and rank |
| `get_balance` | Get your current unpaid bounty balance |
| `analyze_report_patterns` | Analyze your hunting patterns (severity distribution, top programs, weakness types) |
| `search_disclosed_reports` | Search publicly disclosed reports on hacktivity — great for recon and learning |

### Write

| Tool | Description |
|------|-------------|
| `submit_report` | Submit a new vulnerability report to a program |
| `add_comment` | Add a comment to an existing report (respond to triage) |
| `close_report` | Withdraw/close one of your own reports |

## Usage Examples

**Submit a report directly:**
```
Submit this SSRF finding to the uber program with critical severity. Here's my writeup: [paste]
```

**Respond to triage:**
```
Add a comment to report #2345678: "Here's the updated PoC with the new endpoint..."
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

**Check your stats:**
```
Show my hacker profile — what's my current reputation and signal?
```

**Track earnings:**
```
Show my recent bounty earnings and current balance
```

**Analyze patterns:**
```
Analyze my report patterns — what severity gets resolved most?
```

## How It Works

- Connects to the [HackerOne Hacker API v1](https://api.hackerone.com/hacker-resources/) using your personal API token
- Runs locally over stdio — your credentials never leave your machine
- Supports both read and write operations (submit reports, add comments, close reports)
- Auto-paginates programs, scope, and weakness endpoints so nothing gets silently truncated
- Uses server-side API filters where available (program, severity, state) for faster searches
- Built-in retry with exponential backoff for rate limit handling
- 60-second response cache to reduce redundant API calls

## License

MIT
