# HackerOne MCP Server

MCP server that gives Claude Code (or any MCP client) live access to your HackerOne reports, programs, earnings, and scope data via the official HackerOne API.

## Setup

### 1. Get your HackerOne API token

Go to **HackerOne > Settings > API Token** and generate one.

### 2. Install and build

```bash
git clone https://github.com/sicksec/hackerone-mcp-server.git
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
# You should see "hackerone" listed with 9 tools
```

## Tools

| Tool | Description |
|------|-------------|
| `search_reports` | Search and filter your reports by keyword, program, severity, or state |
| `get_report` | Get full report details by ID (title, vuln info, severity, timestamps) |
| `get_report_with_conversation` | Get a report with its triage conversation thread |
| `get_report_activities` | Get activity timeline (comments, state changes, bounties) |
| `list_programs` | List bug bounty programs you have access to |
| `analyze_report_patterns` | Analyze your hunting patterns (severity distribution, top programs, weakness types) |
| `get_program_scope` | Get in-scope assets for a program (asset types, bounty eligibility, severity caps) |
| `get_program_weaknesses` | Get accepted CWE/weakness types for a program |
| `get_earnings` | Get your bounty earnings history (amounts, dates, programs) |

## Usage Examples

**Search reports by program:**
```
Search my reports for the ipc-h1c-aws-tokyo-2026 program
```

**Draft a report matching your style:**
```
Find my resolved critical reports and use the same structure to draft a new report for this SSRF I found.
```

**Learn from triage conversations:**
```
Show me the triage conversation on report #2345678. What questions did they ask?
```

**Check program scope before reporting:**
```
What assets are in scope for the uber program?
```

**Track earnings:**
```
Show my recent bounty earnings
```

**Analyze patterns:**
```
Analyze my report patterns — what severity gets resolved most?
```

## How It Works

- Connects to the [HackerOne Hacker API v1](https://api.hackerone.com/hacker-resources/) using your personal API token
- Runs locally over stdio — your credentials never leave your machine
- Read-only — cannot submit, modify, or delete reports
- Filtering (program, severity, state, keyword) is done client-side since the hacker API only supports pagination

## License

MIT
