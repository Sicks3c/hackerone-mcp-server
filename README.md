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
# You should see "hackerone" listed with 30 tools
```

## Drafting a report

HackerOne's own draft mechanism is called a **report intent**. Create one, review
it, then submit it as a real report — or delete it. Nothing is filed until you
explicitly approve it.

```
create_report_intent  →  (review)  →  submit_report_intent(confirm: true)
```

This server does not store drafts for you. Keep working copies wherever you
like — a scratch file, the conversation — and push one to HackerOne when it is
ready to be saved against the program.

Three things about intents are worth knowing before you use them, all verified
against the live API:

- **You cannot set the title.** HackerOne's AI assistant generates it, and
  rejects the attribute outright if you try.
- **`description` is the only editable field.** Severity, weakness and scope
  cannot be attached to an intent at all — they are set when the report is
  filed, not while it is a draft.
- **Writes are asynchronous and rewrite your prose.** Creating or updating an
  intent queues an assistant job that reformats your description into
  HackerOne's report template. The API response comes back *before* that job
  runs, so it is already stale. `create_report_intent` and
  `update_report_intent` wait for the job to settle before returning;
  `wait_for_intent_ready` does it on demand.

Creates and updates are also heavily rate-limited — roughly 4 per 10 minutes,
undocumented — so compose your description before calling rather than iterating
through the API. Attachments are not rate-limited the same way:
`upload_intent_attachments` takes screenshots, PoC scripts, or HTTP logs.

### Checking a report before you file it

`validate_report` is stateless: pass the fields you intend to submit and it
checks them against the program's live data. Nothing is stored or sent.

It reports blocking errors separately from advisory warnings — whether the
program is even accepting submissions, whether the asset is in scope and
bounty-eligible, whether the severity exceeds the asset's cap, whether the
weakness is one the program accepts, and which report categories the program
excludes from rewards.

Note that intents cannot carry a weakness or scope id, so validating those is
only meaningful on the way to `submit_report`.

## Tools

### Report intents (HackerOne-side drafts)

| Tool | Description |
|------|-------------|
| `create_report_intent` | Save a draft on HackerOne; waits for their assistant to reformat it |
| `list_report_intents` | List your drafts and their states |
| `get_report_intent` | Get one draft by id |
| `update_report_intent` | Replace a draft's description and wait for reprocessing |
| `wait_for_intent_ready` | Poll until the assistant job settles |
| `delete_report_intent` | Delete a draft |
| `submit_report_intent` | File a draft as a real report — irreversible, requires `confirm: true` |
| `list_intent_attachments` | List files attached to a draft |
| `upload_intent_attachments` | Upload screenshots, PoC scripts, or HTTP logs |
| `delete_intent_attachment` | Remove one attachment |

### Read

| Tool | Description |
|------|-------------|
| `validate_report` | Check a report against live scope, weaknesses, and reward exclusions |
| `search_reports` | Search and filter your reports by keyword, program, severity, or state |
| `get_report` | Get full report details including CVSS vector, bounty amounts, and attachments |
| `get_report_with_conversation` | Get a report with its triage conversation thread |
| `get_report_activities` | Get activity timeline (comments, state changes, bounties) |
| `list_programs` | List all bug bounty programs you have access to (auto-paginates) |
| `get_program_details` | Get single program info: policy, response times, metrics |
| `get_program_scope` | Get all in-scope assets for a program (auto-paginates) |
| `get_scope_changes` | List assets added or changed since a date — server-side filtered |
| `get_program_weaknesses` | Get accepted CWE/weakness types for a program (auto-paginates) |
| `get_scope_exclusions` | Get report categories a program excludes from rewards |
| `search_disclosed_reports` | Search hacktivity with HackerOne's Lucene query engine |
| `analyze_report_patterns` | Analyze your hunting patterns (severity, states, programs, assets) |
| `get_earnings` | Get your bounty earnings history (amounts, dates, programs) |
| `get_payouts` | Get your payout transactions (provider, reference, status) |
| `get_balance` | Get your current unpaid bounty balance |
| `get_hacker_profile` | Get your username, reputation, and signal |

### Write

| Tool | Description |
|------|-------------|
| `submit_report` | Submit a report directly — irreversible, requires `confirm: true` |
| `add_comment` | Add a comment to an existing report (respond to triage) |
| `close_report` | Withdraw/close one of your own reports |

## Usage Examples

**Save a draft on HackerOne:**
```
Save this SSRF writeup as a draft on the uber program, then show me how they reformatted it.
```

**Check a finding before writing it up:**
```
Is my.example.com in scope for uber, and do they accept SSRF? Anything excluded from rewards?
```

**Find newly in-scope attack surface:**
```
What's been added to the uber program's scope since June?
```

**Research what gets paid:**
```
Search disclosed reports for SSRF that paid over $5000, highest first.
```

**Learn from triage conversations:**
```
Show me the triage conversation on report #2345678. What questions did they ask?
```

**Respond to triage:**
```
Add a comment to report #2345678: "Here's the updated PoC with the new endpoint..."
```

**Analyze patterns:**
```
Analyze my report patterns — what severity gets resolved most?
```

**Track earnings:**
```
Show my recent bounty earnings, payouts, and current balance
```

## How It Works

- Connects to the [HackerOne Hacker API v1](https://api.hackerone.com/hacker-resources/) using your personal API token
- Runs locally over stdio — your credentials never leave your machine
- Only `submit_report` and `submit_report_intent` can file a report, and both require explicit confirmation
- Auto-paginates by following the API's own `links.next`, so nothing is silently truncated
- 60-second response cache on reads, invalidated on writes

### Working around the API's rough edges

Several Hacker API endpoints accept parameters they then ignore. Rather than
pass them through and return quietly wrong results, this server works around
them:

- **`/hackers/me/reports` ignores every `filter[...]` and `sort` parameter.**
  Verified against the live API — identical results with and without them. Any
  filter on `search_reports` therefore paginates your full report history and
  filters locally. Slower, but correct.
- **The report list endpoint omits severity, bounty, and weakness.** Severity is
  only available through a relationship, and bounty and weakness not at all, so
  `search_reports` returns what is genuinely there instead of null columns.
  `analyze_report_patterns` takes `include_weaknesses` to fetch them per report.
- **Hacktivity ignores `filter[...]`** and takes a Lucene `queryString` instead;
  `search_disclosed_reports` builds one from its arguments.
- **`POST /hackers/reports` takes `weakness_id` and `structured_scope_id` as flat
  attributes,** not relationships. Sending them as relationships silently drops
  them, filing the report with no CWE and no asset.
- **Report intent writes are asynchronous.** The response predates the assistant
  job that rewrites your description, so this server waits for the job to settle
  rather than handing back data it knows is stale.
- **Rate limits are enforced client-side.** HackerOne documents 600 reads/min and
  25 writes/20s, plus 50/min on structured scopes. Report intent creates and
  updates have a much tighter undocumented cap: roughly 4 per 10 minutes, and
  retrying during a lockout appears to extend it. Those requests are refused
  locally with a clear message rather than sent, and a server-side 429 there is
  surfaced immediately instead of retried. Errors carry the status, endpoint,
  and response body.

## License

MIT
