#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z, type ZodRawShape } from "zod";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import * as h1 from "./h1client.js";

const server = new McpServer({ name: "hackerone", version: "3.0.0" });

// The SDK types the callback's args from the schema shape, which TypeScript
// cannot resolve through a generic wrapper. Args are validated by the schema
// at runtime regardless, so bind one concrete signature here.
type RegisterTool = (
  name: string,
  description: string,
  schema: ZodRawShape,
  cb: (params: any) => Promise<CallToolResult>
) => void;

const register = server.tool.bind(server) as unknown as RegisterTool;

// Every tool serialises its result the same way and reports failures as
// tool errors rather than throwing out of the server.
function tool(
  name: string,
  description: string,
  schema: ZodRawShape,
  handler: (params: any) => Promise<unknown>
): void {
  register(name, description, schema, async (params: any): Promise<CallToolResult> => {
    try {
      const result = await handler(params);
      return {
        content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
        isError: false,
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  });
}

const severity = z.enum(["none", "low", "medium", "high", "critical"]);
const programHandle = z.string().describe("Program handle (e.g. 'uber', 'github')");

// ══ Reports ═══════════════════════════════════════════════════════
tool(
  "search_reports",
  "Search and list your HackerOne reports. Filter by keyword, program, severity, or state. " +
    "Note: HackerOne's report list endpoint ignores server-side filters, so any filter here " +
    "paginates your full report history and filters locally — slower, but actually correct.",
  {
    query: z.string().optional().describe("Keyword matched against title, vulnerability info, and asset"),
    program: z.string().optional().describe("Program handle to filter by"),
    severity: severity.optional().describe("Filter by severity rating"),
    state: z
      .enum(["new", "triaged", "needs-more-info", "resolved", "not-applicable", "informative", "duplicate", "spam"])
      .optional()
      .describe("Filter by report state"),
    page_size: z.number().min(1).max(100).optional().describe("Results to return (default 25)"),
    page_number: z.number().optional().describe("Page number; only used when no filter is set"),
    sort: z.string().optional().describe("Sort field, e.g. '-created_at' for newest first"),
    max_pages: z.number().min(1).max(50).optional().describe("Cap pages scanned when filtering (default 20)"),
  },
  (p) => h1.searchReports(p)
);

tool(
  "get_report",
  "Get full details of a HackerOne report: vulnerability info, impact, severity, CVSS vector, bounty, attachments, and program.",
  { report_id: z.string().describe("The HackerOne report ID") },
  ({ report_id }) => h1.getReport(report_id)
);

tool(
  "get_report_with_conversation",
  "Get a report plus its full triage conversation — what triage asked, how you answered, and what led to resolution.",
  { report_id: z.string().describe("The HackerOne report ID") },
  ({ report_id }) => h1.getReportSummary(report_id)
);

tool(
  "get_report_activities",
  "Get a report's activity timeline: comments, state changes, bounty awards, and triage responses.",
  {
    report_id: z.string().describe("The HackerOne report ID"),
    page_size: z.number().min(1).max(100).optional(),
  },
  ({ report_id, page_size }) => h1.getReportActivities(report_id, page_size)
);

tool(
  "analyze_report_patterns",
  "Analyse your recent reports: severity distribution, states, top programs and assets. " +
    "Weakness types require one extra request per report, so they are opt-in.",
  {
    page_size: z.number().min(10).max(100).optional().describe("Reports to analyse (default 100)"),
    include_weaknesses: z
      .boolean()
      .optional()
      .describe("Fetch each report individually to tally CWE types (slow)"),
  },
  (p) => h1.analyzeReportPatterns(p)
);

// ══ Programs ══════════════════════════════════════════════════════
tool(
  "list_programs",
  "List bug bounty programs you have access to. Auto-paginates.",
  { page_size: z.number().min(1).max(1000).optional().describe("Max to return (default: all)") },
  ({ page_size }) => h1.listPrograms(page_size)
);

tool(
  "get_program_details",
  "Get a program's policy, response metrics, submission state, and bounty splitting settings.",
  { program_handle: programHandle },
  ({ program_handle }) => h1.getProgramDetails(program_handle)
);

tool(
  "get_program_scope",
  "Get a program's in-scope assets: types, identifiers, bounty eligibility, and severity caps. Auto-paginates.",
  {
    program_handle: programHandle,
    page_size: z.number().min(1).max(1000).optional().describe("Max to return (default: all)"),
  },
  ({ program_handle, page_size }) => h1.getProgramScope(program_handle, page_size)
);

tool(
  "get_scope_changes",
  "List scope assets added or changed since a date — server-side filtered. Use this to spot newly in-scope attack surface.",
  {
    program_handle: programHandle,
    since: z.string().describe("ISO-8601 date, e.g. '2026-01-01' or '2026-01-01T00:00:00+00:00'"),
    field: z
      .enum(["updated_at", "created_at"])
      .optional()
      .describe("Compare against last update (default) or original creation"),
  },
  ({ program_handle, since, field }) => h1.getScopeChanges(program_handle, since, field)
);

tool(
  "get_program_weaknesses",
  "Get the weakness/CWE types a program accepts. Auto-paginates. Use the returned id as weakness_id when drafting.",
  {
    program_handle: programHandle,
    page_size: z.number().min(1).max(1000).optional(),
  },
  ({ program_handle, page_size }) => h1.getProgramWeaknesses(program_handle, page_size)
);

tool(
  "get_scope_exclusions",
  "Get report categories a program excludes from rewards, beyond the standard ineligible findings. Check before investing time in a finding.",
  { program_handle: programHandle },
  ({ program_handle }) => h1.getScopeExclusions(program_handle)
);

// ══ Hacktivity ════════════════════════════════════════════════════
tool(
  "search_disclosed_reports",
  "Search publicly disclosed reports (hacktivity) using HackerOne's Lucene query engine. " +
    "Useful for prior art, seeing what a program pays for, and calibrating severity.",
  {
    program: z.string().optional().describe("Program handle, e.g. 'stripe'"),
    query: z
      .string()
      .optional()
      .describe("Free text, or raw Lucene (e.g. 'SSRF AND cve_ids:CVE-2024-1234')"),
    severity: severity.optional().describe("Filter by severity rating"),
    substate: z
      .enum(["resolved", "informative", "duplicate", "not-applicable", "spam"])
      .optional()
      .describe("Filter by final report state"),
    reporter: z.string().optional().describe("Filter by reporter username"),
    min_bounty: z.number().optional().describe("Only reports awarding more than this amount"),
    disclosed_only: z.boolean().optional().describe("Exclude undisclosed activity entries"),
    sort: z
      .enum([
        "-latest_disclosable_activity_at",
        "latest_disclosable_activity_at",
        "-disclosed_at",
        "disclosed_at",
        "-total_awarded_amount",
        "total_awarded_amount",
        "-votes",
        "votes",
      ])
      .optional()
      .describe("Sort order; '-' prefix is descending"),
    page_size: z.number().min(1).max(100).optional().describe("Results (default 25)"),
  },
  (p) => h1.searchDisclosedReports(p)
);

// ══ Validation ════════════════════════════════════════════════════
tool(
  "validate_report",
  "Check a report you have drafted against the program's live scope, accepted weaknesses, and reward " +
    "exclusions before filing it. Stateless — pass the fields you plan to submit; nothing is stored or sent. " +
    "Reports blocking errors separately from advisory warnings.",
  {
    program_handle: programHandle,
    title: z.string().optional(),
    vulnerability_information: z.string().optional(),
    impact: z.string().optional(),
    severity_rating: severity.optional(),
    weakness_id: z.string().optional().describe("Weakness id from get_program_weaknesses"),
    structured_scope_id: z.string().optional().describe("Asset id from get_program_scope"),
  },
  (p) => h1.validateReport(p)
);


// ══ Report intents (HackerOne-side drafts) ════════════════════════
tool(
  "create_report_intent",
  "Save a draft report on HackerOne. HackerOne's AI assistant rewrites your description into its own report " +
    "template and generates the title, so you cannot set the title, severity, weakness or scope here — only the " +
    "description. Waits for that assistant job to finish before returning. Creates and updates are heavily " +
    "rate-limited (~4 per 10 minutes), so compose the text before calling rather than iterating through this tool.",
  {
    program_handle: programHandle,
    description: z.string().describe("Vulnerability details in markdown; will be rewritten by HackerOne"),
    wait: z
      .boolean()
      .optional()
      .describe("Wait for HackerOne's assistant to finish reformatting (default true)"),
  },
  (p) => h1.createReportIntent(p)
);

tool("list_report_intents", "List your HackerOne report intents and their states.", {}, () =>
  h1.listReportIntents()
);

tool("get_report_intent", "Get one report intent by id.", { id: z.string() }, ({ id }) =>
  h1.getReportIntent(id)
);

tool(
  "update_report_intent",
  "Replace a report intent's description. Description is the only editable field — title is generated by HackerOne. " +
    "Waits for their assistant to finish reprocessing before returning, so the result is not stale.",
  {
    id: z.string().describe("Report intent id"),
    description: z.string().describe("New vulnerability description in markdown"),
  },
  ({ id, description }) => h1.updateReportIntent(id, description)
);

tool("delete_report_intent", "Delete a report intent.", { id: z.string() }, ({ id }) =>
  h1.deleteReportIntent(id)
);

tool(
  "wait_for_intent_ready",
  "Poll a report intent until HackerOne's assistant job finishes and the state settles.",
  {
    id: z.string().describe("Report intent id"),
    timeout_ms: z.number().min(1000).max(300000).optional().describe("Give up after this long (default 60s)"),
  },
  ({ id, timeout_ms }) => h1.waitForIntentReady(id, timeout_ms)
);

tool(
  "submit_report_intent",
  "Convert a report intent into a real submitted report. IRREVERSIBLE. " +
    "Requires confirm=true, which you may only pass after the user has explicitly approved this exact submission.",
  {
    id: z.string().describe("Report intent id"),
    confirm: z.boolean().describe("Must be true. Only set after explicit user approval."),
  },
  ({ id, confirm }) => h1.submitReportIntent(id, confirm)
);

tool("list_intent_attachments", "List files attached to a report intent.", { id: z.string() }, ({ id }) =>
  h1.listIntentAttachments(id)
);

tool(
  "upload_intent_attachments",
  "Upload local files (screenshots, PoC scripts, HTTP logs) to a report intent.",
  {
    id: z.string().describe("Report intent id"),
    file_paths: z.array(z.string()).min(1).describe("Absolute paths of files to upload"),
  },
  ({ id, file_paths }) => h1.uploadIntentAttachments(id, file_paths)
);

tool(
  "delete_intent_attachment",
  "Remove one attachment from a report intent.",
  { id: z.string().describe("Report intent id"), attachment_id: z.string() },
  ({ id, attachment_id }) => h1.deleteIntentAttachment(id, attachment_id)
);

// ══ Direct writes ═════════════════════════════════════════════════
tool(
  "submit_report",
  "Submit a report to HackerOne directly, bypassing the draft workflow. IRREVERSIBLE. " +
    "Run validate_report first to catch out-of-scope assets and unaccepted weaknesses. " +
    "Requires confirm=true, which you may only pass after explicit user approval.",
  {
    program_handle: programHandle,
    title: z.string().describe("Report title"),
    vulnerability_information: z.string().describe("Full details in markdown"),
    impact: z.string().describe("What an attacker achieves (required by HackerOne)"),
    severity_rating: severity.optional(),
    weakness_id: z.string().optional().describe("Weakness id from get_program_weaknesses"),
    structured_scope_id: z.string().optional().describe("Asset id from get_program_scope"),
    confirm: z.boolean().describe("Must be true. Only set after explicit user approval."),
  },
  ({ confirm, ...opts }) => {
    if (!confirm) {
      throw new Error(
        `submit_report files a real report to '${opts.program_handle}' and cannot be undone. ` +
          `Re-run with confirm=true once the user has explicitly approved it.`
      );
    }
    return h1.submitReport(opts);
  }
);

tool(
  "add_comment",
  "Add a comment to one of your reports — respond to triage questions or supply more information.",
  {
    report_id: z.string(),
    message: z.string().describe("Comment text (markdown supported)"),
    internal: z.boolean().optional().describe("Team-only comment (default false)"),
  },
  ({ report_id, message, internal }) => h1.addComment(report_id, message, internal ?? false)
);

tool(
  "close_report",
  "Withdraw one of your own reports with an optional message.",
  { report_id: z.string(), message: z.string().optional().describe("Reason for closing") },
  ({ report_id, message }) => h1.closeReport(report_id, message)
);

// ══ Account ═══════════════════════════════════════════════════════
tool(
  "get_earnings",
  "Your bounty earnings history: amounts, currency, dates, and paying programs.",
  { page_size: z.number().min(1).max(100).optional() },
  ({ page_size }) => h1.getEarnings(page_size)
);

tool(
  "get_payouts",
  "Your payout transactions: amount, provider, reference, and status.",
  { page_size: z.number().min(1).max(100).optional() },
  ({ page_size }) => h1.getPayouts(page_size)
);

tool("get_balance", "Your current unpaid bounty balance.", {}, () => h1.getBalance());

tool(
  "get_hacker_profile",
  "Your hacker profile: username, reputation, signal, and account info.",
  {},
  () => h1.getHackerProfile()
);

// ══ Start ═════════════════════════════════════════════════════════
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("HackerOne MCP server running on stdio");
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
