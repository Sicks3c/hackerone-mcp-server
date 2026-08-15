#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  searchReports,
  getReport,
  getReportActivities,
  getReportSummary,
  listPrograms,
  getProgramDetails,
  getProgramScope,
  getProgramScopeExclusions,
  getProgramWeaknesses,
  getEarnings,
  getPayouts,
  getBalance,
  submitReport,
  addComment,
  closeReport,
  searchDisclosedReports,
  listReportIntents,
  getReportIntent,
  createReportIntent,
  updateReportIntent,
  deleteReportIntent,
  submitReportIntent,
  listReportIntentAttachments,
  uploadReportIntentAttachments,
  deleteReportIntentAttachment,
} from "./h1client.js";

const server = new McpServer({
  name: "hackerone",
  version: "2.1.0",
});

// ── Shared response helpers ────────────────────────────────────────
type ToolResult = {
  content: { type: "text"; text: string }[];
  isError?: boolean;
};

async function run(fn: () => Promise<unknown>): Promise<ToolResult> {
  try {
    const result = await fn();
    return {
      content: [
        { type: "text" as const, text: JSON.stringify(result, null, 2) },
      ],
    };
  } catch (err: any) {
    return {
      content: [{ type: "text" as const, text: `Error: ${err.message}` }],
      isError: true,
    };
  }
}

const severityEnum = z.enum(["none", "low", "medium", "high", "critical"]);
const programHandle = z
  .string()
  .describe("Program handle (e.g. 'uber', 'github')");
const reportIntentId = z.string().describe("Report intent ID");

// ── Tool: search_reports ───────────────────────────────────────────
server.tool(
  "search_reports",
  "Search and list your HackerOne reports. Filter by keyword, program, severity, or state. Note: GET /hackers/me/reports has no server-side filters, so filtering walks paginated results client-side.",
  {
    query: z
      .string()
      .optional()
      .describe("Keyword search (e.g. 'SSRF', 'OAuth', 'PassRole', 'S3')"),
    program: z
      .string()
      .optional()
      .describe("Program handle to filter by (e.g. 'uber', 'amazon')"),
    severity: severityEnum.optional().describe("Filter by severity rating"),
    state: z
      .enum([
        "new",
        "triaged",
        "needs-more-info",
        "resolved",
        "not-applicable",
        "informative",
        "duplicate",
        "spam",
      ])
      .optional()
      .describe("Filter by report state"),
    page_size: z
      .number()
      .min(1)
      .max(100)
      .optional()
      .describe("Results per page (default 25)"),
    page_number: z
      .number()
      .optional()
      .describe("Page number (only applies when no filters are given)"),
    sort: z
      .string()
      .optional()
      .describe(
        "Client-side sort field (e.g. 'created_at' or '-created_at' for desc)"
      ),
  },
  async (params) => run(() => searchReports(params))
);

// ── Tool: get_report ───────────────────────────────────────────────
server.tool(
  "get_report",
  "Get the full details of a specific HackerOne report by ID: title, vulnerability details, impact, severity, full CVSS vector/score, CVE IDs, bounties, summaries, campaign, attachments, timestamps, and program info.",
  {
    report_id: z.string().describe("The HackerOne report ID"),
  },
  async ({ report_id }) => run(() => getReport(report_id))
);

// ── Tool: get_report_with_conversation ─────────────────────────────
server.tool(
  "get_report_with_conversation",
  "Get a report with its full triage conversation. Useful for understanding what questions triage asked, how you responded, and what led to resolution.",
  {
    report_id: z.string().describe("The HackerOne report ID"),
  },
  async ({ report_id }) => run(() => getReportSummary(report_id))
);

// ── Tool: get_report_activities ────────────────────────────────────
server.tool(
  "get_report_activities",
  "Get the activity timeline of a report: comments, state changes, bounty awards, triage responses, and activity attachments.",
  {
    report_id: z.string().describe("The HackerOne report ID"),
    page_size: z
      .number()
      .min(1)
      .max(100)
      .optional()
      .describe("Number of activities to return (default 50)"),
  },
  async ({ report_id, page_size }) =>
    run(() => getReportActivities(report_id, page_size))
);

// ── Tool: list_programs ────────────────────────────────────────────
server.tool(
  "list_programs",
  "List bug bounty programs you have access to on HackerOne. Auto-paginates to return all programs.",
  {
    page_size: z
      .number()
      .min(1)
      .max(1000)
      .optional()
      .describe("Max programs to return (default: all)"),
  },
  async ({ page_size }) => run(() => listPrograms(page_size))
);

// ── Tool: get_program_details ──────────────────────────────────────
server.tool(
  "get_program_details",
  "Get detailed info about a single program: policy, currency, response times, bounty splitting, safe harbor, submission state, and your own stats on that program.",
  {
    program_handle: programHandle,
  },
  async ({ program_handle }) => run(() => getProgramDetails(program_handle))
);

// ── Tool: get_program_scope ──────────────────────────────────────
server.tool(
  "get_program_scope",
  "Get the in-scope assets for a bug bounty program. Auto-paginates. Returns asset types, identifiers, bounty eligibility, severity caps, and CIA requirements. Supports incremental sync filters (id/created_at/updated_at greater-than).",
  {
    program_handle: programHandle,
    page_size: z
      .number()
      .min(1)
      .max(1000)
      .optional()
      .describe("Max scope items to return (default: all)"),
    id_gt: z
      .string()
      .optional()
      .describe("Only return scopes with an ID greater than this"),
    created_at_gt: z
      .string()
      .optional()
      .describe("Only return scopes created after this ISO 8601 timestamp"),
    updated_at_gt: z
      .string()
      .optional()
      .describe("Only return scopes updated after this ISO 8601 timestamp"),
  },
  async ({ program_handle, ...opts }) =>
    run(() => getProgramScope(program_handle, opts))
);

// ── Tool: get_program_scope_exclusions ─────────────────────────────
server.tool(
  "get_program_scope_exclusions",
  "Get a program's scope exclusions — report categories that are explicitly excluded from rewards. Check this before spending time on a class of bug.",
  {
    program_handle: programHandle,
    page_size: z
      .number()
      .min(1)
      .max(1000)
      .optional()
      .describe("Max exclusions to return (default: all)"),
  },
  async ({ program_handle, page_size }) =>
    run(() => getProgramScopeExclusions(program_handle, page_size))
);

// ── Tool: get_program_weaknesses ────────────────────────────────
server.tool(
  "get_program_weaknesses",
  "Get the accepted vulnerability/weakness types for a program. Auto-paginates. Use the returned `id` as weakness_id when submitting a report.",
  {
    program_handle: programHandle,
    page_size: z
      .number()
      .min(1)
      .max(1000)
      .optional()
      .describe("Max weaknesses to return (default: all)"),
  },
  async ({ program_handle, page_size }) =>
    run(() => getProgramWeaknesses(program_handle, page_size))
);

// ── Tool: get_earnings ──────────────────────────────────────────
server.tool(
  "get_earnings",
  "Get your bounty earnings history. Shows amounts, currency, dates, and which programs paid out.",
  {
    page_size: z
      .number()
      .min(1)
      .max(100)
      .optional()
      .describe("Number of earnings to return (default 100)"),
    page_number: z.number().min(1).optional().describe("Page number"),
  },
  async ({ page_size, page_number }) =>
    run(() => getEarnings(page_size, page_number))
);

// ── Tool: get_payouts ───────────────────────────────────────────
server.tool(
  "get_payouts",
  "Get your payout history — money actually sent to you. Shows amount, payout date, provider, reference, and status.",
  {
    page_size: z
      .number()
      .min(1)
      .max(100)
      .optional()
      .describe("Number of payouts to return (default 25)"),
    page_number: z.number().min(1).optional().describe("Page number"),
  },
  async ({ page_size, page_number }) =>
    run(() => getPayouts(page_size, page_number))
);

// ── Tool: get_balance ─────────────────────────────────────────────
server.tool(
  "get_balance",
  "Get your current unpaid bounty balance on HackerOne.",
  {},
  async () => run(() => getBalance())
);

// ── Tool: analyze_report_patterns ──────────────────────────────────
server.tool(
  "analyze_report_patterns",
  "Fetch your recent reports and analyze patterns: most common vulnerability types, severity distribution, resolution rates, and programs.",
  {
    page_size: z
      .number()
      .min(10)
      .max(100)
      .optional()
      .describe("Number of reports to analyze (default 100)"),
  },
  async ({ page_size }) =>
    run(async () => {
      const reports = await searchReports({
        page_size: page_size ?? 100,
        sort: "-created_at",
      });

      const severityCounts: Record<string, number> = {};
      const stateCounts: Record<string, number> = {};
      const programCounts: Record<string, number> = {};
      const weaknessCounts: Record<string, number> = {};

      for (const r of reports) {
        severityCounts[r.severity ?? "unknown"] =
          (severityCounts[r.severity ?? "unknown"] ?? 0) + 1;
        stateCounts[r.state ?? "unknown"] =
          (stateCounts[r.state ?? "unknown"] ?? 0) + 1;
        if (r.program)
          programCounts[r.program] = (programCounts[r.program] ?? 0) + 1;
        if (r.weakness)
          weaknessCounts[r.weakness] = (weaknessCounts[r.weakness] ?? 0) + 1;
      }

      const topN = (counts: Record<string, number>, key: string) =>
        Object.entries(counts)
          .sort(([, a], [, b]) => b - a)
          .slice(0, 10)
          .map(([name, count]) => ({ [key]: name, count }));

      return {
        total_reports_analyzed: reports.length,
        severity_distribution: severityCounts,
        state_distribution: stateCounts,
        top_programs: topN(programCounts, "program"),
        top_weakness_types: topN(weaknessCounts, "weakness"),
      };
    })
);

// ── Tool: submit_report ───────────────────────────────────────────
server.tool(
  "submit_report",
  "Submit a new vulnerability report to a HackerOne program. Returns the new report ID and URL. Use get_program_scope and get_program_weaknesses first to get the right scope/weakness IDs. For drafts with attachments, use the report_intent tools instead.",
  {
    program_handle: z
      .string()
      .describe("Program handle to submit to (e.g. 'uber')"),
    title: z.string().describe("Report title"),
    vulnerability_information: z
      .string()
      .describe(
        "Full vulnerability details in markdown — steps to reproduce, root cause, and proof of concept"
      ),
    impact: z
      .string()
      .optional()
      .describe("Impact statement — what an attacker can achieve"),
    severity_rating: severityEnum
      .optional()
      .describe("Suggested severity rating"),
    weakness_id: z
      .string()
      .optional()
      .describe(
        "Weakness/CWE ID from get_program_weaknesses (the numeric id field)"
      ),
    structured_scope_id: z
      .string()
      .optional()
      .describe("Scope asset ID from get_program_scope (the numeric id field)"),
  },
  async (params) => run(() => submitReport(params))
);

// ── Tool: add_comment ─────────────────────────────────────────────
server.tool(
  "add_comment",
  "Add a comment to an existing HackerOne report — respond to triage questions or provide additional information. (Uses an endpoint outside the documented Hacker API surface.)",
  {
    report_id: z.string().describe("The HackerOne report ID"),
    message: z.string().describe("Comment text (supports markdown)"),
    internal: z
      .boolean()
      .optional()
      .describe("If true, comment is only visible to the team (default false)"),
  },
  async ({ report_id, message, internal }) =>
    run(() => addComment(report_id, message, internal ?? false))
);

// ── Tool: close_report ────────────────────────────────────────────
server.tool(
  "close_report",
  "Withdraw/close one of your own HackerOne reports. (Uses an endpoint outside the documented Hacker API surface.)",
  {
    report_id: z.string().describe("The HackerOne report ID to close"),
    message: z
      .string()
      .optional()
      .describe("Reason for closing (default: 'Withdrawing this report.')"),
  },
  async ({ report_id, message }) => run(() => closeReport(report_id, message))
);

// ── Tool: list_report_intents ─────────────────────────────────────
server.tool(
  "list_report_intents",
  "List your report intents — draft reports that HackerOne analyzes (asset type, bug class, completeness) before you submit them.",
  {
    page_size: z
      .number()
      .min(1)
      .max(100)
      .optional()
      .describe("Results per page (default 25)"),
    page_number: z.number().min(1).optional().describe("Page number"),
  },
  async ({ page_size, page_number }) =>
    run(() => listReportIntents(page_size, page_number))
);

// ── Tool: get_report_intent ───────────────────────────────────────
server.tool(
  "get_report_intent",
  "Get a single report intent, including its state, analysis job status, metadata, and attachments. Check `state` is ready before submitting.",
  { report_intent_id: reportIntentId },
  async ({ report_intent_id }) => run(() => getReportIntent(report_intent_id))
);

// ── Tool: create_report_intent ────────────────────────────────────
server.tool(
  "create_report_intent",
  "Create a draft report (report intent) for a program. HackerOne runs analysis jobs on it; poll with get_report_intent, then call submit_report_intent to turn it into a real report.",
  {
    program_handle: z
      .string()
      .describe("Program handle to draft against (e.g. 'uber')"),
    title: z.string().describe("Draft report title"),
    description: z
      .string()
      .describe("Full vulnerability description in markdown"),
    bug_class: z
      .string()
      .optional()
      .describe("Bug class metadata (e.g. 'SSRF', 'XSS')"),
    vulnerable_url: z
      .string()
      .optional()
      .describe("Affected URL metadata"),
    vulnerable_parameter: z
      .string()
      .optional()
      .describe("Affected parameter metadata"),
    http_method: z
      .string()
      .optional()
      .describe("HTTP method metadata (e.g. 'GET', 'POST')"),
  },
  async ({
    program_handle,
    title,
    description,
    bug_class,
    vulnerable_url,
    vulnerable_parameter,
    http_method,
  }) =>
    run(() => {
      const metadata = Object.fromEntries(
        Object.entries({
          bug_class,
          vulnerable_url,
          vulnerable_parameter,
          http_method,
        }).filter(([, v]) => v !== undefined)
      );
      return createReportIntent({
        program_handle,
        title,
        description,
        metadata: Object.keys(metadata).length ? metadata : undefined,
      });
    })
);

// ── Tool: update_report_intent ────────────────────────────────────
server.tool(
  "update_report_intent",
  "Update a draft report intent's title, description, or metadata before submitting it.",
  {
    report_intent_id: reportIntentId,
    title: z.string().optional().describe("New title"),
    description: z.string().optional().describe("New description (markdown)"),
    bug_class: z.string().optional().describe("Bug class metadata"),
    vulnerable_url: z.string().optional().describe("Affected URL metadata"),
    vulnerable_parameter: z
      .string()
      .optional()
      .describe("Affected parameter metadata"),
    http_method: z.string().optional().describe("HTTP method metadata"),
  },
  async ({
    report_intent_id,
    title,
    description,
    bug_class,
    vulnerable_url,
    vulnerable_parameter,
    http_method,
  }) =>
    run(() => {
      const metadata = Object.fromEntries(
        Object.entries({
          bug_class,
          vulnerable_url,
          vulnerable_parameter,
          http_method,
        }).filter(([, v]) => v !== undefined)
      );
      return updateReportIntent(report_intent_id, {
        title,
        description,
        metadata: Object.keys(metadata).length ? metadata : undefined,
      });
    })
);

// ── Tool: submit_report_intent ────────────────────────────────────
server.tool(
  "submit_report_intent",
  "Submit a report intent, converting the draft (and its attachments) into a real HackerOne report.",
  { report_intent_id: reportIntentId },
  async ({ report_intent_id }) => run(() => submitReportIntent(report_intent_id))
);

// ── Tool: delete_report_intent ────────────────────────────────────
server.tool(
  "delete_report_intent",
  "Delete an unsubmitted report intent draft.",
  { report_intent_id: reportIntentId },
  async ({ report_intent_id }) => run(() => deleteReportIntent(report_intent_id))
);

// ── Tool: list_report_intent_attachments ──────────────────────────
server.tool(
  "list_report_intent_attachments",
  "List the attachments on a report intent draft.",
  { report_intent_id: reportIntentId },
  async ({ report_intent_id }) =>
    run(() => listReportIntentAttachments(report_intent_id))
);

// ── Tool: upload_report_intent_attachments ────────────────────────
server.tool(
  "upload_report_intent_attachments",
  "Upload local files (screenshots, PoC scripts, HTTP logs) as attachments on a report intent draft.",
  {
    report_intent_id: reportIntentId,
    file_paths: z
      .array(z.string())
      .min(1)
      .describe("Absolute paths of local files to upload"),
  },
  async ({ report_intent_id, file_paths }) =>
    run(() => uploadReportIntentAttachments(report_intent_id, file_paths))
);

// ── Tool: delete_report_intent_attachment ─────────────────────────
server.tool(
  "delete_report_intent_attachment",
  "Remove an attachment from a report intent draft. Returns the remaining attachments.",
  {
    report_intent_id: reportIntentId,
    attachment_id: z.string().describe("Attachment ID to remove"),
  },
  async ({ report_intent_id, attachment_id }) =>
    run(() => deleteReportIntentAttachment(report_intent_id, attachment_id))
);

// ── Tool: search_disclosed_reports ────────────────────────────────
server.tool(
  "search_disclosed_reports",
  "Search publicly disclosed HackerOne reports (hacktivity). Filters are compiled into the API's Lucene queryString, so they run server-side. Great for recon: what a program pays, prior art, and what counts as valid.",
  {
    program: z
      .string()
      .optional()
      .describe("Program handle to filter by (e.g. 'uber')"),
    query: z
      .string()
      .optional()
      .describe("Free-text search term (e.g. 'SSRF', 'IDOR')"),
    raw_query: z
      .string()
      .optional()
      .describe(
        "Raw Lucene query, overrides all other filters (e.g. 'severity_rating:critical AND team:\"uber\"')"
      ),
    severity: severityEnum.optional().describe("Filter by severity rating"),
    substate: z
      .string()
      .optional()
      .describe("Report substate (e.g. 'resolved', 'informative')"),
    cwe: z.string().optional().describe("CWE identifier (e.g. 'CWE-918')"),
    cve: z.string().optional().describe("CVE identifier (e.g. 'CVE-2024-1234')"),
    asset_type: z
      .string()
      .optional()
      .describe("Asset type (e.g. 'URL', 'CIDR', 'GOOGLE_PLAY_APP_ID')"),
    reporter: z.string().optional().describe("Reporter username"),
    min_bounty: z
      .number()
      .optional()
      .describe("Minimum total awarded amount"),
    disclosed_after: z
      .string()
      .optional()
      .describe("Only reports disclosed on/after this date (YYYY-MM-DD)"),
    has_collaboration: z
      .boolean()
      .optional()
      .describe("Filter for collaborative reports"),
    sort: z
      .enum([
        "latest_disclosable_activity_at",
        "-latest_disclosable_activity_at",
        "disclosed_at",
        "-disclosed_at",
        "total_awarded_amount",
        "-total_awarded_amount",
        "votes",
        "-votes",
      ])
      .optional()
      .describe(
        "Sort order (default '-latest_disclosable_activity_at'). Prefix '-' for descending."
      ),
    page_size: z
      .number()
      .min(1)
      .max(100)
      .optional()
      .describe("Number of results (default 25)"),
    page_number: z.number().min(1).optional().describe("Page number"),
  },
  async (params) => run(() => searchDisclosedReports(params))
);

// ── Start server ───────────────────────────────────────────────────
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("HackerOne MCP server running on stdio");
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
