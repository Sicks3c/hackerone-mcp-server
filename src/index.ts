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
  getProgramWeaknesses,
  submitReport,
  addComment,
  closeReport,
  createReportIntent,
  updateReportIntent,
  getReportIntent,
  listReportIntents,
  uploadReportIntentAttachments,
  getReportIntentAttachments,
  deleteReportIntentAttachment,
  searchDisclosedReports,
  WRITES_ENABLED,
  DRAFTS_ENABLED,
} from "./h1client.js";

const server = new McpServer({
  name: "hackerone",
  version: "3.0.1",
});

// ── Tool: search_reports ───────────────────────────────────────────
server.tool(
  "search_reports",
  "Search and list your HackerOne reports. Filter by keyword, program, severity, or state. Great for finding past reports to reference when drafting new ones.",
  {
    query: z
      .string()
      .optional()
      .describe(
        "Keyword search (e.g. 'SSRF', 'OAuth', 'PassRole', 'S3')"
      ),
    program: z
      .string()
      .optional()
      .describe("Program handle to filter by (e.g. 'uber', 'amazon')"),
    severity: z
      .enum(["none", "low", "medium", "high", "critical"])
      .optional()
      .describe("Filter by severity rating"),
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
    page_number: z.number().optional().describe("Page number for pagination"),
    sort: z
      .string()
      .optional()
      .describe(
        "Sort field (e.g. 'reports.created_at' or '-reports.created_at' for desc)"
      ),
  },
  async (params) => {
    try {
      const results = await searchReports(params);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(results, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: get_report ───────────────────────────────────────────────
server.tool(
  "get_report",
  "Get the full details of a specific HackerOne report by ID. Returns title, vulnerability details, impact, severity, full CVSS vector/score, attachments, timestamps, and program info.",
  {
    report_id: z.string().describe("The HackerOne report ID"),
  },
  async ({ report_id }) => {
    try {
      const report = await getReport(report_id);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(report, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: get_report_with_conversation ─────────────────────────────
server.tool(
  "get_report_with_conversation",
  "Get a report with its full triage conversation. Useful for understanding what questions triage asked, how you responded, and what led to resolution. Great for learning what works.",
  {
    report_id: z.string().describe("The HackerOne report ID"),
  },
  async ({ report_id }) => {
    try {
      const summary = await getReportSummary(report_id);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(summary, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: get_report_activities ────────────────────────────────────
server.tool(
  "get_report_activities",
  "Get the activity timeline of a report: comments, state changes, bounty awards, and triage responses.",
  {
    report_id: z.string().describe("The HackerOne report ID"),
    page_size: z
      .number()
      .min(1)
      .max(100)
      .optional()
      .describe("Number of activities to return (default 50)"),
  },
  async ({ report_id, page_size }) => {
    try {
      const activities = await getReportActivities(report_id, page_size);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(activities, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
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
  async ({ page_size }) => {
    try {
      const programs = await listPrograms(page_size);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(programs, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: get_program_details ──────────────────────────────────────
server.tool(
  "get_program_details",
  "Get detailed info about a single program: policy, response times, metrics, bounty splitting, and submission state.",
  {
    program_handle: z
      .string()
      .describe("Program handle (e.g. 'uber', 'github')"),
  },
  async ({ program_handle }) => {
    try {
      const details = await getProgramDetails(program_handle);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(details, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: analyze_report_patterns ──────────────────────────────────
server.tool(
  "analyze_report_patterns",
  "Fetch your recent reports and analyze patterns: most common vulnerability types, severity distribution, resolution rates, and programs. Useful for understanding your hunting profile.",
  {
    page_size: z
      .number()
      .min(10)
      .max(100)
      .optional()
      .describe("Number of reports to analyze (default 100)"),
  },
  async ({ page_size }) => {
    try {
      const reports = await searchReports({
        page_size: page_size ?? 100,
        sort: "-reports.created_at",
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

      const analysis = {
        total_reports_analyzed: reports.length,
        severity_distribution: severityCounts,
        state_distribution: stateCounts,
        top_programs: Object.entries(programCounts)
          .sort(([, a], [, b]) => b - a)
          .slice(0, 10)
          .map(([prog, count]) => ({ program: prog, count })),
        top_weakness_types: Object.entries(weaknessCounts)
          .sort(([, a], [, b]) => b - a)
          .slice(0, 10)
          .map(([weakness, count]) => ({ weakness, count })),
      };

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(analysis, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: get_program_scope ──────────────────────────────────────
server.tool(
  "get_program_scope",
  "Get the in-scope assets for a bug bounty program. Auto-paginates to return all scope items. Returns asset types, identifiers, bounty eligibility, and severity caps.",
  {
    program_handle: z
      .string()
      .describe("Program handle (e.g. 'uber', 'ipc-h1c-aws-tokyo-2026')"),
    page_size: z
      .number()
      .min(1)
      .max(1000)
      .optional()
      .describe("Max scope items to return (default: all)"),
  },
  async ({ program_handle, page_size }) => {
    try {
      const scope = await getProgramScope(program_handle, page_size);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(scope, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: get_program_weaknesses ────────────────────────────────
server.tool(
  "get_program_weaknesses",
  "Get the accepted vulnerability/weakness types for a program. Auto-paginates. Helps frame reports using the right CWE categories the program cares about.",
  {
    program_handle: z
      .string()
      .describe("Program handle (e.g. 'uber', 'ipc-h1c-aws-tokyo-2026')"),
    page_size: z
      .number()
      .min(1)
      .max(1000)
      .optional()
      .describe("Max weaknesses to return (default: all)"),
  },
  async ({ program_handle, page_size }) => {
    try {
      const weaknesses = await getProgramWeaknesses(program_handle, page_size);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(weaknesses, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ── Write tools (only registered when H1_ALLOW_WRITES=true) ───────
if (WRITES_ENABLED) {
// ── Tool: submit_report ───────────────────────────────────────────
server.tool(
  "submit_report",
  "Submit a new vulnerability report to a HackerOne program. Returns the new report ID and URL. Use get_program_scope and get_program_weaknesses first to get the right scope/weakness IDs.",
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
    severity_rating: z
      .enum(["none", "low", "medium", "high", "critical"])
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
      .describe(
        "Scope asset ID from get_program_scope (the numeric id field)"
      ),
  },
  async (params) => {
    try {
      const result = await submitReport(params);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: add_comment ─────────────────────────────────────────────
server.tool(
  "add_comment",
  "Add a comment to an existing HackerOne report. Use this to respond to triage questions or provide additional information.",
  {
    report_id: z.string().describe("The HackerOne report ID"),
    message: z.string().describe("Comment text (supports markdown)"),
    internal: z
      .boolean()
      .optional()
      .describe("If true, comment is only visible to the team (default false)"),
  },
  async ({ report_id, message, internal }) => {
    try {
      const result = await addComment(report_id, message, internal ?? false);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: close_report ────────────────────────────────────────────
server.tool(
  "close_report",
  "Withdraw/close one of your own HackerOne reports. Sends a close request with an optional message.",
  {
    report_id: z.string().describe("The HackerOne report ID to close"),
    message: z
      .string()
      .optional()
      .describe("Reason for closing (default: 'Withdrawing this report.')"),
  },
  async ({ report_id, message }) => {
    try {
      const result = await closeReport(report_id, message);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ── End of write tools ────────────────────────────────────────────
}

// ── HAI draft tools (only registered when H1_ALLOW_DRAFTS=true) ───
if (DRAFTS_ENABLED) {
// ── Tool: create_report_draft ─────────────────────────────────────
server.tool(
  "create_report_draft",
  "Create a draft report (report intent) reviewed by HAI, HackerOne's Report Assistant. Nothing is submitted to the program — the draft stays private to you. HAI analyzes the description and produces an improved title and write-up. Poll with get_report_draft until state is 'ready_to_submit'. Requires the program to have Report Assistant enabled. Attachments can be added with upload_draft_attachments; reference them in the description with {F<id>} (link) or !{F<id>} (embedded image).",
  {
    program_handle: z
      .string()
      .describe("Program handle for the draft (e.g. 'uber')"),
    description: z
      .string()
      .describe(
        "Everything you know about the vulnerability: summary, steps to reproduce, impact, PoC details. The more detail, the better HAI's draft."
      ),
  },
  async ({ program_handle, description }) => {
    try {
      const result = await createReportIntent(program_handle, description);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: update_report_draft ─────────────────────────────────────
server.tool(
  "update_report_draft",
  "Replace a HAI report draft (report intent) with a new one carrying the new description: fetches the old draft, creates a new draft for the same program, waits until HAI finishes (state 'ready_to_submit'), and only then deletes the old draft. If the new draft is not ready within the timeout, the old draft is kept and both IDs are returned. The title is re-generated by HAI. Attachments are NOT carried over — re-upload them to the new draft and update any {F<id>} references in the description.",
  {
    draft_id: z.string().describe("The report intent (draft) ID"),
    description: z
      .string()
      .describe("The new description — replaces the existing one entirely."),
  },
  async ({ draft_id, description }) => {
    try {
      const result = await updateReportIntent(draft_id, description);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: get_report_draft ────────────────────────────────────────
server.tool(
  "get_report_draft",
  "Get a HAI report draft (report intent) by ID. Use this to poll after create_report_draft: check job_status_by_type until HAI's jobs finish and state becomes 'ready_to_submit'.",
  {
    draft_id: z.string().describe("The report intent (draft) ID"),
  },
  async ({ draft_id }) => {
    try {
      const result = await getReportIntent(draft_id);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: list_report_drafts ──────────────────────────────────────
server.tool(
  "list_report_drafts",
  "List your HAI report drafts (report intents) with their state and HAI job statuses.",
  {},
  async () => {
    try {
      const results = await listReportIntents();
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(results, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: upload_draft_attachments ────────────────────────────────
server.tool(
  "upload_draft_attachments",
  "Upload one or more files (screenshots, logs, PoC files) to a HAI report draft. The draft must not be submitted yet. Each returned attachment includes a markdown_reference ({F<id>}) to link it in text and a markdown_embed (!{F<id>}) to embed an image inline. Reference uploaded attachments in the draft description or in the eventual report body.",
  {
    draft_id: z.string().describe("The report intent (draft) ID"),
    file_paths: z
      .array(z.string())
      .min(1)
      .describe("Absolute paths of local files to upload (images, logs, etc.)"),
  },
  async ({ draft_id, file_paths }) => {
    try {
      const result = await uploadReportIntentAttachments(draft_id, file_paths);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: list_draft_attachments ──────────────────────────────────
server.tool(
  "list_draft_attachments",
  "List all attachments on a HAI report draft, with their markdown reference ({F<id>}) and embed (!{F<id>}) syntax.",
  {
    draft_id: z.string().describe("The report intent (draft) ID"),
  },
  async ({ draft_id }) => {
    try {
      const result = await getReportIntentAttachments(draft_id);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: delete_draft_attachment ─────────────────────────────────
server.tool(
  "delete_draft_attachment",
  "Delete an attachment from a HAI report draft. Irreversible; only possible while the draft has not been submitted.",
  {
    draft_id: z.string().describe("The report intent (draft) ID"),
    attachment_id: z.string().describe("The attachment ID to delete"),
  },
  async ({ draft_id, attachment_id }) => {
    try {
      const result = await deleteReportIntentAttachment(
        draft_id,
        attachment_id
      );
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);
// ── End of HAI draft tools ────────────────────────────────────────
}

// ── Tool: search_disclosed_reports ────────────────────────────────
server.tool(
  "search_disclosed_reports",
  "Search publicly disclosed HackerOne reports (hacktivity). Useful for finding prior art and understanding what a program considers valid.",
  {
    program: z
      .string()
      .optional()
      .describe("Program handle to filter by (e.g. 'uber')"),
    query: z
      .string()
      .optional()
      .describe("Keyword to filter results (e.g. 'SSRF', 'IDOR')"),
    page_size: z
      .number()
      .min(1)
      .max(100)
      .optional()
      .describe("Number of results (default 25)"),
  },
  async (params) => {
    try {
      const results = await searchDisclosedReports(params);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(results, null, 2),
          },
        ],
      };
    } catch (err: any) {
      return {
        content: [{ type: "text" as const, text: `Error: ${err.message}` }],
        isError: true,
      };
    }
  }
);

// ── Start server ───────────────────────────────────────────────────
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  const mode = [
    WRITES_ENABLED ? "writes ENABLED" : "read-only",
    ...(DRAFTS_ENABLED ? ["HAI drafts ENABLED"] : []),
  ].join(", ");
  console.error(`HackerOne MCP server running on stdio (${mode})`);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
