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
  getProgramScope,
  getProgramWeaknesses,
  getEarnings,
} from "./h1client.js";

const server = new McpServer({
  name: "hackerone",
  version: "1.0.0",
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
  "Get the full details of a specific HackerOne report by ID. Returns title, vulnerability details, impact, severity, CVSS, timestamps, and program info.",
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
  "List bug bounty programs you have access to on HackerOne.",
  {
    page_size: z
      .number()
      .min(1)
      .max(100)
      .optional()
      .describe("Number of programs to return (default 50)"),
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
  "Get the in-scope assets for a bug bounty program. Returns asset types, identifiers, bounty eligibility, and severity caps. Useful when drafting reports to pick the correct asset.",
  {
    program_handle: z
      .string()
      .describe("Program handle (e.g. 'uber', 'ipc-h1c-aws-tokyo-2026')"),
    page_size: z
      .number()
      .min(1)
      .max(100)
      .optional()
      .describe("Number of scope items to return (default 100)"),
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
  "Get the accepted vulnerability/weakness types for a program. Helps frame reports using the right CWE categories the program cares about.",
  {
    program_handle: z
      .string()
      .describe("Program handle (e.g. 'uber', 'ipc-h1c-aws-tokyo-2026')"),
    page_size: z
      .number()
      .min(1)
      .max(100)
      .optional()
      .describe("Number of weaknesses to return (default 100)"),
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
  },
  async ({ page_size }) => {
    try {
      const earnings = await getEarnings(page_size);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(earnings, null, 2),
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
  console.error("HackerOne MCP server running on stdio");
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
