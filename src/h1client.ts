import { H1_BASE, h1FetchAll, h1Request, sleep } from "./http.js";

export type Severity = "none" | "low" | "medium" | "high" | "critical";

const SEVERITY_ORDER: Severity[] = ["none", "low", "medium", "high", "critical"];

// ── List / search reports ──────────────────────────────────────────
// NOTE: /hackers/me/reports ignores every filter[...] and sort parameter —
// verified against the live API, identical results with and without them.
// So we paginate honestly and filter locally, rather than pretending.
export interface SearchReportsOpts {
  query?: string;
  program?: string;
  severity?: string;
  state?: string;
  page_size?: number;
  page_number?: number;
  sort?: string;
  max_pages?: number;
}

export async function searchReports(opts: SearchReportsOpts = {}) {
  const requestedSize = opts.page_size ?? 25;
  const needsFilter = !!(opts.program || opts.severity || opts.state || opts.query);

  let raw: any[];
  if (needsFilter) {
    // Any filter means we must scan the full history ourselves.
    raw = await h1FetchAll("/hackers/me/reports", undefined, opts.max_pages ?? 20);
  } else {
    const page = await h1Request("/hackers/me/reports", {
      params: {
        "page[size]": String(requestedSize),
        "page[number]": String(opts.page_number ?? 1),
      },
    });
    raw = page.data ?? [];
  }

  let reports = raw.map(mapReportSummary);

  if (opts.program) {
    const prog = opts.program.toLowerCase();
    reports = reports.filter((r) => r.program?.toLowerCase() === prog);
  }
  if (opts.severity) {
    reports = reports.filter((r) => r.severity === opts.severity);
  }
  if (opts.state) {
    reports = reports.filter((r) => r.state === opts.state);
  }
  if (opts.query) {
    const q = opts.query.toLowerCase();
    reports = reports.filter(
      (r) =>
        r.title?.toLowerCase().includes(q) ||
        r._vuln_info?.toLowerCase().includes(q) ||
        r.asset?.toLowerCase().includes(q)
    );
  }

  if (opts.sort) {
    const desc = opts.sort.startsWith("-");
    const field = opts.sort.replace(/^-/, "").replace("reports.", "");
    reports.sort((a: any, b: any) => {
      const va = a[field] ?? "";
      const vb = b[field] ?? "";
      return desc ? (vb > va ? 1 : -1) : va > vb ? 1 : -1;
    });
  }

  if (needsFilter) reports = reports.slice(0, requestedSize);
  return reports.map(({ _vuln_info, ...rest }) => rest);
}

// The list endpoint carries a narrower payload than /hackers/reports/{id}:
// no bounties or weakness relationship, and severity lives in a relationship
// rather than attributes. Only expose fields that are genuinely present.
function mapReportSummary(r: any) {
  const sev = r.relationships?.severity?.data?.attributes;
  const scope = r.relationships?.structured_scope?.data?.attributes;
  return {
    id: r.id,
    title: r.attributes.title,
    state: r.attributes.state,
    severity: sev?.rating ?? null,
    cvss_score: sev?.score ?? null,
    created_at: r.attributes.created_at,
    submitted_at: r.attributes.submitted_at,
    triaged_at: r.attributes.triaged_at,
    closed_at: r.attributes.closed_at,
    disclosed_at: r.attributes.disclosed_at,
    bounty_awarded_at: r.attributes.bounty_awarded_at,
    last_activity_at: r.attributes.last_activity_at,
    asset: scope?.asset_identifier ?? null,
    program: r.relationships?.program?.data?.attributes?.handle ?? null,
    _vuln_info: r.attributes.vulnerability_information,
  };
}

// ── Get single report (with full CVSS + bounty) ──────────────────
export async function getReport(reportId: string) {
  const data = await h1Request(`/hackers/reports/${reportId}`);
  const r = data.data;
  const attrs = r.attributes;
  const sev = r.relationships?.severity?.data?.attributes;
  const bounty = r.relationships?.bounties?.data?.[0]?.attributes;
  const attachments = r.relationships?.attachments?.data ?? [];

  return {
    id: r.id,
    title: attrs.title,
    state: attrs.state,
    created_at: attrs.created_at,
    closed_at: attrs.closed_at,
    triaged_at: attrs.triaged_at,
    bounty_awarded_at: attrs.bounty_awarded_at,
    disclosed_at: attrs.disclosed_at,
    severity: sev?.rating ?? null,
    cvss_score: sev?.score ?? null,
    cvss_vector: sev?.attack_vector
      ? {
          attack_vector: sev.attack_vector,
          attack_complexity: sev.attack_complexity,
          privileges_required: sev.privileges_required,
          user_interaction: sev.user_interaction,
          scope: sev.scope,
          confidentiality: sev.confidentiality,
          integrity: sev.integrity,
          availability: sev.availability,
        }
      : null,
    bounty_amount: bounty?.amount ?? null,
    bounty_bonus: bounty?.bonus_amount ?? null,
    vulnerability_information: attrs.vulnerability_information,
    impact: attrs.impact,
    weakness: r.relationships?.weakness?.data?.attributes?.name ?? null,
    weakness_id: r.relationships?.weakness?.data?.attributes?.external_id ?? null,
    program: r.relationships?.program?.data?.attributes?.handle ?? null,
    structured_scope:
      r.relationships?.structured_scope?.data?.attributes?.asset_identifier ?? null,
    structured_scope_type:
      r.relationships?.structured_scope?.data?.attributes?.asset_type ?? null,
    attachments: attachments.map((a: any) => ({
      id: a.id,
      file_name: a.attributes?.file_name,
      content_type: a.attributes?.content_type,
      file_size: a.attributes?.file_size,
      expiring_url: a.attributes?.expiring_url,
    })),
  };
}

// ── Get report activities (comments, state changes) ────────────────
export async function getReportActivities(reportId: string, _pageSize = 50) {
  const data = await h1Request(`/hackers/reports/${reportId}`);
  const activities = data.data?.relationships?.activities?.data ?? [];

  return activities.map((a: any) => ({
    id: a.id,
    type: a.type,
    message: a.attributes.message,
    created_at: a.attributes.created_at,
    internal: a.attributes.internal,
    automated_response: a.attributes.automated_response,
    actor_type: a.relationships?.actor?.data?.type ?? null,
    actor:
      a.relationships?.actor?.data?.attributes?.username ??
      a.relationships?.actor?.data?.attributes?.name ??
      null,
  }));
}

// ── Programs ──────────────────────────────────────────────────────
export async function listPrograms(pageSize = 50) {
  const allData = await h1FetchAll("/hackers/programs");
  const programs = allData.map((p: any) => ({
    id: p.id,
    handle: p.attributes.handle,
    name: p.attributes.name,
    offers_bounties: p.attributes.offers_bounties,
    state: p.attributes.state,
    started_accepting_at: p.attributes.started_accepting_at,
    submission_state: p.attributes.submission_state,
  }));
  return pageSize && pageSize < programs.length ? programs.slice(0, pageSize) : programs;
}

export async function getProgramDetails(handle: string) {
  const data = await h1Request(`/hackers/programs/${handle}`);
  // Some H1 endpoints return the resource directly; others wrap it in {data: {...}}
  const p = data.data ?? data;
  const attrs = p.attributes;

  return {
    id: p.id,
    handle: attrs.handle,
    name: attrs.name,
    url: attrs.url,
    offers_bounties: attrs.offers_bounties,
    state: attrs.state,
    submission_state: attrs.submission_state,
    started_accepting_at: attrs.started_accepting_at,
    policy: attrs.policy,
    response_efficiency_percentage: attrs.response_efficiency_percentage,
    average_time_to_first_program_response:
      attrs.average_time_to_first_program_response,
    average_time_to_report_resolved: attrs.average_time_to_report_resolved,
    average_time_to_bounty_awarded: attrs.average_time_to_bounty_awarded,
    allow_bounty_splitting: attrs.allow_bounty_splitting,
    bookmarked: attrs.bookmarked,
  };
}

function mapScope(s: any) {
  return {
    id: s.id,
    asset_type: s.attributes.asset_type,
    asset_identifier: s.attributes.asset_identifier,
    eligible_for_bounty: s.attributes.eligible_for_bounty,
    eligible_for_submission: s.attributes.eligible_for_submission,
    instruction: s.attributes.instruction,
    max_severity: s.attributes.max_severity,
    created_at: s.attributes.created_at,
    updated_at: s.attributes.updated_at,
  };
}

export async function getProgramScope(handle: string, pageSize = 100) {
  const allData = await h1FetchAll(`/hackers/programs/${handle}/structured_scopes`);
  const scopes = allData.map(mapScope);
  return pageSize && pageSize < scopes.length ? scopes.slice(0, pageSize) : scopes;
}

/**
 * Scope items created or updated since a timestamp. HackerOne added
 * server-side date filtering here in Jan 2026, so this is a real query
 * rather than a client-side scan.
 */
export async function getScopeChanges(
  handle: string,
  since: string,
  field: "updated_at" | "created_at" = "updated_at"
) {
  const iso = normalizeSince(since);
  const rows = await h1FetchAll(`/hackers/programs/${handle}/structured_scopes`, {
    [`filter[${field}__gt]`]: iso,
  });
  return {
    program: handle,
    since: iso,
    compared_on: field,
    count: rows.length,
    scopes: rows.map(mapScope),
  };
}

// The API wants ISO-8601 with an explicit offset (a Jun 2026 fix).
function normalizeSince(since: string): string {
  const d = new Date(since);
  if (isNaN(d.getTime())) {
    throw new Error(
      `Invalid date '${since}' — use ISO-8601, e.g. 2026-01-01 or 2026-01-01T00:00:00+00:00`
    );
  }
  return d.toISOString().replace(/\.\d{3}Z$/, "+00:00");
}

export async function getProgramWeaknesses(handle: string, pageSize = 100) {
  const allData = await h1FetchAll(`/hackers/programs/${handle}/weaknesses`);
  const weaknesses = allData.map((w: any) => ({
    id: w.id,
    name: w.attributes.name,
    description: w.attributes.description,
    external_id: w.attributes.external_id,
  }));
  return pageSize && pageSize < weaknesses.length
    ? weaknesses.slice(0, pageSize)
    : weaknesses;
}

/** Report categories a program excludes from rewards (added Apr 2026). */
export async function getScopeExclusions(handle: string) {
  const rows = await h1FetchAll(`/hackers/programs/${handle}/scope_exclusions`);
  return rows.map((e: any) => ({
    id: e.id,
    category: e.attributes?.category,
    details: e.attributes?.details,
    created_at: e.attributes?.created_at,
    updated_at: e.attributes?.updated_at,
  }));
}

// ── Payments ──────────────────────────────────────────────────────
export async function getEarnings(pageSize = 100) {
  const data = await h1Request("/hackers/payments/earnings", {
    params: { "page[size]": String(pageSize) },
  });
  return (data.data ?? []).map((e: any) => ({
    id: e.id,
    amount: e.attributes.amount,
    awarded_by: e.attributes.awarded_by_name,
    created_at: e.attributes.created_at,
    currency: e.relationships?.program?.data?.attributes?.currency ?? null,
    program: e.relationships?.program?.data?.attributes?.handle ?? null,
  }));
}

export async function getPayouts(pageSize = 100) {
  const data = await h1Request("/hackers/payments/payouts", {
    params: { "page[size]": String(pageSize) },
  });
  return (data.data ?? []).map((p: any) => {
    const a = p.attributes ?? p;
    return {
      id: p.id ?? null,
      amount: a.amount,
      paid_out_at: a.paid_out_at,
      reference: a.reference,
      payout_provider: a.payout_provider,
      status: a.status,
    };
  });
}

export async function getBalance() {
  const data = await h1Request("/hackers/payments/balance");
  if (data.data) {
    const attrs = data.data.attributes ?? data.data;
    return {
      balance: attrs.balance ?? attrs.amount ?? null,
      currency: attrs.currency ?? null,
      pending: attrs.pending ?? null,
    };
  }
  return data;
}

// ── Hacker profile ────────────────────────────────────────────────
// There is no /hackers/me endpoint; profile data is only exposed via the
// reporter relationship on your own reports.
export async function getHackerProfile() {
  const data = await h1Request("/hackers/me/reports", { params: { "page[size]": "1" } });
  const reporter = data.data?.[0]?.relationships?.reporter?.data;
  if (!reporter) {
    throw new Error("No reports found — profile info can only be read from your reports");
  }
  const attrs = reporter.attributes;
  return {
    id: reporter.id,
    username: attrs.username,
    name: attrs.name,
    bio: attrs.bio,
    location: attrs.location,
    website: attrs.website,
    reputation: attrs.reputation,
    signal: attrs.signal,
    disabled: attrs.disabled,
    created_at: attrs.created_at,
    hackerone_triager: attrs.hackerone_triager,
  };
}

// ── Report summary (condensed for Claude context) ──────────────────
export async function getReportSummary(reportId: string) {
  const report = await getReport(reportId);
  const activities = await getReportActivities(reportId);

  const comments = activities.filter(
    (a: any) =>
      a.message &&
      !a.automated_response &&
      (a.type === "activity-comment" ||
        a.type === "activity-bug-triaged" ||
        a.type === "activity-bug-resolved" ||
        a.type === "activity-bounty-awarded")
  );

  return {
    ...report,
    conversation: comments.map((c: any) => ({
      from: c.actor ?? c.actor_type,
      type: c.type.replace("activity-", ""),
      message: c.message,
      date: c.created_at,
    })),
  };
}

// ── Submit report ─────────────────────────────────────────────────
// weakness_id and structured_scope_id are flat attributes on this endpoint,
// not relationships. Sending them as relationships silently drops them.
export async function submitReport(opts: {
  program_handle: string;
  title: string;
  vulnerability_information: string;
  impact: string;
  severity_rating?: string;
  weakness_id?: string | number;
  structured_scope_id?: string | number;
}) {
  const attributes: Record<string, unknown> = {
    team_handle: opts.program_handle,
    title: opts.title,
    vulnerability_information: opts.vulnerability_information,
    impact: opts.impact,
  };
  if (opts.severity_rating) attributes.severity_rating = opts.severity_rating;
  if (opts.weakness_id != null) attributes.weakness_id = Number(opts.weakness_id);
  if (opts.structured_scope_id != null) {
    attributes.structured_scope_id = Number(opts.structured_scope_id);
  }

  const result = await h1Request("/hackers/reports", {
    method: "POST",
    body: { data: { type: "report", attributes } },
  });
  const r = result.data;
  return {
    id: r.id,
    title: r.attributes?.title,
    state: r.attributes?.state,
    url: `https://hackerone.com/reports/${r.id}`,
  };
}

// ── Comments / close ──────────────────────────────────────────────
export async function addComment(reportId: string, message: string, internal = false) {
  const result = await h1Request(`/hackers/reports/${reportId}/activities`, {
    method: "POST",
    body: { data: { type: "activity-comment", attributes: { message, internal } } },
  });
  return {
    id: result.data?.id,
    type: result.data?.type,
    message: result.data?.attributes?.message,
    created_at: result.data?.attributes?.created_at,
  };
}

export async function closeReport(reportId: string, message?: string) {
  const result = await h1Request(`/hackers/reports/${reportId}/activities`, {
    method: "POST",
    body: {
      data: {
        type: "activity-hacker-requested-mediation",
        attributes: {
          message: message ?? "Withdrawing this report.",
          close_report: true,
        },
      },
    },
  });
  return {
    id: result.data?.id,
    type: result.data?.type,
    message: result.data?.attributes?.message,
    created_at: result.data?.attributes?.created_at,
  };
}

// ── Hacktivity (disclosed reports) ────────────────────────────────
// Hacktivity ignores filter[...] params; it takes a Lucene `queryString`.
export interface DisclosedSearchOpts {
  program?: string;
  query?: string;
  severity?: string;
  substate?: string;
  reporter?: string;
  min_bounty?: number;
  disclosed_only?: boolean;
  sort?: string;
  page_size?: number;
}

export function buildHacktivityQuery(opts: DisclosedSearchOpts): string {
  const terms: string[] = [];
  if (opts.program) terms.push(`team_handle:${quoteTerm(opts.program)}`);
  if (opts.severity) terms.push(`severity_rating:${quoteTerm(opts.severity)}`);
  if (opts.substate) terms.push(`substate:${quoteTerm(opts.substate)}`);
  if (opts.reporter) terms.push(`reporter:${quoteTerm(opts.reporter)}`);
  if (opts.min_bounty != null) terms.push(`total_awarded_amount:>${opts.min_bounty}`);
  if (opts.disclosed_only) terms.push("disclosed:true");
  if (opts.query) terms.push(`(${opts.query})`);
  return terms.join(" AND ");
}

function quoteTerm(v: string): string {
  return /[\s:()]/.test(v) ? `"${v.replace(/"/g, '\\"')}"` : v;
}

export async function searchDisclosedReports(opts: DisclosedSearchOpts) {
  const queryString = buildHacktivityQuery(opts);
  const params: Record<string, string> = {
    "page[size]": String(opts.page_size ?? 25),
  };
  if (queryString) params.queryString = queryString;
  if (opts.sort) params.sort = opts.sort;

  const data = await h1Request("/hackers/hacktivity", { params, skipCache: true });
  return {
    query: queryString || "(all)",
    count: (data.data ?? []).length,
    results: (data.data ?? []).map((r: any) => ({
      id: r.id,
      title: r.attributes?.title,
      substate: r.attributes?.substate,
      severity: r.attributes?.severity_rating,
      cwe: r.attributes?.cwe,
      cve_ids: r.attributes?.cve_ids,
      disclosed_at: r.attributes?.disclosed_at,
      submitted_at: r.attributes?.submitted_at,
      total_awarded_amount: r.attributes?.total_awarded_amount,
      votes: r.attributes?.votes,
      url: r.attributes?.url ?? `https://hackerone.com/reports/${r.id}`,
      reporter: r.relationships?.reporter?.data?.attributes?.username ?? null,
      program: r.relationships?.program?.data?.attributes?.handle ?? null,
    })),
  };
}

// ── Report analysis ───────────────────────────────────────────────
export async function analyzeReportPatterns(opts: {
  page_size?: number;
  include_weaknesses?: boolean;
}) {
  const reports = await searchReports({
    page_size: opts.page_size ?? 100,
    sort: "-reports.created_at",
  });

  const tally = (rows: (string | null | undefined)[]) => {
    const counts: Record<string, number> = {};
    for (const v of rows) counts[v ?? "unknown"] = (counts[v ?? "unknown"] ?? 0) + 1;
    return counts;
  };
  const top = (counts: Record<string, number>, key: string) =>
    Object.entries(counts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([k, count]) => ({ [key]: k, count }));

  const analysis: Record<string, unknown> = {
    total_reports_analyzed: reports.length,
    severity_distribution: tally(reports.map((r: any) => r.severity)),
    state_distribution: tally(reports.map((r: any) => r.state)),
    top_programs: top(
      tally(reports.filter((r: any) => r.program).map((r: any) => r.program)),
      "program"
    ),
    top_assets: top(
      tally(reports.filter((r: any) => r.asset).map((r: any) => r.asset)),
      "asset"
    ),
  };

  // Weakness only exists on the per-report endpoint, so this costs one
  // request per report and stays opt-in.
  if (opts.include_weaknesses) {
    const details = await mapWithConcurrency(reports, 5, async (r: any) => {
      try {
        return (await getReport(r.id)).weakness;
      } catch {
        return null;
      }
    });
    analysis.top_weakness_types = top(tally(details), "weakness");
  } else {
    analysis.note =
      "Weakness types omitted: the report list endpoint does not return them. Pass include_weaknesses=true to fetch each report individually.";
  }

  return analysis;
}

async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let cursor = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      for (;;) {
        const i = cursor++;
        if (i >= items.length) return;
        results[i] = await fn(items[i]);
      }
    })
  );
  return results;
}

// ── Report validation ─────────────────────────────────────────────
// Stateless: the caller holds the draft, this only checks it against the
// program's live scope, accepted weaknesses and reward exclusions.
export interface ValidationFinding {
  level: "error" | "warning" | "info";
  field?: string;
  message: string;
}

export interface ReportDraftInput {
  program_handle: string;
  title?: string;
  vulnerability_information?: string;
  impact?: string;
  severity_rating?: Severity;
  weakness_id?: string | number;
  structured_scope_id?: string | number;
}

export async function validateReport(input: ReportDraftInput) {
  const findings: ValidationFinding[] = [];
  const err = (message: string, field?: string) =>
    findings.push({ level: "error", field, message });
  const warn = (message: string, field?: string) =>
    findings.push({ level: "warning", field, message });

  if (!input.title?.trim()) err("Title is empty.", "title");
  if (!input.vulnerability_information?.trim()) {
    err("vulnerability_information is empty.", "vulnerability_information");
  }
  if (!input.impact?.trim()) {
    err("Impact is empty — HackerOne requires it on submission.", "impact");
  }

  let program: any = null;
  try {
    program = await getProgramDetails(input.program_handle);
  } catch {
    err(`Program '${input.program_handle}' not found or not visible to you.`, "program_handle");
  }

  if (program && program.submission_state !== "open") {
    err(
      `Program '${input.program_handle}' is not accepting submissions (submission_state: ${program.submission_state}).`,
      "program_handle"
    );
  }

  if (program) {
    const [scopes, weaknesses, exclusions] = await Promise.all([
      getProgramScope(input.program_handle, 1000).catch(() => []),
      getProgramWeaknesses(input.program_handle, 1000).catch(() => []),
      getScopeExclusions(input.program_handle).catch(() => []),
    ]);

    if (input.structured_scope_id != null) {
      const asset = scopes.find(
        (s: any) => String(s.id) === String(input.structured_scope_id)
      );
      if (!asset) {
        err(
          `structured_scope_id '${input.structured_scope_id}' is not in this program's scope.`,
          "structured_scope_id"
        );
      } else {
        if (!asset.eligible_for_submission) {
          err(
            `Asset '${asset.asset_identifier}' is not eligible for submission.`,
            "structured_scope_id"
          );
        }
        if (!asset.eligible_for_bounty) {
          warn(
            `Asset '${asset.asset_identifier}' is in scope but not bounty-eligible.`,
            "structured_scope_id"
          );
        }
        if (asset.max_severity && input.severity_rating) {
          const cap = SEVERITY_ORDER.indexOf(asset.max_severity);
          const want = SEVERITY_ORDER.indexOf(input.severity_rating);
          if (cap >= 0 && want > cap) {
            warn(
              `Severity '${input.severity_rating}' exceeds this asset's max_severity of '${asset.max_severity}'; expect it to be capped.`,
              "severity_rating"
            );
          }
        }
      }
    } else {
      warn(
        "No structured_scope_id set. Reports without an asset get slower, worse triage.",
        "structured_scope_id"
      );
    }

    if (input.weakness_id != null) {
      const w = weaknesses.find((x: any) => String(x.id) === String(input.weakness_id));
      if (!w) {
        err(
          `weakness_id '${input.weakness_id}' is not among this program's accepted weaknesses.`,
          "weakness_id"
        );
      }
    } else {
      warn("No weakness_id set — the program will have to classify it for you.", "weakness_id");
    }

    for (const ex of exclusions) {
      findings.push({
        level: "info",
        message: `Program excludes from reward: ${ex.category}${ex.details ? ` — ${ex.details}` : ""}`,
      });
    }
  }

  return {
    program: input.program_handle,
    ready_to_submit: !findings.some((f) => f.level === "error"),
    errors: findings.filter((f) => f.level === "error"),
    warnings: findings.filter((f) => f.level === "warning"),
    notes: findings.filter((f) => f.level === "info"),
  };
}

// ── Report intents (HackerOne-side drafts) ────────────────────────
// Behaviour verified against the live API:
//  * `title` is not settable — HackerOne's assistant generates it.
//  * `description` is the only patchable attribute.
//  * Writes are async: state goes `pending`, an assistant job rewrites the
//    description into HackerOne's report template, then state becomes
//    `ready_to_submit`. Reading immediately after a write returns stale data.
function normalizeIntent(d: any) {
  const a = d.attributes ?? {};
  return {
    id: d.id,
    type: d.type,
    title: a.title ?? null,
    description: a.description ?? null,
    state: a.state ?? null,
    has_failing_jobs: a.has_failing_jobs ?? false,
    has_canceled_jobs: a.has_canceled_jobs ?? false,
    job_status_by_type: a.job_status_by_type ?? {},
    metadata: a.metadata ?? {},
    program_id: d.relationships?.program?.data?.id ?? null,
    report_id: d.relationships?.report?.data?.id ?? null,
    attachments: (d.relationships?.attachments?.data ?? []).map((x: any) => ({
      id: x.id,
      file_name: x.attributes?.file_name,
      content_type: x.attributes?.content_type,
      file_size: x.attributes?.file_size,
    })),
  };
}

export async function createReportIntent(opts: {
  program_handle: string;
  description: string;
  wait?: boolean;
}) {
  const result = await h1Request("/hackers/report_intents", {
    method: "POST",
    body: {
      data: {
        type: "report-intent",
        attributes: {
          team_handle: opts.program_handle,
          description: opts.description,
        },
      },
    },
  });
  const intent = normalizeIntent(result.data);
  // The create response predates the assistant job, so it is already stale.
  return opts.wait === false ? intent : waitForIntentReady(intent.id);
}

export async function listReportIntents() {
  const result = await h1Request("/hackers/report_intents", { skipCache: true });
  return (result.data ?? []).map(normalizeIntent);
}

export async function getReportIntent(id: string) {
  const result = await h1Request(`/hackers/report_intents/${id}`, { skipCache: true });
  return normalizeIntent(result.data);
}

export async function updateReportIntent(id: string, description: string) {
  await h1Request(`/hackers/report_intents/${id}`, {
    method: "PATCH",
    body: { data: { type: "report-intent", id, attributes: { description } } },
  });
  // The PATCH response echoes pre-job state, so re-read once the job settles.
  return waitForIntentReady(id);
}

export async function deleteReportIntent(id: string) {
  await h1Request(`/hackers/report_intents/${id}`, { method: "DELETE" });
  return { deleted: true, id };
}

/**
 * Poll until the assistant job settles. Reads are cheap relative to the
 * write limit, so polling here is safe.
 */
export async function waitForIntentReady(id: string, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  let intent = await getReportIntent(id);
  while (intent.state === "pending" && Date.now() < deadline) {
    await sleep(2000);
    intent = await getReportIntent(id);
  }
  return { ...intent, timed_out: intent.state === "pending" };
}

export async function submitReportIntent(id: string, confirm: boolean) {
  if (!confirm) {
    const intent = await getReportIntent(id);
    throw new Error(
      `submit_report_intent files a real report and cannot be undone. ` +
        `Intent '${id}' is titled "${intent.title}" (state: ${intent.state}). ` +
        `Re-run with confirm=true once the user has explicitly approved it.`
    );
  }
  const result = await h1Request(`/hackers/report_intents/${id}/submit`, {
    method: "POST",
    body: {},
  });
  const r = result.data;
  return {
    report_id: r?.id ?? null,
    state: r?.attributes?.state ?? null,
    url: r?.id ? `https://hackerone.com/reports/${r.id}` : null,
  };
}

// ── Report intent attachments ─────────────────────────────────────
export async function listIntentAttachments(id: string) {
  const result = await h1Request(`/hackers/report_intents/${id}/attachments`, {
    skipCache: true,
  });
  return (result.data ?? []).map((a: any) => ({
    id: a.id,
    file_name: a.attributes?.file_name,
    content_type: a.attributes?.content_type,
    file_size: a.attributes?.file_size,
    expiring_url: a.attributes?.expiring_url,
  }));
}

export async function uploadIntentAttachments(id: string, filePaths: string[]) {
  const { readFile } = await import("fs/promises");
  const { basename } = await import("path");

  const form = new FormData();
  for (const p of filePaths) {
    const buf = await readFile(p);
    form.append("files[]", new Blob([new Uint8Array(buf)]), basename(p));
  }

  const result = await h1Request(`/hackers/report_intents/${id}/attachments`, {
    method: "POST",
    rawBody: form,
  });
  const rows = Array.isArray(result.data) ? result.data : [result.data].filter(Boolean);
  return rows.map((a: any) => ({
    id: a.id,
    file_name: a.attributes?.file_name,
    content_type: a.attributes?.content_type,
    file_size: a.attributes?.file_size,
  }));
}

export async function deleteIntentAttachment(intentId: string, attachmentId: string) {
  await h1Request(`/hackers/report_intents/${intentId}/attachments/${attachmentId}`, {
    method: "DELETE",
  });
  return { deleted: true, intent_id: intentId, attachment_id: attachmentId };
}

export { H1_BASE };
