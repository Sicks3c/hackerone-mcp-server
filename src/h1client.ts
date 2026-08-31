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
  /** Only reports where the program replied after you last did. */
  awaiting_reply?: boolean;
  page_size?: number;
  page_number?: number;
  sort?: string;
  max_pages?: number;
}

export async function searchReports(opts: SearchReportsOpts = {}) {
  const requestedSize = opts.page_size ?? 25;
  const needsFilter = !!(
    opts.program || opts.severity || opts.state || opts.query || opts.awaiting_reply
  );

  let raw: any[];
  let truncated = false;
  if (needsFilter) {
    // Any filter means we must scan the full history ourselves.
    const paged = await h1FetchAll("/hackers/me/reports", undefined, opts.max_pages ?? 20);
    raw = paged.rows;
    truncated = paged.truncated;
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
  if (opts.awaiting_reply) {
    reports = reports.filter((r) => r.awaiting_your_reply);
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
      if (va === vb) return 0; // without this, equal values sorted as -1 and reversed the list
      return desc ? (vb > va ? 1 : -1) : va > vb ? 1 : -1;
    });
  }

  const matched = reports.length;
  if (needsFilter) reports = reports.slice(0, requestedSize);
  return {
    count: reports.length,
    matched,
    ...(truncated
      ? {
          truncated: true,
          note: `Scanned the first ${(opts.max_pages ?? 20) * 100} reports only; older ones were not searched. Raise max_pages to go further.`,
        }
      : {}),
    results: reports.map(({ _vuln_info, ...rest }) => rest),
  };
}

function awaitingReply(attrs: any): boolean {
  const prog = attrs.last_program_activity_at;
  const you = attrs.last_reporter_activity_at;
  if (!prog) return false;
  if (attrs.closed_at) return false;
  return !you || prog > you;
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
    // last_activity_at is null on every report the API returns — verified
    // across this account's full history. These are the ones actually populated.
    last_program_activity_at: r.attributes.last_program_activity_at,
    last_reporter_activity_at: r.attributes.last_reporter_activity_at,
    first_program_activity_at: r.attributes.first_program_activity_at,
    last_public_activity_at: r.attributes.last_public_activity_at,
    // The program spoke after you did: this report is waiting on your reply.
    awaiting_your_reply: awaitingReply(r.attributes),
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
    // HackerOne now returns CVSS 4.0 (calculation_method "cvss_4_0"). The flat
    // 3.1 fields this used to read are absent entirely, so the old gate on
    // sev.attack_vector made cvss_vector null on every single report.
    cvss_version: sev?.calculation_method ?? null,
    cvss_vector_string: sev?.cvss_vector_string ?? null,
    cvss_metrics:
      sev?.cvss_4_point_0_metrics ??
      (sev?.attack_vector
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
        : null),
    max_severity: sev?.max_severity ?? null,
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
// The list response carries 19 attributes; only `policy` and `profile_picture`
// are deliberately dropped — policy alone would be megabytes across 600
// programs. `bookmarked` matters most: it is the only way to identify the
// programs you actually follow.
const mapProgram = (p: any) => ({
  id: p.id,
  handle: p.attributes.handle,
  name: p.attributes.name,
  bookmarked: p.attributes.bookmarked,
  state: p.attributes.state,
  submission_state: p.attributes.submission_state,
  triage_active: p.attributes.triage_active,
  offers_bounties: p.attributes.offers_bounties,
  currency: p.attributes.currency,
  open_scope: p.attributes.open_scope,
  fast_payments: p.attributes.fast_payments,
  allows_bounty_splitting: p.attributes.allows_bounty_splitting,
  gold_standard_safe_harbor: p.attributes.gold_standard_safe_harbor,
  started_accepting_at: p.attributes.started_accepting_at,
  number_of_reports_for_user: p.attributes.number_of_reports_for_user,
  number_of_valid_reports_for_user: p.attributes.number_of_valid_reports_for_user,
  bounty_earned_for_user: p.attributes.bounty_earned_for_user,
});

async function listProgramRows(): Promise<any[]> {
  return (await h1FetchAll("/hackers/programs")).rows.map(mapProgram);
}

export interface ListProgramsOpts {
  page_size?: number;
  bookmarked_only?: boolean;
  submission_state?: string;
  offers_bounties?: boolean;
  query?: string;
}

export async function listPrograms(opts: ListProgramsOpts = {}) {
  const paged = await h1FetchAll("/hackers/programs");
  let programs = paged.rows.map(mapProgram);
  const total = programs.length;

  if (opts.bookmarked_only) programs = programs.filter((p) => p.bookmarked);
  if (opts.submission_state) {
    programs = programs.filter((p) => p.submission_state === opts.submission_state);
  }
  if (opts.offers_bounties !== undefined) {
    programs = programs.filter((p) => p.offers_bounties === opts.offers_bounties);
  }
  if (opts.query) {
    const q = opts.query.toLowerCase();
    programs = programs.filter(
      (p) =>
        p.handle?.toLowerCase().includes(q) || p.name?.toLowerCase().includes(q)
    );
  }

  const matched = programs.length;
  if (opts.page_size && opts.page_size < programs.length) {
    programs = programs.slice(0, opts.page_size);
  }
  return {
    count: programs.length,
    matched,
    total_available: total,
    ...(paged.truncated ? { truncated: true } : {}),
    programs,
  };
}

export async function getProgramDetails(handle: string, includePolicy = true) {
  const data = await h1Request(`/hackers/programs/${handle}`);
  // Some H1 endpoints return the resource directly; others wrap it in {data: {...}}
  const p = data.data ?? data;
  const attrs = p.attributes;

  // These are the attributes the endpoint actually returns, verified live.
  // The previous version read url, response_efficiency_percentage and three
  // average_time_to_* fields that do not exist (every "response metric" its
  // description advertised), and misspelled allows_bounty_splitting.
  return {
    id: p.id,
    handle: attrs.handle,
    name: attrs.name,
    currency: attrs.currency,
    state: attrs.state,
    submission_state: attrs.submission_state,
    triage_active: attrs.triage_active,
    started_accepting_at: attrs.started_accepting_at,
    offers_bounties: attrs.offers_bounties,
    allows_bounty_splitting: attrs.allows_bounty_splitting,
    open_scope: attrs.open_scope,
    fast_payments: attrs.fast_payments,
    gold_standard_safe_harbor: attrs.gold_standard_safe_harbor,
    bookmarked: attrs.bookmarked,
    profile_picture: attrs.profile_picture,
    // Per-user stats for the authenticated hacker.
    number_of_reports_for_user: attrs.number_of_reports_for_user,
    number_of_valid_reports_for_user: attrs.number_of_valid_reports_for_user,
    bounty_earned_for_user: attrs.bounty_earned_for_user,
    last_invitation_accepted_at_for_user: attrs.last_invitation_accepted_at_for_user,
    url: `https://hackerone.com/${attrs.handle}`,
    // The policy is usually the overwhelming majority of this payload.
    ...(includePolicy
      ? { policy: attrs.policy }
      : { policy_omitted: true, policy_length: (attrs.policy ?? "").length }),
  };
}

function envelope(paged: { rows: any[]; truncated: boolean }, mapped: any[], key: string) {
  return {
    count: mapped.length,
    ...(paged.truncated
      ? { truncated: true, note: "Hit the page cap; more exist server-side." }
      : {}),
    [key]: mapped,
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

export async function getProgramScope(handle: string, pageSize?: number) {
  const paged = await h1FetchAll(`/hackers/programs/${handle}/structured_scopes`);
  let scopes = paged.rows.map(mapScope);
  if (pageSize && pageSize < scopes.length) scopes = scopes.slice(0, pageSize);
  return envelope(paged, scopes, "scopes");
}

/** Flat list, for internal callers that just need the rows. */
async function scopeRows(handle: string): Promise<any[]> {
  return (await h1FetchAll(`/hackers/programs/${handle}/structured_scopes`)).rows.map(mapScope);
}

/**
 * Scope items created or updated since a timestamp. HackerOne added
 * server-side date filtering here in Jan 2026, so this is a real query
 * rather than a client-side scan.
 */
export async function getScopeChanges(
  handles: string | string[],
  since: string,
  field: "updated_at" | "created_at" = "updated_at",
  bookmarkedOnly = false
) {
  const iso = normalizeSince(since);

  let list: string[];
  if (bookmarkedOnly) {
    list = (await listProgramRows())
      .filter((p: any) => p.bookmarked)
      .map((p: any) => p.handle);
    if (list.length === 0) {
      return {
        since: iso,
        compared_on: field,
        programs: [],
        count: 0,
        note: "You have no bookmarked programs. Bookmark them on hackerone.com, or pass handles explicitly.",
        scopes: [],
      };
    }
  } else {
    list = Array.isArray(handles) ? handles : [handles];
  }

  // Sequential on purpose: structured_scopes is capped at 50 req/min and the
  // limiter would otherwise just serialise these anyway, with worse errors.
  const scopes: any[] = [];
  const failures: { program: string; error: string }[] = [];
  for (const handle of list) {
    try {
      const paged = await h1FetchAll(`/hackers/programs/${handle}/structured_scopes`, {
        [`filter[${field}__gt]`]: iso,
      });
      for (const row of paged.rows) scopes.push({ program: handle, ...mapScope(row) });
    } catch (e: any) {
      failures.push({ program: handle, error: e.message });
    }
  }

  return {
    since: iso,
    compared_on: field,
    programs: list,
    count: scopes.length,
    // Never let a failed program read as "nothing changed there".
    ...(failures.length ? { failed: failures } : {}),
    scopes,
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

const mapWeakness = (w: any) => ({
  id: w.id,
  name: w.attributes.name,
  description: w.attributes.description,
  external_id: w.attributes.external_id,
});

export async function getProgramWeaknesses(handle: string, pageSize?: number) {
  const paged = await h1FetchAll(`/hackers/programs/${handle}/weaknesses`);
  let rows = paged.rows.map(mapWeakness);
  if (pageSize && pageSize < rows.length) rows = rows.slice(0, pageSize);
  return envelope(paged, rows, "weaknesses");
}

async function weaknessRows(handle: string): Promise<any[]> {
  return (await h1FetchAll(`/hackers/programs/${handle}/weaknesses`)).rows.map(mapWeakness);
}

/** Report categories a program excludes from rewards (added Apr 2026). */
const mapExclusion = (e: any) => ({
  id: e.id,
  category: e.attributes?.category,
  details: e.attributes?.details,
  created_at: e.attributes?.created_at,
  updated_at: e.attributes?.updated_at,
});

export async function getScopeExclusions(handle: string) {
  const paged = await h1FetchAll(`/hackers/programs/${handle}/scope_exclusions`);
  return envelope(paged, paged.rows.map(mapExclusion), "exclusions");
}

async function exclusionRows(handle: string): Promise<any[]> {
  return (await h1FetchAll(`/hackers/programs/${handle}/scope_exclusions`)).rows.map(mapExclusion);
}

// ── Payments ──────────────────────────────────────────────────────
export async function getEarnings(pageSize = 100, pageNumber?: number) {
  const params: Record<string, string> = { "page[size]": String(pageSize) };
  if (pageNumber) params["page[number]"] = String(pageNumber);
  const data = await h1Request("/hackers/payments/earnings", { params });

  const rows = (data.data ?? []).map((e: any) => {
    // The documented earning attributes are {amount, created_at}. The previous
    // `awarded_by_name` does not exist, and the bounty relationship — which
    // carries the award detail and the originating report — was discarded.
    const bounty = e.relationships?.bounty?.data;
    const b = bounty?.attributes ?? {};
    const report = bounty?.relationships?.report?.data;
    const program = e.relationships?.program?.data?.attributes;
    return {
      id: e.id,
      type: e.type,
      amount: e.attributes?.amount,
      created_at: e.attributes?.created_at,
      program: program?.handle ?? null,
      currency: b.awarded_currency ?? program?.currency ?? null,
      bounty_amount: b.awarded_amount ?? null,
      bonus_amount: b.awarded_bonus_amount ?? null,
      report_id: report?.id ?? null,
      report_title: report?.attributes?.title ?? null,
    };
  });
  return { count: rows.length, page: pageNumber ?? 1, earnings: rows };
}

export async function getPayouts(pageSize = 100, pageNumber?: number) {
  const params: Record<string, string> = { "page[size]": String(pageSize) };
  if (pageNumber) params["page[number]"] = String(pageNumber);
  const data = await h1Request("/hackers/payments/payouts", { params });

  // This endpoint returns flat objects with no JSON:API attributes wrapper.
  const rows = (data.data ?? []).map((p: any) => {
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
  return { count: rows.length, page: pageNumber ?? 1, payouts: rows };
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

/**
 * One call for a report and, optionally, its timeline. get_report,
 * get_report_activities and get_report_with_conversation all hit the same
 * endpoint; an agent that called two paid for the same payload twice.
 */
export async function getReportBundle(
  reportId: string,
  include: string[] = []
) {
  const report = await getReport(reportId);
  const out: Record<string, unknown> = { ...report };
  if (include.includes("activities")) {
    out.activities = await getReportActivities(reportId);
  }
  if (include.includes("conversation")) {
    out.conversation = (await getReportSummary(reportId)).conversation;
  }
  return out;
}

// ── Report summary (condensed for Claude context) ──────────────────
export async function getReportSummary(reportId: string) {
  const report = await getReport(reportId);
  const activities = await getReportActivities(reportId);

  // Any activity carrying a human message is part of the conversation. The
  // previous four-type whitelist silently dropped most of the thread — and
  // returned nothing at all for reports closed with a single message.
  const comments = activities.filter(
    (a: any) => a.message && !a.automated_response
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

function requireNumericId(
  value: string | number | undefined,
  field: string
): number | undefined {
  if (value == null || value === "") return undefined;
  const n = Number(value);
  if (!Number.isFinite(n)) {
    throw new Error(
      `${field} must be the numeric id from ${
        field === "weakness_id" ? "get_program_weaknesses" : "get_program_scope"
      }, got '${value}'. ` +
        `(get_report returns the CWE external_id such as 'cwe-200', which is a ` +
        `different identifier and is not accepted here.)`
    );
  }
  return n;
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
  // Number("cwe-200") is NaN and JSON.stringify turns NaN into null, which the
  // API accepts — filing the report with no CWE and raising no error. Refuse
  // instead. Note get_report returns the CWE external_id ("cwe-200"); the id
  // this endpoint wants is the numeric one from get_program_weaknesses.
  attributes.weakness_id = requireNumericId(opts.weakness_id, "weakness_id");
  attributes.structured_scope_id = requireNumericId(
    opts.structured_scope_id,
    "structured_scope_id"
  );
  if (attributes.weakness_id === undefined) delete attributes.weakness_id;
  if (attributes.structured_scope_id === undefined) {
    delete attributes.structured_scope_id;
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
// REMOVED: addComment() and closeReport().
//
// Both posted to POST /hackers/reports/{id}/activities. That route does not
// exist in the Hacker API — it is absent from the documented endpoint list, and
// probing it returns 401 for GET and for POST even with a deliberately invalid
// body (a real endpoint would answer 400), while the same credentials get 200
// on /hackers/reports/{id}. Because HackerOne answers 401 for unrouted paths,
// the old tools failed while blaming the user's credentials.
//
// closeReport was worse than broken: it sent activity-hacker-requested-mediation,
// which requests HackerOne mediation rather than withdrawing anything, under a
// tool described to the agent as "Withdraw one of your own reports".
//
// The Hacker API exposes no way to comment on or close a report. Use the web UI.

// ── Hacktivity (disclosed reports) ────────────────────────────────
// Hacktivity ignores filter[...] params; it takes a Lucene `queryString`.
export interface DisclosedSearchOpts {
  program?: string;
  query?: string;
  severity?: string;
  substate?: string;
  reporter?: string;
  min_bounty?: number;
  /** Default true. Undisclosed rows are all-null except the program handle. */
  disclosed_only?: boolean;
  sort?: string;
  page_size?: number;
  page_number?: number;
}

// hacktivity silently caps page[size] at 50 regardless of what is requested,
// and returns `links: {}` — so page[number] is the only way to paginate.
const HACKTIVITY_MAX_PAGE_SIZE = 50;

export function buildHacktivityQuery(opts: DisclosedSearchOpts): string {
  const terms: string[] = [];
  if (opts.program) terms.push(`team_handle:${quoteTerm(opts.program)}`);
  if (opts.severity) terms.push(`severity_rating:${quoteTerm(opts.severity)}`);
  if (opts.substate) terms.push(`substate:${quoteTerm(opts.substate)}`);
  if (opts.reporter) terms.push(`reporter:${quoteTerm(opts.reporter)}`);
  if (opts.min_bounty != null) terms.push(`total_awarded_amount:>${opts.min_bounty}`);
  if (opts.disclosed_only !== false) terms.push("disclosed:true");
  if (opts.query) terms.push(`(${opts.query})`);
  return terms.join(" AND ");
}

// Quote anything that is not a bare alphanumeric/underscore token. Hyphens
// matter most: hacktivity tokenizes on them, so an unquoted `dept-of-defense`
// matched `us-department-of-state` and returned another program's reports
// under the requested program's name. Verified live.
function quoteTerm(v: string): string {
  return /^[A-Za-z0-9_]+$/.test(v) ? v : `"${v.replace(/"/g, '\\"')}"`;
}

export async function searchDisclosedReports(opts: DisclosedSearchOpts) {
  const queryString = buildHacktivityQuery(opts);
  const requested = opts.page_size ?? 25;
  const params: Record<string, string> = {
    "page[size]": String(Math.min(requested, HACKTIVITY_MAX_PAGE_SIZE)),
  };
  if (opts.page_number) params["page[number]"] = String(opts.page_number);
  if (queryString) params.queryString = queryString;
  if (opts.sort) params.sort = opts.sort;

  const data = await h1Request("/hackers/hacktivity", { params, skipCache: true });
  const rows = data.data ?? [];

  return {
    query: queryString || "(all)",
    page: opts.page_number ?? 1,
    count: rows.length,
    ...(requested > HACKTIVITY_MAX_PAGE_SIZE
      ? { note: `page_size capped at ${HACKTIVITY_MAX_PAGE_SIZE} by HackerOne.` }
      : {}),
    results: rows.map((r: any) => {
      const a = r.attributes ?? {};
      // An undisclosed row carries no title, severity, CWE or bounty — only a
      // program handle. Never mint a hackerone.com/reports/<id> link for one:
      // the report is not public, so the URL reads as real prior art and is not.
      const disclosed = a.disclosed === true || !!a.disclosed_at;
      return {
        id: r.id,
        disclosed,
        title: a.title ?? null,
        substate: a.substate ?? null,
        severity: a.severity_rating ?? null,
        cwe: a.cwe ?? null,
        cve_ids: a.cve_ids ?? null,
        disclosed_at: a.disclosed_at ?? null,
        submitted_at: a.submitted_at ?? null,
        total_awarded_amount: a.total_awarded_amount ?? null,
        votes: a.votes ?? null,
        url: a.url ?? (disclosed ? `https://hackerone.com/reports/${r.id}` : null),
        reporter: r.relationships?.reporter?.data?.attributes?.username ?? null,
        program: r.relationships?.program?.data?.attributes?.handle ?? null,
      };
    }),
  };
}

// ── Report analysis ───────────────────────────────────────────────
export async function analyzeReportPatterns(opts: {
  page_size?: number;
  include_weaknesses?: boolean;
}) {
  const reports = (
    await searchReports({ page_size: opts.page_size ?? 100, sort: "-reports.created_at" })
  ).results;

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
    // A failed lookup must never read as a verdict. Previously .catch(() => [])
    // turned a network error into "this asset is not in scope" (a hard block on
    // a valid report) and into "no reward exclusions" (a false all-clear).
    const settle = async (label: string, fn: () => Promise<any[]>) => {
      try {
        return { ok: true as const, data: await fn(), label };
      } catch (e: any) {
        return { ok: false as const, data: [] as any[], label, error: e.message };
      }
    };
    const [scopeRes, weaknessRes, exclusionRes] = await Promise.all([
      settle("scope", () => scopeRows(input.program_handle)),
      settle("weaknesses", () => weaknessRows(input.program_handle)),
      settle("scope exclusions", () => exclusionRows(input.program_handle)),
    ]);
    for (const r of [scopeRes, weaknessRes, exclusionRes]) {
      if (!r.ok) {
        warn(`Could not fetch ${r.label} (${r.error}); checks against it were skipped, NOT passed.`);
      }
    }
    const scopes = scopeRes.data;
    const weaknesses = weaknessRes.data;
    const exclusions = exclusionRes.data;

    if (input.structured_scope_id != null && !scopeRes.ok) {
      // Unknown, not invalid — do not block a valid report on our own failure.
      warn(
        `Could not verify structured_scope_id '${input.structured_scope_id}': the scope lookup failed.`,
        "structured_scope_id"
      );
    } else if (input.structured_scope_id != null) {
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

    if (input.weakness_id != null && !weaknessRes.ok) {
      warn(
        `Could not verify weakness_id '${input.weakness_id}': the weakness lookup failed.`,
        "weakness_id"
      );
    } else if (input.weakness_id != null) {
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
//  * Writes are async: state goes `pending`, an assistant job processes the
//    description, then state becomes `ready_to_submit` (~6-17s). Reading
//    immediately after a write returns stale data.
//  * The rewrite is CONDITIONAL, and the assistant FOLLOWS INSTRUCTIONS found
//    in the description. A/B tested on identical technical content: with a
//    leading "TEST DRAFT — not a real finding; do not submit" line, the text
//    came back verbatim and the title stayed "Report Intent #<id>"; without
//    it, the same content was reformatted into HackerOne's template under a
//    generated title.
//
//    Two consequences. Callers must not assume the description or title they
//    get back was rewritten — check, do not presume. And any untrusted text
//    placed in a description (a scraped page, a captured HTTP response, an
//    attacker-controlled string in a PoC) is read as instructions by a third
//    party's LLM: treat the description as a prompt-injection surface.
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
  // The submit endpoint returns the report-INTENT, not the report. The real
  // report id is on the `report` relationship, which the docs say is "only
  // present after submission". Using r.id here produced a valid-looking URL
  // pointing at an unrelated third party's report.
  const r = result.data;
  const reportId = r?.relationships?.report?.data?.id ?? null;
  return {
    intent_id: r?.id ?? null,
    report_id: reportId,
    state: r?.attributes?.state ?? null,
    url: reportId ? `https://hackerone.com/reports/${reportId}` : null,
    ...(reportId
      ? {}
      : {
          warning:
            "HackerOne did not return a report id for this submission. The intent " +
            "may still have been submitted — check list_report_intents and your " +
            "reports on hackerone.com before resubmitting.",
        }),
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

// This tool sends local files to a third party, so it refuses the paths an
// agent is most likely to be talked into exfiltrating — including the very
// file holding this server's own HackerOne token.
const BLOCKED_ATTACHMENT_PATTERNS: RegExp[] = [
  /(^|\/)\.claude\.json$/,
  /(^|\/)\.claude\//,
  /(^|\/)\.ssh\//,
  /(^|\/)\.aws\//,
  /(^|\/)\.gnupg\//,
  /(^|\/)\.netrc$/,
  /(^|\/)\.env(\.|$)/,
  /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/,
  /(^|\/)(shadow|passwd)$/,
  /\.pem$/,
  /\.p12$/,
  /\.pfx$/,
  /(^|\/)credentials$/,
];
const MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024;

export async function uploadIntentAttachments(id: string, filePaths: string[]) {
  const { readFile } = await import("fs/promises");
  const { basename, resolve } = await import("path");

  const form = new FormData();
  for (const p of filePaths) {
    const abs = resolve(p);
    const blocked = BLOCKED_ATTACHMENT_PATTERNS.find((re) => re.test(abs));
    if (blocked) {
      throw new Error(
        `Refusing to upload '${abs}': it matches a credential/secret path pattern. ` +
          `This tool sends files to HackerOne. If the file is genuinely a proof of ` +
          `concept, copy the relevant excerpt to a new file and upload that instead.`
      );
    }
    const buf = await readFile(abs);
    if (buf.byteLength > MAX_ATTACHMENT_BYTES) {
      throw new Error(
        `Refusing to upload '${abs}': ${(buf.byteLength / 1048576).toFixed(1)}MB ` +
          `exceeds the ${MAX_ATTACHMENT_BYTES / 1048576}MB cap.`
      );
    }
    form.append("files[]", new Blob([new Uint8Array(buf)]), basename(abs));
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
