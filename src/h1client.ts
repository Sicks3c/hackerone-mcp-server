import { readFile } from "fs/promises";
import { basename } from "path";

const H1_BASE = "https://api.hackerone.com/v1";

// ── Simple in-memory cache ────────────────────────────────────────
interface CacheEntry {
  data: any;
  expiresAt: number;
}
const cache = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 60_000; // 1 minute

function cacheGet(key: string): any | undefined {
  const entry = cache.get(key);
  if (!entry) return undefined;
  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return undefined;
  }
  return entry.data;
}

function cacheSet(key: string, data: any): void {
  cache.set(key, { data, expiresAt: Date.now() + CACHE_TTL_MS });
}

function cacheInvalidatePrefix(prefix: string): void {
  for (const key of cache.keys()) {
    if (key.startsWith(prefix)) cache.delete(key);
  }
}

// ── Auth ──────────────────────────────────────────────────────────
function getAuth(): string {
  const username = process.env.H1_USERNAME;
  const token = process.env.H1_API_TOKEN;
  if (!username || !token) {
    throw new Error(
      "Missing H1_USERNAME or H1_API_TOKEN environment variables"
    );
  }
  return Buffer.from(`${username}:${token}`).toString("base64");
}

// ── Rate limiting ─────────────────────────────────────────────────
// Documented limits: reads 600/min, writes 25/20s, structured_scopes 50/min.
// The structured_scopes limit is the only one auto-pagination can realistically
// hit, so gate that path to one request per 1.2s.
const STRUCTURED_SCOPES_MIN_INTERVAL_MS = 1200;
let structuredScopesNextAt = 0;

async function throttleIfNeeded(path: string): Promise<void> {
  if (!path.includes("/structured_scopes")) return;
  const now = Date.now();
  if (now < structuredScopesNextAt) {
    await sleep(structuredScopesNextAt - now);
  }
  structuredScopesNextAt = Date.now() + STRUCTURED_SCOPES_MIN_INTERVAL_MS;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ── HTTP helpers with retry + backoff ─────────────────────────────
function buildUrl(path: string, params?: Record<string, string>): string {
  const url = new URL(`${H1_BASE}${path}`);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v != null && v !== "") url.searchParams.set(k, v);
    }
  }
  return url.toString();
}

async function h1Fetch(
  path: string,
  params?: Record<string, string>,
  options?: { skipCache?: boolean }
): Promise<any> {
  const cacheKey = buildUrl(path, params);
  if (!options?.skipCache) {
    const cached = cacheGet(cacheKey);
    if (cached) return cached;
  }

  const json = await h1Request("GET", path, { params });
  cacheSet(cacheKey, json);
  return json;
}

interface RequestOpts {
  params?: Record<string, string>;
  body?: any;
  formData?: FormData;
}

async function h1Request(
  method: "GET" | "POST" | "PATCH" | "DELETE",
  path: string,
  opts: RequestOpts = {}
): Promise<any> {
  const url = buildUrl(path, opts.params);

  let lastErr: Error | null = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) {
      await sleep(1000 * Math.pow(2, attempt)); // 2s, 4s
    }
    await throttleIfNeeded(path);
    try {
      const headers: Record<string, string> = {
        Authorization: `Basic ${getAuth()}`,
        Accept: "application/json",
      };

      let body: BodyInit | undefined;
      if (opts.formData) {
        // Let fetch set the multipart boundary itself.
        body = opts.formData;
      } else if (opts.body !== undefined) {
        headers["Content-Type"] = "application/json";
        body =
          typeof opts.body === "string"
            ? opts.body
            : JSON.stringify(opts.body);
      }

      const res = await fetch(url, { method, headers, body });

      if (res.status === 429) {
        const retryAfter = res.headers.get("retry-after");
        const waitMs = retryAfter ? parseInt(retryAfter, 10) * 1000 : 5000;
        await sleep(waitMs);
        continue;
      }

      if (!res.ok) {
        const text = await res.text();
        throw new Error(`HackerOne API error ${res.status}: ${text}`);
      }

      if (method !== "GET") invalidateWriteCaches();

      if (res.status === 204) return {};
      const text = await res.text();
      return text ? JSON.parse(text) : {};
    } catch (err: any) {
      lastErr = err;
      if (err.message?.includes("HackerOne API error")) throw err;
    }
  }
  throw lastErr ?? new Error(`h1Request ${method} ${path} failed after retries`);
}

function invalidateWriteCaches(): void {
  cacheInvalidatePrefix(`${H1_BASE}/hackers/me/reports`);
  cacheInvalidatePrefix(`${H1_BASE}/hackers/reports`);
  cacheInvalidatePrefix(`${H1_BASE}/hackers/report_intents`);
}

// ── Auto-pagination helper ────────────────────────────────────────
// Follows `links.next` when the API provides it, and falls back to
// incrementing page[number] otherwise.
async function h1FetchAllPages(
  path: string,
  extraParams?: Record<string, string>,
  maxPages = 20
): Promise<any[]> {
  const all: any[] = [];
  const pageSize = 100;
  for (let page = 1; page <= maxPages; page++) {
    const params: Record<string, string> = {
      "page[size]": String(pageSize),
      "page[number]": String(page),
      ...extraParams,
    };
    const data = await h1Fetch(path, params);
    if (!data.data || data.data.length === 0) break;
    all.push(...data.data);
    if (!data.links?.next && data.data.length < pageSize) break;
    if (data.links && !data.links.next) break;
  }
  return all;
}

// ── List / search reports ──────────────────────────────────────────
export interface SearchReportsOpts {
  query?: string;
  program?: string;
  severity?: string;
  state?: string;
  page_size?: number;
  page_number?: number;
  sort?: string;
}

// GET /hackers/me/reports only documents page[number] / page[size]; there are
// no server-side filters, so anything narrower is applied client-side over
// paginated results.
export async function searchReports(opts: SearchReportsOpts = {}) {
  const requestedSize = opts.page_size ?? 25;
  const needsFilter = !!(
    opts.program ||
    opts.severity ||
    opts.state ||
    opts.query
  );

  const matches = (r: any) => {
    if (opts.program && r.program?.toLowerCase() !== opts.program.toLowerCase())
      return false;
    if (opts.severity && r.severity !== opts.severity) return false;
    if (opts.state && r.state !== opts.state) return false;
    if (opts.query) {
      const q = opts.query.toLowerCase();
      const hit =
        r.title?.toLowerCase().includes(q) ||
        r._vuln_info?.toLowerCase().includes(q) ||
        r.weakness?.toLowerCase().includes(q);
      if (!hit) return false;
    }
    return true;
  };

  let reports: any[] = [];

  if (!needsFilter) {
    const data = await h1Fetch("/hackers/me/reports", {
      "page[size]": String(Math.min(requestedSize, 100)),
      "page[number]": String(opts.page_number ?? 1),
    });
    reports = (data.data ?? []).map(mapReportSummary);
  } else {
    // Walk pages until we have enough matches (or run out of reports).
    for (let page = 1; page <= 20; page++) {
      const data = await h1Fetch("/hackers/me/reports", {
        "page[size]": "100",
        "page[number]": String(page),
      });
      const batch = data.data ?? [];
      if (batch.length === 0) break;
      reports.push(...batch.map(mapReportSummary).filter(matches));
      if (reports.length >= requestedSize && !opts.sort) break;
      if (!data.links?.next && batch.length < 100) break;
      if (data.links && !data.links.next) break;
    }
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

  if (needsFilter) {
    reports = reports.slice(0, requestedSize);
  }

  return reports.map(({ _vuln_info, ...rest }) => rest);
}

function mapReportSummary(r: any) {
  const attrs = r.attributes ?? {};
  const bounty = r.relationships?.bounties?.data?.[0]?.attributes;
  const sev = r.relationships?.severity?.data?.attributes;
  return {
    id: r.id,
    title: attrs.title,
    state: attrs.state,
    substate: attrs.substate ?? null,
    severity: sev?.rating ?? attrs.severity_rating ?? null,
    cvss_score: sev?.score ?? null,
    created_at: attrs.created_at,
    submitted_at: attrs.submitted_at ?? null,
    triaged_at: attrs.triaged_at ?? null,
    closed_at: attrs.closed_at ?? null,
    disclosed_at: attrs.disclosed_at ?? null,
    bounty_awarded_at: attrs.bounty_awarded_at ?? null,
    last_activity_at: attrs.last_activity_at ?? null,
    cve_ids: attrs.cve_ids ?? [],
    bounty_amount: bounty?.awarded_amount ?? bounty?.amount ?? null,
    bounty_bonus: bounty?.awarded_bonus_amount ?? bounty?.bonus_amount ?? null,
    _vuln_info: attrs.vulnerability_information,
    weakness: r.relationships?.weakness?.data?.attributes?.name ?? null,
    program: r.relationships?.program?.data?.attributes?.handle ?? null,
  };
}

// ── Get single report (with full CVSS + bounty) ──────────────────
export async function getReport(reportId: string) {
  const data = await h1Fetch(`/hackers/reports/${reportId}`);
  const r = data.data;
  const attrs = r.attributes;
  const rels = r.relationships ?? {};
  const sev = rels.severity?.data?.attributes;
  const bounties = rels.bounties?.data ?? [];
  const bounty = bounties[0]?.attributes;
  const attachments = rels.attachments?.data ?? [];
  const summaries = rels.summaries?.data ?? [];
  const scope = rels.structured_scope?.data?.attributes;
  const campaign = rels.campaign?.data;

  return {
    id: r.id,
    title: attrs.title,
    state: attrs.state,
    substate: attrs.substate ?? null,
    created_at: attrs.created_at,
    submitted_at: attrs.submitted_at ?? null,
    closed_at: attrs.closed_at,
    triaged_at: attrs.triaged_at,
    bounty_awarded_at: attrs.bounty_awarded_at,
    swag_awarded_at: attrs.swag_awarded_at ?? null,
    disclosed_at: attrs.disclosed_at,
    last_reporter_activity_at: attrs.last_reporter_activity_at ?? null,
    last_program_activity_at: attrs.last_program_activity_at ?? null,
    last_activity_at: attrs.last_activity_at ?? null,
    cve_ids: attrs.cve_ids ?? [],
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
    bounty_amount: bounty?.awarded_amount ?? bounty?.amount ?? null,
    bounty_bonus: bounty?.awarded_bonus_amount ?? bounty?.bonus_amount ?? null,
    bounty_currency: bounty?.awarded_currency ?? null,
    bounties: bounties.map((b: any) => ({
      id: b.id,
      amount: b.attributes?.awarded_amount ?? b.attributes?.amount ?? null,
      bonus_amount:
        b.attributes?.awarded_bonus_amount ?? b.attributes?.bonus_amount ?? null,
      currency: b.attributes?.awarded_currency ?? null,
      created_at: b.attributes?.created_at ?? null,
    })),
    vulnerability_information: attrs.vulnerability_information,
    impact: attrs.impact,
    weakness: rels.weakness?.data?.attributes?.name ?? null,
    weakness_id: rels.weakness?.data?.attributes?.external_id ?? null,
    reporter: rels.reporter?.data?.attributes?.username ?? null,
    program: rels.program?.data?.attributes?.handle ?? null,
    campaign: campaign
      ? {
          id: campaign.id,
          name: campaign.attributes?.name ?? null,
          state: campaign.attributes?.state ?? null,
        }
      : null,
    structured_scope: scope?.asset_identifier ?? null,
    structured_scope_type: scope?.asset_type ?? null,
    structured_scope_max_severity: scope?.max_severity ?? null,
    summaries: summaries.map((s: any) => ({
      id: s.id,
      category: s.attributes?.category,
      content: s.attributes?.content,
      created_at: s.attributes?.created_at,
    })),
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
// There is no standalone hacker activities endpoint; activities arrive as a
// relationship on GET /hackers/reports/{id}.
export async function getReportActivities(reportId: string, pageSize = 50) {
  const data = await h1Fetch(`/hackers/reports/${reportId}`);
  const activities = data.data?.relationships?.activities?.data ?? [];

  const mapped = activities.map((a: any) => ({
    id: a.id,
    type: a.type,
    message: a.attributes.message,
    created_at: a.attributes.created_at,
    updated_at: a.attributes.updated_at ?? null,
    internal: a.attributes.internal,
    automated_response: a.attributes.automated_response,
    actor_type: a.relationships?.actor?.data?.type ?? null,
    actor:
      a.relationships?.actor?.data?.attributes?.username ??
      a.relationships?.actor?.data?.attributes?.name ??
      null,
    attachments: (a.relationships?.attachments?.data ?? []).map((at: any) => ({
      id: at.id,
      file_name: at.attributes?.file_name,
      expiring_url: at.attributes?.expiring_url,
    })),
  }));

  return pageSize ? mapped.slice(0, pageSize) : mapped;
}

// ── List programs (auto-paginated) ────────────────────────────────
export async function listPrograms(pageSize = 50) {
  const allData = await h1FetchAllPages("/hackers/programs");

  const programs = allData.map((p: any) => ({
    id: p.id,
    handle: p.attributes.handle,
    name: p.attributes.name,
    currency: p.attributes.currency ?? null,
    offers_bounties: p.attributes.offers_bounties,
    open_scope: p.attributes.open_scope ?? null,
    gold_standard_safe_harbor: p.attributes.gold_standard_safe_harbor ?? null,
    state: p.attributes.state,
    started_accepting_at: p.attributes.started_accepting_at,
    submission_state: p.attributes.submission_state,
    triage_active: p.attributes.triage_active ?? null,
    bookmarked: p.attributes.bookmarked ?? null,
  }));

  if (pageSize && pageSize < programs.length) {
    return programs.slice(0, pageSize);
  }
  return programs;
}

// ── Get program details ───────────────────────────────────────────
export async function getProgramDetails(handle: string) {
  const data = await h1Fetch(`/hackers/programs/${handle}`);
  // Unlike the collection/sub-resource endpoints, this one has been observed
  // to return the program resource directly (no `data` envelope) rather than
  // the usual JSON:API `{ data: {...} }` wrapper.
  const p = data.data ?? data;
  if (!p?.attributes) {
    throw new Error(
      `Unexpected response shape from /hackers/programs/${handle}: ${JSON.stringify(
        data
      )}`
    );
  }
  const attrs = p.attributes;

  return {
    id: p.id,
    handle: attrs.handle,
    name: attrs.name,
    url: attrs.url,
    currency: attrs.currency ?? null,
    offers_bounties: attrs.offers_bounties,
    open_scope: attrs.open_scope ?? null,
    fast_payments: attrs.fast_payments ?? null,
    gold_standard_safe_harbor: attrs.gold_standard_safe_harbor ?? null,
    state: attrs.state,
    submission_state: attrs.submission_state,
    triage_active: attrs.triage_active ?? null,
    started_accepting_at: attrs.started_accepting_at,
    policy: attrs.policy,
    response_efficiency_percentage: attrs.response_efficiency_percentage,
    average_time_to_first_program_response:
      attrs.average_time_to_first_program_response,
    average_time_to_report_resolved: attrs.average_time_to_report_resolved,
    average_time_to_bounty_awarded: attrs.average_time_to_bounty_awarded,
    // The API spells this `allows_bounty_splitting`; older responses used the
    // singular form.
    allows_bounty_splitting:
      attrs.allows_bounty_splitting ?? attrs.allow_bounty_splitting ?? null,
    bookmarked: attrs.bookmarked,
    // Per-user stats scoped to the authenticated hacker.
    number_of_reports_for_user: attrs.number_of_reports_for_user ?? null,
    number_of_valid_reports_for_user:
      attrs.number_of_valid_reports_for_user ?? null,
    bounty_earned_for_user: attrs.bounty_earned_for_user ?? null,
    last_invitation_accepted_at_for_user:
      attrs.last_invitation_accepted_at_for_user ?? null,
  };
}

// ── Get program scope (auto-paginated) ────────────────────────────
export interface ScopeFilterOpts {
  page_size?: number;
  id_gt?: string;
  created_at_gt?: string;
  updated_at_gt?: string;
}

export async function getProgramScope(
  handle: string,
  opts: ScopeFilterOpts = {}
) {
  const filters: Record<string, string> = {};
  if (opts.id_gt) filters["filter[id__gt]"] = opts.id_gt;
  if (opts.created_at_gt) filters["filter[created_at__gt]"] = opts.created_at_gt;
  if (opts.updated_at_gt) filters["filter[updated_at__gt]"] = opts.updated_at_gt;

  const allData = await h1FetchAllPages(
    `/hackers/programs/${handle}/structured_scopes`,
    filters
  );

  const scopes = allData.map((s: any) => ({
    id: s.id,
    asset_type: s.attributes.asset_type,
    asset_identifier: s.attributes.asset_identifier,
    eligible_for_bounty: s.attributes.eligible_for_bounty,
    eligible_for_submission: s.attributes.eligible_for_submission,
    instruction: s.attributes.instruction,
    max_severity: s.attributes.max_severity,
    confidentiality_requirement: s.attributes.confidentiality_requirement ?? null,
    integrity_requirement: s.attributes.integrity_requirement ?? null,
    availability_requirement: s.attributes.availability_requirement ?? null,
    reference: s.attributes.reference ?? null,
    created_at: s.attributes.created_at,
    updated_at: s.attributes.updated_at ?? null,
  }));

  if (opts.page_size && opts.page_size < scopes.length) {
    return scopes.slice(0, opts.page_size);
  }
  return scopes;
}

// ── Get program scope exclusions (added Apr 2026) ─────────────────
export async function getProgramScopeExclusions(
  handle: string,
  pageSize = 100
) {
  const allData = await h1FetchAllPages(
    `/hackers/programs/${handle}/scope_exclusions`
  );

  const exclusions = allData.map((e: any) => ({
    id: e.id,
    category: e.attributes.category,
    details: e.attributes.details,
    created_at: e.attributes.created_at,
    updated_at: e.attributes.updated_at ?? null,
  }));

  if (pageSize && pageSize < exclusions.length) {
    return exclusions.slice(0, pageSize);
  }
  return exclusions;
}

// ── Get program weaknesses (auto-paginated) ───────────────────────
export async function getProgramWeaknesses(handle: string, pageSize = 100) {
  const allData = await h1FetchAllPages(
    `/hackers/programs/${handle}/weaknesses`
  );

  const weaknesses = allData.map((w: any) => ({
    id: w.id,
    name: w.attributes.name,
    description: w.attributes.description,
    external_id: w.attributes.external_id,
    created_at: w.attributes.created_at ?? null,
  }));

  if (pageSize && pageSize < weaknesses.length) {
    return weaknesses.slice(0, pageSize);
  }
  return weaknesses;
}

// ── Get earnings ──────────────────────────────────────────────────
export async function getEarnings(pageSize = 100, pageNumber = 1) {
  const data = await h1Fetch("/hackers/payments/earnings", {
    "page[size]": String(Math.min(pageSize, 100)),
    "page[number]": String(pageNumber),
  });

  return (data.data ?? []).map((e: any) => {
    const rels = e.relationships ?? {};
    const team = rels.team?.data ?? rels.program?.data;
    const bounty = rels.bounty?.data;
    return {
      id: e.id,
      type: e.type,
      amount: e.attributes.amount,
      created_at: e.attributes.created_at,
      currency: team?.attributes?.currency ?? null,
      program: team?.attributes?.handle ?? null,
      program_name: team?.attributes?.name ?? null,
      bounty_id: bounty?.id ?? null,
      report_id: bounty?.relationships?.report?.data?.id ?? null,
    };
  });
}

// ── Get payouts ───────────────────────────────────────────────────
export async function getPayouts(pageSize = 25, pageNumber = 1) {
  const data = await h1Fetch("/hackers/payments/payouts", {
    "page[size]": String(Math.min(pageSize, 100)),
    "page[number]": String(pageNumber),
  });

  return (data.data ?? []).map((p: any) => {
    // Payout entries are documented as flat objects, but tolerate the
    // JSON:API-wrapped shape too.
    const attrs = p.attributes ?? p;
    return {
      id: p.id ?? null,
      amount: attrs.amount ?? null,
      paid_out_at: attrs.paid_out_at ?? null,
      reference: attrs.reference ?? null,
      payout_provider: attrs.payout_provider ?? null,
      status: attrs.status ?? null,
    };
  });
}

// ── Get balance ───────────────────────────────────────────────────
export async function getBalance() {
  const data = await h1Fetch("/hackers/payments/balance");
  // The balance endpoint may return differently; handle both formats
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

// ── Get report summary (condensed for Claude context) ──────────────
export async function getReportSummary(reportId: string) {
  const report = await getReport(reportId);
  const activities = await getReportActivities(reportId, 0);

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
// POST /hackers/reports takes everything in `attributes` — weakness_id and
// structured_scope_id are integer attributes, not relationships.
export async function submitReport(opts: {
  program_handle: string;
  title: string;
  vulnerability_information: string;
  impact?: string;
  severity_rating?: string;
  weakness_id?: string;
  structured_scope_id?: string;
}) {
  const attributes: Record<string, any> = {
    team_handle: opts.program_handle,
    title: opts.title,
    vulnerability_information: opts.vulnerability_information,
  };
  if (opts.impact) attributes.impact = opts.impact;
  if (opts.severity_rating) attributes.severity_rating = opts.severity_rating;
  if (opts.weakness_id) attributes.weakness_id = Number(opts.weakness_id);
  if (opts.structured_scope_id)
    attributes.structured_scope_id = Number(opts.structured_scope_id);

  const result = await h1Request("POST", "/hackers/reports", {
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

// ── Add comment to report ─────────────────────────────────────────
// NOTE: not part of the documented Hacker API surface; kept because it works
// against the live platform. May break without notice.
export async function addComment(
  reportId: string,
  message: string,
  internal = false
) {
  const body = {
    data: {
      type: "activity-comment",
      attributes: { message, internal },
    },
  };

  const result = await h1Request(
    "POST",
    `/hackers/reports/${reportId}/activities`,
    { body }
  );
  return {
    id: result.data?.id,
    type: result.data?.type,
    message: result.data?.attributes?.message,
    created_at: result.data?.attributes?.created_at,
  };
}

// ── Close / withdraw report ───────────────────────────────────────
// NOTE: also undocumented — see addComment.
export async function closeReport(reportId: string, message?: string) {
  const body = {
    data: {
      type: "activity-hacker-requested-mediation",
      attributes: {
        message: message ?? "Withdrawing this report.",
        close_report: true,
      },
    },
  };

  const result = await h1Request(
    "POST",
    `/hackers/reports/${reportId}/activities`,
    { body }
  );
  return {
    id: result.data?.id,
    type: result.data?.type,
    message: result.data?.attributes?.message,
    created_at: result.data?.attributes?.created_at,
  };
}

// ── Report intents (draft reports) ────────────────────────────────
export interface ReportIntentMetadata {
  bug_class?: string;
  http_method?: string;
  vulnerable_url?: string;
  vulnerable_parameter?: string;
  [key: string]: unknown;
}

function mapReportIntent(ri: any) {
  if (!ri) return null;
  const attrs = ri.attributes ?? {};
  const rels = ri.relationships ?? {};
  return {
    id: ri.id,
    type: ri.type,
    title: attrs.title,
    description: attrs.description,
    state: attrs.state,
    has_failing_jobs: attrs.has_failing_jobs ?? null,
    has_canceled_jobs: attrs.has_canceled_jobs ?? null,
    job_status_by_type: attrs.job_status_by_type ?? null,
    metadata: attrs.metadata ?? null,
    program: rels.program?.data?.attributes?.handle ?? null,
    report_id: rels.report?.data?.id ?? null,
    attachments: (rels.attachments?.data ?? []).map(mapAttachment),
  };
}

function mapAttachment(a: any) {
  return {
    id: a.id,
    file_name: a.attributes?.file_name,
    content_type: a.attributes?.content_type,
    file_size: a.attributes?.file_size,
    expiring_url: a.attributes?.expiring_url,
    created_at: a.attributes?.created_at,
  };
}

export async function listReportIntents(pageSize = 25, pageNumber = 1) {
  const data = await h1Fetch("/hackers/report_intents", {
    "page[size]": String(Math.min(pageSize, 100)),
    "page[number]": String(pageNumber),
  });
  return (data.data ?? []).map(mapReportIntent);
}

export async function getReportIntent(reportIntentId: string) {
  const data = await h1Fetch(`/hackers/report_intents/${reportIntentId}`, {}, {
    skipCache: true,
  });
  return mapReportIntent(data.data);
}

export async function createReportIntent(opts: {
  program_handle: string;
  title: string;
  description: string;
  metadata?: ReportIntentMetadata;
}) {
  const attributes: Record<string, any> = {
    team_handle: opts.program_handle,
    title: opts.title,
    description: opts.description,
  };
  if (opts.metadata) attributes.metadata = opts.metadata;

  const result = await h1Request("POST", "/hackers/report_intents", {
    body: { data: { type: "report-intent", attributes } },
  });
  return mapReportIntent(result.data);
}

export async function updateReportIntent(
  reportIntentId: string,
  opts: {
    title?: string;
    description?: string;
    metadata?: ReportIntentMetadata;
  }
) {
  const attributes: Record<string, any> = {};
  if (opts.title !== undefined) attributes.title = opts.title;
  if (opts.description !== undefined) attributes.description = opts.description;
  if (opts.metadata !== undefined) attributes.metadata = opts.metadata;

  const result = await h1Request(
    "PATCH",
    `/hackers/report_intents/${reportIntentId}`,
    { body: { data: { type: "report-intent", attributes } } }
  );
  return mapReportIntent(result.data);
}

export async function deleteReportIntent(reportIntentId: string) {
  await h1Request("DELETE", `/hackers/report_intents/${reportIntentId}`);
  return { id: reportIntentId, deleted: true };
}

export async function submitReportIntent(reportIntentId: string) {
  const result = await h1Request(
    "POST",
    `/hackers/report_intents/${reportIntentId}/submit`
  );
  const intent = mapReportIntent(result.data);
  const reportId = intent?.report_id ?? result.data?.id;
  return {
    ...intent,
    url: reportId ? `https://hackerone.com/reports/${reportId}` : null,
  };
}

export async function listReportIntentAttachments(reportIntentId: string) {
  const data = await h1Fetch(
    `/hackers/report_intents/${reportIntentId}/attachments`,
    {},
    { skipCache: true }
  );
  return (data.data ?? []).map(mapAttachment);
}

export async function uploadReportIntentAttachments(
  reportIntentId: string,
  filePaths: string[]
) {
  const form = new FormData();
  for (const path of filePaths) {
    const buf = await readFile(path);
    form.append("files[]", new Blob([new Uint8Array(buf)]), basename(path));
  }

  const result = await h1Request(
    "POST",
    `/hackers/report_intents/${reportIntentId}/attachments`,
    { formData: form }
  );
  const payload = Array.isArray(result.data) ? result.data : [result.data];
  return payload.filter(Boolean).map(mapAttachment);
}

export async function deleteReportIntentAttachment(
  reportIntentId: string,
  attachmentId: string
) {
  const result = await h1Request(
    "DELETE",
    `/hackers/report_intents/${reportIntentId}/attachments/${attachmentId}`
  );
  const remaining = Array.isArray(result.data) ? result.data : [];
  return {
    deleted: attachmentId,
    remaining_attachments: remaining.map(mapAttachment),
  };
}

// ── Search disclosed reports (hacktivity) ─────────────────────────
// GET /hackers/hacktivity takes a Lucene `queryString`, not filter[] params.
// Filterable fields: severity_rating, asset_type, substate, cwe, cve_ids,
// reporter, team, total_awarded_amount, disclosed_at, has_collaboration,
// disclosed.
export interface HacktivityOpts {
  program?: string;
  query?: string;
  raw_query?: string;
  severity?: string;
  substate?: string;
  cwe?: string;
  cve?: string;
  asset_type?: string;
  reporter?: string;
  min_bounty?: number;
  disclosed_after?: string;
  has_collaboration?: boolean;
  sort?: string;
  page_size?: number;
  page_number?: number;
}

const HACKTIVITY_SORT_FIELDS = new Set([
  "latest_disclosable_activity_at",
  "disclosed_at",
  "total_awarded_amount",
  "votes",
]);

function luceneQuote(value: string): string {
  return `"${value.replace(/(["\\])/g, "\\$1")}"`;
}

export function buildHacktivityQuery(opts: HacktivityOpts): string {
  if (opts.raw_query) return opts.raw_query;

  const clauses: string[] = [];
  if (opts.program) clauses.push(`team:${luceneQuote(opts.program)}`);
  if (opts.severity) clauses.push(`severity_rating:${opts.severity}`);
  if (opts.substate) clauses.push(`substate:${opts.substate}`);
  if (opts.cwe) clauses.push(`cwe:${luceneQuote(opts.cwe)}`);
  if (opts.cve) clauses.push(`cve_ids:${luceneQuote(opts.cve)}`);
  if (opts.asset_type) clauses.push(`asset_type:${opts.asset_type}`);
  if (opts.reporter) clauses.push(`reporter:${luceneQuote(opts.reporter)}`);
  if (opts.min_bounty != null)
    clauses.push(`total_awarded_amount:>=${opts.min_bounty}`);
  if (opts.disclosed_after)
    clauses.push(`disclosed_at:>=${opts.disclosed_after}`);
  if (opts.has_collaboration != null)
    clauses.push(`has_collaboration:${opts.has_collaboration}`);
  if (opts.query) clauses.push(luceneQuote(opts.query));

  return clauses.join(" AND ");
}

export async function searchDisclosedReports(opts: HacktivityOpts) {
  const params: Record<string, string> = {
    "page[size]": String(Math.min(opts.page_size ?? 25, 100)),
    "page[number]": String(opts.page_number ?? 1),
  };

  const queryString = buildHacktivityQuery(opts);
  if (queryString) params.queryString = queryString;

  if (opts.sort) {
    const field = opts.sort.replace(/^-/, "");
    if (!HACKTIVITY_SORT_FIELDS.has(field)) {
      throw new Error(
        `Unsupported hacktivity sort '${opts.sort}'. Supported: ${[
          ...HACKTIVITY_SORT_FIELDS,
        ].join(", ")} (prefix with '-' for descending).`
      );
    }
    params.sort = opts.sort;
  }

  const data = await h1Fetch("/hackers/hacktivity", params, {
    skipCache: true,
  });

  return (data.data ?? []).map((r: any) => {
    const attrs = r.attributes ?? {};
    const rels = r.relationships ?? {};
    const program = rels.program?.data ?? rels.team?.data;
    return {
      id: r.id,
      // Undisclosed hacktivity entries omit the title; the generated summary is
      // the only description available for those.
      title: attrs.title ?? null,
      hacktivity_summary:
        rels.report_generated_content?.data?.attributes?.hacktivity_summary ??
        null,
      substate: attrs.substate ?? null,
      severity: attrs.severity_rating ?? null,
      cwe: attrs.cwe ?? null,
      cve_ids: attrs.cve_ids ?? [],
      disclosed: attrs.disclosed ?? null,
      disclosed_at: attrs.disclosed_at ?? null,
      submitted_at: attrs.submitted_at ?? null,
      latest_disclosable_action: attrs.latest_disclosable_action ?? null,
      latest_disclosable_activity_at:
        attrs.latest_disclosable_activity_at ?? null,
      total_awarded_amount: attrs.total_awarded_amount ?? null,
      votes: attrs.votes ?? null,
      url: attrs.url ?? `https://hackerone.com/reports/${r.id}`,
      reporter: rels.reporter?.data?.attributes?.username ?? null,
      program: program?.attributes?.handle ?? null,
      program_name: program?.attributes?.name ?? null,
      currency: program?.attributes?.currency ?? null,
    };
  });
}
