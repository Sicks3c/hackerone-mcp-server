import fetch, { type RequestInit } from "node-fetch";
import { type Readable } from "stream";

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

// ── HTTP helpers with retry + backoff ─────────────────────────────
async function h1Fetch(
  path: string,
  params?: Record<string, string>,
  options?: { skipCache?: boolean }
): Promise<any> {
  const url = new URL(`${H1_BASE}${path}`);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v != null && v !== "") url.searchParams.set(k, v);
    }
  }

  const cacheKey = url.toString();
  if (!options?.skipCache) {
    const cached = cacheGet(cacheKey);
    if (cached) return cached;
  }

  let lastErr: Error | null = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) {
      await sleep(1000 * Math.pow(2, attempt)); // 2s, 4s
    }
    try {
      const res = await fetch(url.toString(), {
        headers: {
          Authorization: `Basic ${getAuth()}`,
          Accept: "application/json",
        },
      });

      if (res.status === 429) {
        const retryAfter = res.headers.get("retry-after");
        const waitMs = retryAfter ? parseInt(retryAfter, 10) * 1000 : 5000;
        await sleep(waitMs);
        continue;
      }

      if (!res.ok) {
        const body = await res.text();
        throw new Error(`HackerOne API error ${res.status}: ${body}`);
      }

      const json = await res.json();
      cacheSet(cacheKey, json);
      return json;
    } catch (err: any) {
      lastErr = err;
      if (err.message?.includes("HackerOne API error")) throw err;
    }
  }
  throw lastErr ?? new Error("h1Fetch failed after retries");
}

async function h1Post(
  path: string,
  body: any,
  contentType = "application/json"
): Promise<any> {
  const url = `${H1_BASE}${path}`;

  let lastErr: Error | null = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) await sleep(1000 * Math.pow(2, attempt));
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          Authorization: `Basic ${getAuth()}`,
          Accept: "application/json",
          "Content-Type": contentType,
        },
        body: typeof body === "string" ? body : JSON.stringify(body),
      });

      if (res.status === 429) {
        const retryAfter = res.headers.get("retry-after");
        await sleep(retryAfter ? parseInt(retryAfter, 10) * 1000 : 5000);
        continue;
      }

      if (!res.ok) {
        const text = await res.text();
        throw new Error(`HackerOne API error ${res.status}: ${text}`);
      }

      // Invalidate caches that may be stale after a write
      cacheInvalidatePrefix(`${H1_BASE}/hackers/me/reports`);
      cacheInvalidatePrefix(`${H1_BASE}/hackers/reports`);

      const text = await res.text();
      return text ? JSON.parse(text) : {};
    } catch (err: any) {
      lastErr = err;
      if (err.message?.includes("HackerOne API error")) throw err;
    }
  }
  throw lastErr ?? new Error("h1Post failed after retries");
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ── Auto-pagination helper ────────────────────────────────────────
async function h1FetchAllPages(
  path: string,
  extraParams?: Record<string, string>,
  maxPages = 20
): Promise<any[]> {
  const all: any[] = [];
  for (let page = 1; page <= maxPages; page++) {
    const params: Record<string, string> = {
      "page[size]": "100",
      "page[number]": String(page),
      ...extraParams,
    };
    const data = await h1Fetch(path, params);
    if (!data.data || data.data.length === 0) break;
    all.push(...data.data);
    if (data.data.length < 100) break; // last page
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

export async function searchReports(opts: SearchReportsOpts = {}) {
  const needsFilter = !!(
    opts.program ||
    opts.severity ||
    opts.state ||
    opts.query
  );
  const requestedSize = opts.page_size ?? 25;

  const fetchSize = needsFilter ? 100 : requestedSize;
  const pageNumber = opts.page_number ?? 1;

  let allReports: any[] = [];

  if (needsFilter) {
    // Build server-side filter params where possible
    const serverParams: Record<string, string> = {
      "page[size]": "100",
      "page[number]": "1",
    };
    if (opts.program) {
      serverParams["filter[program][]"] = opts.program;
    }
    if (opts.severity) {
      serverParams["filter[severity][]"] = opts.severity;
    }
    if (opts.state) {
      serverParams["filter[state][]"] = opts.state;
    }

    // If we have server-side filters (not just keyword), use them
    const hasServerFilters = !!(opts.program || opts.severity || opts.state);

    if (hasServerFilters) {
      // Fetch with server-side filters, paginate until we have enough
      for (let page = 1; page <= 20; page++) {
        serverParams["page[number]"] = String(page);
        const data = await h1Fetch("/hackers/me/reports", serverParams);
        if (!data.data || data.data.length === 0) break;
        allReports.push(...data.data);
        if (data.data.length < 100) break;
        if (!opts.query && allReports.length >= requestedSize) break;
      }
    } else {
      // Keyword-only: fall back to client-side search with backward pagination
      const probeRes = await h1Fetch("/hackers/me/reports", {
        "page[size]": "100",
        "page[number]": "1",
      });
      if (probeRes.data?.length === 100) {
        let lo = 1,
          hi = 50;
        while (lo < hi) {
          const mid = Math.ceil((lo + hi) / 2);
          const check = await h1Fetch("/hackers/me/reports", {
            "page[size]": "100",
            "page[number]": String(mid),
          });
          if (check.data?.length > 0) {
            lo = mid;
            if (check.data.length < 100) break;
            hi = Math.max(hi, mid + 5);
          } else {
            hi = mid - 1;
          }
        }
        for (let page = lo; page >= 1; page--) {
          const data =
            page === 1 && probeRes.data
              ? probeRes
              : await h1Fetch("/hackers/me/reports", {
                  "page[size]": "100",
                  "page[number]": String(page),
                });
          if (!data.data || data.data.length === 0) continue;
          allReports.push(...data.data);
          const tempFiltered = allReports.filter((r: any) => {
            const q = opts.query!.toLowerCase();
            const title = r.attributes.title?.toLowerCase() ?? "";
            const vuln =
              r.attributes.vulnerability_information?.toLowerCase() ?? "";
            const weakness =
              r.relationships?.weakness?.data?.attributes?.name?.toLowerCase() ??
              "";
            return (
              title.includes(q) || vuln.includes(q) || weakness.includes(q)
            );
          });
          if (tempFiltered.length >= requestedSize) break;
        }
      } else {
        allReports = probeRes.data ?? [];
      }
    }
  } else {
    const data = await h1Fetch("/hackers/me/reports", {
      "page[size]": String(fetchSize),
      "page[number]": String(pageNumber),
    });
    allReports = data.data ?? [];
  }

  let reports = allReports.map((r: any) => mapReportSummary(r));

  // Client-side filtering (keyword always needs this; program/severity/state as fallback)
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
        r.weakness?.toLowerCase().includes(q)
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

  if (needsFilter) {
    reports = reports.slice(0, requestedSize);
  }

  return reports.map(({ _vuln_info, ...rest }) => rest);
}

function mapReportSummary(r: any) {
  const bounty = r.relationships?.bounties?.data?.[0]?.attributes;
  return {
    id: r.id,
    title: r.attributes.title,
    state: r.attributes.state,
    substate: r.attributes.substate,
    severity: r.attributes.severity_rating,
    created_at: r.attributes.created_at,
    disclosed_at: r.attributes.disclosed_at,
    bounty_awarded_at: r.attributes.bounty_awarded_at,
    bounty_amount: bounty?.amount ?? null,
    bounty_bonus: bounty?.bonus_amount ?? null,
    _vuln_info: r.attributes.vulnerability_information,
    weakness: r.relationships?.weakness?.data?.attributes?.name ?? null,
    program: r.relationships?.program?.data?.attributes?.handle ?? null,
  };
}

// ── Get single report (with full CVSS + bounty) ──────────────────
export async function getReport(reportId: string) {
  const data = await h1Fetch(`/hackers/reports/${reportId}`);
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
    weakness_id:
      r.relationships?.weakness?.data?.attributes?.external_id ?? null,
    program: r.relationships?.program?.data?.attributes?.handle ?? null,
    structured_scope:
      r.relationships?.structured_scope?.data?.attributes?.asset_identifier ??
      null,
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
export async function getReportActivities(
  reportId: string,
  _pageSize = 50
) {
  const data = await h1Fetch(`/hackers/reports/${reportId}`);
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

// ── List programs (auto-paginated) ────────────────────────────────
export async function listPrograms(pageSize = 50) {
  const allData = await h1FetchAllPages("/hackers/programs");

  const programs = allData.map((p: any) => ({
    id: p.id,
    handle: p.attributes.handle,
    name: p.attributes.name,
    offers_bounties: p.attributes.offers_bounties,
    state: p.attributes.state,
    started_accepting_at: p.attributes.started_accepting_at,
    submission_state: p.attributes.submission_state,
  }));

  // If caller requested a specific size, respect it
  if (pageSize && pageSize < programs.length) {
    return programs.slice(0, pageSize);
  }
  return programs;
}

// ── Get program details ───────────────────────────────────────────
export async function getProgramDetails(handle: string) {
  const data = await h1Fetch(`/hackers/programs/${handle}`);
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

// ── Get program scope (auto-paginated) ────────────────────────────
export async function getProgramScope(handle: string, pageSize = 100) {
  const allData = await h1FetchAllPages(
    `/hackers/programs/${handle}/structured_scopes`
  );

  const scopes = allData.map((s: any) => ({
    id: s.id,
    asset_type: s.attributes.asset_type,
    asset_identifier: s.attributes.asset_identifier,
    eligible_for_bounty: s.attributes.eligible_for_bounty,
    eligible_for_submission: s.attributes.eligible_for_submission,
    instruction: s.attributes.instruction,
    max_severity: s.attributes.max_severity,
    created_at: s.attributes.created_at,
  }));

  if (pageSize && pageSize < scopes.length) {
    return scopes.slice(0, pageSize);
  }
  return scopes;
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
  }));

  if (pageSize && pageSize < weaknesses.length) {
    return weaknesses.slice(0, pageSize);
  }
  return weaknesses;
}

// ── Get earnings ──────────────────────────────────────────────────
export async function getEarnings(pageSize = 100) {
  const data = await h1Fetch("/hackers/payments/earnings", {
    "page[size]": String(pageSize),
  });

  return data.data.map((e: any) => ({
    id: e.id,
    amount: e.attributes.amount,
    awarded_by: e.attributes.awarded_by_name,
    created_at: e.attributes.created_at,
    currency:
      e.relationships?.program?.data?.attributes?.currency ?? null,
    program: e.relationships?.program?.data?.attributes?.handle ?? null,
  }));
}

// ── Get hacker profile ────────────────────────────────────────────
export async function getHackerProfile() {
  const data = await h1Fetch("/hackers/me");
  const u = data.data;
  const attrs = u.attributes;

  return {
    id: u.id,
    username: attrs.username,
    name: attrs.name,
    bio: attrs.bio,
    reputation: attrs.reputation,
    signal: attrs.signal,
    impact: attrs.impact,
    rank: attrs.rank,
    created_at: attrs.created_at,
    hackerone_triager: attrs.hackerone_triager,
  };
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
export async function submitReport(opts: {
  program_handle: string;
  title: string;
  vulnerability_information: string;
  impact?: string;
  severity_rating?: string;
  weakness_id?: string;
  structured_scope_id?: string;
  draft?: boolean;
}) {
  const relationships: any = {
    program: {
      data: {
        type: "program",
        attributes: { handle: opts.program_handle },
      },
    },
  };

  if (opts.weakness_id) {
    relationships.weakness = {
      data: { type: "weakness", id: opts.weakness_id },
    };
  }

  if (opts.structured_scope_id) {
    relationships.structured_scope = {
      data: { type: "structured-scope", id: opts.structured_scope_id },
    };
  }

  const severity: any = {};
  if (opts.severity_rating) {
    severity.rating = opts.severity_rating;
  }

  const body = {
    data: {
      type: "report",
      attributes: {
        team_handle: opts.program_handle,
        title: opts.title,
        vulnerability_information: opts.vulnerability_information,
        impact: opts.impact ?? "",
        severity_rating: opts.severity_rating,
        ...(opts.draft ? { state: "pending" } : {}),
      },
      relationships,
    },
  };

  const result = await h1Post("/hackers/reports", body);
  const r = result.data;
  return {
    id: r.id,
    title: r.attributes?.title,
    state: r.attributes?.state,
    url: `https://hackerone.com/reports/${r.id}`,
  };
}

// ── Add comment to report ─────────────────────────────────────────
export async function addComment(
  reportId: string,
  message: string,
  internal = false
) {
  const body = {
    data: {
      type: "activity-comment",
      attributes: {
        message,
        internal,
      },
    },
  };

  const result = await h1Post(
    `/hackers/reports/${reportId}/activities`,
    body
  );
  return {
    id: result.data?.id,
    type: result.data?.type,
    message: result.data?.attributes?.message,
    created_at: result.data?.attributes?.created_at,
  };
}

// ── Close / withdraw report ───────────────────────────────────────
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

  // Attempt the state change via activities
  const result = await h1Post(
    `/hackers/reports/${reportId}/activities`,
    body
  );
  return {
    id: result.data?.id,
    type: result.data?.type,
    message: result.data?.attributes?.message,
    created_at: result.data?.attributes?.created_at,
  };
}

// ── Search disclosed reports ──────────────────────────────────────
export async function searchDisclosedReports(opts: {
  program?: string;
  query?: string;
  page_size?: number;
}) {
  // The hacktivity endpoint for disclosed reports
  const params: Record<string, string> = {
    "page[size]": String(opts.page_size ?? 25),
  };
  if (opts.program) {
    params["filter[team_handle][]"] = opts.program;
  }

  const data = await h1Fetch("/hackers/hacktivity", params, {
    skipCache: true,
  });
  let reports = (data.data ?? []).map((r: any) => ({
    id: r.id,
    title: r.attributes?.title ?? r.attributes?.raw_title,
    severity: r.attributes?.severity_rating,
    disclosed_at: r.attributes?.disclosed_at,
    total_awarded_amount: r.attributes?.total_awarded_amount,
    upvotes: r.attributes?.vote_count ?? r.attributes?.upvotes,
    url: r.attributes?.url ?? `https://hackerone.com/reports/${r.id}`,
    reporter:
      r.relationships?.reporter?.data?.attributes?.username ?? null,
    program:
      r.relationships?.team?.data?.attributes?.handle ??
      r.relationships?.program?.data?.attributes?.handle ??
      null,
    weakness: r.relationships?.weakness?.data?.attributes?.name ?? null,
  }));

  if (opts.query) {
    const q = opts.query.toLowerCase();
    reports = reports.filter(
      (r: any) =>
        r.title?.toLowerCase().includes(q) ||
        r.weakness?.toLowerCase().includes(q)
    );
  }

  return reports;
}

// ── Report Intents (draft reports) ───────────────────────────────────

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
    report_id: d.relationships?.report?.data?.id ?? null,
    url: `https://hackerone.com/report_intents/${d.id}`,
  };
}

export async function createReportIntent(opts: {
  program_handle: string;
  description: string;
  title?: string;
}) {
  const body = {
    data: {
      type: "report-intent",
      attributes: {
        team_handle: opts.program_handle,
        description: opts.description,
        ...(opts.title ? { title: opts.title } : {}),
      },
    },
  };
  const result = await h1Post("/hackers/report_intents", body);
  return normalizeIntent(result.data);
}

export async function listReportIntents() {
  const result = await h1Fetch("/hackers/report_intents", undefined, {
    skipCache: true,
  });
  const items: any[] = result.data ?? [];
  return items.map(normalizeIntent);
}

export async function getReportIntent(id: string) {
  const result = await h1Fetch(`/hackers/report_intents/${id}`, undefined, {
    skipCache: true,
  });
  return normalizeIntent(result.data);
}

export async function updateReportIntent(
  id: string,
  opts: { title?: string; description?: string }
) {
  const url = `${H1_BASE}/hackers/report_intents/${id}`;
  const body = {
    data: {
      type: "report-intent",
      id,
      attributes: {
        ...(opts.title !== undefined ? { title: opts.title } : {}),
        ...(opts.description !== undefined
          ? { description: opts.description }
          : {}),
      },
    },
  };
  const res = await fetch(url, {
    method: "PATCH",
    headers: {
      Authorization: `Basic ${getAuth()}`,
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HackerOne API error ${res.status}: ${text}`);
  }
  const json = await res.json() as any;
  return normalizeIntent(json.data);
}

export async function deleteReportIntent(id: string) {
  const url = `${H1_BASE}/hackers/report_intents/${id}`;
  const res = await fetch(url, {
    method: "DELETE",
    headers: {
      Authorization: `Basic ${getAuth()}`,
      Accept: "application/json",
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HackerOne API error ${res.status}: ${text}`);
  }
  return { deleted: true, id };
}

export async function submitReportIntent(id: string) {
  const result = await h1Post(`/hackers/report_intents/${id}/submit`, {});
  // Returns the newly created report
  const r = result.data;
  return {
    report_id: r?.id ?? null,
    state: r?.attributes?.state ?? null,
    url: r?.id ? `https://hackerone.com/reports/${r.id}` : null,
  };
}
