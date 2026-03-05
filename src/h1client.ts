import fetch from "node-fetch";

const H1_BASE = "https://api.hackerone.com/v1";

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

async function h1Fetch(path: string, params?: Record<string, string>) {
  const url = new URL(`${H1_BASE}${path}`);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v) url.searchParams.set(k, v);
    }
  }

  const res = await fetch(url.toString(), {
    headers: {
      Authorization: `Basic ${getAuth()}`,
      Accept: "application/json",
    },
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`HackerOne API error ${res.status}: ${body}`);
  }

  return res.json() as Promise<any>;
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
  // The /hackers/me/reports endpoint only supports pagination (page[number], page[size]).
  // Filtering by program, severity, state, keyword must be done client-side.

  const needsFilter = !!(opts.program || opts.severity || opts.state || opts.query);
  const requestedSize = opts.page_size ?? 25;

  // If filtering, fetch max results to filter from; otherwise respect page_size
  const fetchSize = needsFilter ? 100 : requestedSize;
  const pageNumber = opts.page_number ?? 1;

  let allReports: any[] = [];

  if (needsFilter) {
    // H1 hacker API doesn't support server-side filtering or sorting.
    // Strategy: find the last page first, then fetch backwards (newest first)
    // so recent reports are found quickly without fetching all 900+ reports.

    // Step 1: find total pages by probing
    let lastPage = 1;
    const probeRes = await h1Fetch("/hackers/me/reports", {
      "page[size]": "100",
      "page[number]": "1",
    });
    if (probeRes.data?.length === 100) {
      // Binary search for last page
      let lo = 1, hi = 50;
      while (lo < hi) {
        const mid = Math.ceil((lo + hi) / 2);
        const check = await h1Fetch("/hackers/me/reports", {
          "page[size]": "100",
          "page[number]": String(mid),
        });
        if (check.data?.length > 0) {
          lo = mid;
          if (check.data.length < 100) break; // This is the last page
          hi = Math.max(hi, mid + 5);
        } else {
          hi = mid - 1;
        }
      }
      lastPage = lo;
    }

    // Step 2: fetch from last page backwards (newest reports first)
    for (let page = lastPage; page >= 1; page--) {
      const data = page === 1 && probeRes.data
        ? probeRes // reuse first page probe if we loop back to it
        : await h1Fetch("/hackers/me/reports", {
            "page[size]": "100",
            "page[number]": String(page),
          });
      if (!data.data || data.data.length === 0) continue;
      allReports.push(...data.data);

      // Early exit: check if we already have enough matches
      const tempFiltered = allReports.filter((r: any) => {
        const prog = r.relationships?.program?.data?.attributes?.handle;
        if (opts.program && prog?.toLowerCase() !== opts.program.toLowerCase()) return false;
        if (opts.severity && r.attributes.severity_rating !== opts.severity) return false;
        if (opts.state && r.attributes.state !== opts.state) return false;
        return true;
      });
      if (tempFiltered.length >= requestedSize) break;
    }
  } else {
    const data = await h1Fetch("/hackers/me/reports", {
      "page[size]": String(fetchSize),
      "page[number]": String(pageNumber),
    });
    allReports = data.data ?? [];
  }

  // Map to clean objects — keep vulnerability_information for keyword filtering but strip from final output
  let reports = allReports.map((r: any) => ({
    id: r.id,
    title: r.attributes.title,
    state: r.attributes.state,
    substate: r.attributes.substate,
    severity: r.attributes.severity_rating,
    created_at: r.attributes.created_at,
    disclosed_at: r.attributes.disclosed_at,
    bounty_awarded_at: r.attributes.bounty_awarded_at,
    _vuln_info: r.attributes.vulnerability_information,
    weakness: r.relationships?.weakness?.data?.attributes?.name ?? null,
    program:
      r.relationships?.program?.data?.attributes?.handle ?? null,
  }));

  // Client-side filtering
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

  // Sort if requested
  if (opts.sort) {
    const desc = opts.sort.startsWith("-");
    const field = opts.sort.replace(/^-/, "").replace("reports.", "");
    reports.sort((a: any, b: any) => {
      const va = a[field] ?? "";
      const vb = b[field] ?? "";
      return desc ? (vb > va ? 1 : -1) : (va > vb ? 1 : -1);
    });
  }

  // Apply page_size limit to filtered results
  if (needsFilter) {
    reports = reports.slice(0, requestedSize);
  }

  // Strip internal _vuln_info from output to keep responses small
  return reports.map(({ _vuln_info, ...rest }) => rest);
}

// ── Get single report ──────────────────────────────────────────────
export async function getReport(reportId: string) {
  const data = await h1Fetch(`/hackers/reports/${reportId}`);
  const r = data.data;
  const attrs = r.attributes;
  const sev = r.relationships?.severity?.data?.attributes;

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
    vulnerability_information: attrs.vulnerability_information,
    weakness: r.relationships?.weakness?.data?.attributes?.name ?? null,
    program:
      r.relationships?.program?.data?.attributes?.handle ?? null,
    structured_scope:
      r.relationships?.structured_scope?.data?.attributes?.asset_identifier ??
      null,
  };
}

// ── Get report activities (comments, state changes) ────────────────
export async function getReportActivities(
  reportId: string,
  _pageSize = 50
) {
  // Activities are included in the report response under relationships
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

// ── List programs ──────────────────────────────────────────────────
export async function listPrograms(pageSize = 50) {
  const data = await h1Fetch("/hackers/programs", {
    "page[size]": String(pageSize),
  });

  return data.data.map((p: any) => ({
    id: p.id,
    handle: p.attributes.handle,
    name: p.attributes.name,
    offers_bounties: p.attributes.offers_bounties,
    state: p.attributes.state,
    started_accepting_at: p.attributes.started_accepting_at,
    submission_state: p.attributes.submission_state,
  }));
}

// ── Get program scope ─────────────────────────────────────────────
export async function getProgramScope(handle: string, pageSize = 100) {
  const data = await h1Fetch(`/hackers/programs/${handle}/structured_scopes`, {
    "page[size]": String(pageSize),
  });

  return data.data.map((s: any) => ({
    id: s.id,
    asset_type: s.attributes.asset_type,
    asset_identifier: s.attributes.asset_identifier,
    eligible_for_bounty: s.attributes.eligible_for_bounty,
    eligible_for_submission: s.attributes.eligible_for_submission,
    instruction: s.attributes.instruction,
    max_severity: s.attributes.max_severity,
    created_at: s.attributes.created_at,
  }));
}

// ── Get program weaknesses ────────────────────────────────────────
export async function getProgramWeaknesses(handle: string, pageSize = 100) {
  const data = await h1Fetch(`/hackers/programs/${handle}/weaknesses`, {
    "page[size]": String(pageSize),
  });

  return data.data.map((w: any) => ({
    id: w.id,
    name: w.attributes.name,
    description: w.attributes.description,
    external_id: w.attributes.external_id,
  }));
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
    currency: e.relationships?.program?.data?.attributes?.currency ?? null,
    program: e.relationships?.program?.data?.attributes?.handle ?? null,
  }));
}

// ── Get report summary (condensed for Claude context) ──────────────
export async function getReportSummary(reportId: string) {
  const report = await getReport(reportId);
  const activities = await getReportActivities(reportId);

  // Filter to meaningful comments only (no automated, no internal)
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
