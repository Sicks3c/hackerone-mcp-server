// ── HackerOne HTTP transport ──────────────────────────────────────
// Owns auth, caching, rate limiting, retries and error reporting.
// Every API call in h1client.ts goes through h1Request.

export const H1_BASE = "https://api.hackerone.com/v1";

// ── Errors ────────────────────────────────────────────────────────
export class H1ApiError extends Error {
  readonly status: number;
  readonly body: string;
  readonly method: string;
  readonly path: string;

  constructor(status: number, body: string, method: string, path: string) {
    super(describeApiError(status, body, method, path));
    this.name = "H1ApiError";
    this.status = status;
    this.body = body;
    this.method = method;
    this.path = path;
  }
}

function describeApiError(
  status: number,
  body: string,
  method: string,
  path: string
): string {
  const trimmed = body.length > 500 ? `${body.slice(0, 500)}…` : body;
  const hints: Record<number, string> = {
    400: " — malformed body; check attribute names against the Hacker API docs",
    401: " — check H1_USERNAME and H1_API_TOKEN",
    403: " — your account lacks access to this program or endpoint",
    404: " — unknown handle/id, or not visible to your account",
    429: " — rate limited by HackerOne",
  };
  const hint = hints[status] ?? "";
  return `HackerOne API error ${status} on ${method} ${path}${hint}: ${trimmed}`;
}

/** Thrown before a request is sent, when our own limiter says to hold off. */
export class H1RateLimitError extends Error {
  readonly retryAfterMs: number;

  constructor(label: string, retryAfterMs: number, method: string, path: string) {
    const secs = Math.ceil(retryAfterMs / 1000);
    super(
      `Local rate limit for ${label} reached on ${method} ${path}; request not sent. ` +
        `HackerOne locks this endpoint once tripped and retrying keeps it locked, ` +
        `so wait ~${secs}s and try again.`
    );
    this.name = "H1RateLimitError";
    this.retryAfterMs = retryAfterMs;
  }
}

// ── Auth ──────────────────────────────────────────────────────────
function getAuth(): string {
  const username = process.env.H1_USERNAME;
  const token = process.env.H1_API_TOKEN;
  if (!username || !token) {
    throw new Error("Missing H1_USERNAME or H1_API_TOKEN environment variables");
  }
  return Buffer.from(`${username}:${token}`).toString("base64");
}

// ── Response cache (GET only) ─────────────────────────────────────
interface CacheEntry {
  data: any;
  expiresAt: number;
}
const cache = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 60_000;

function cacheGet(key: string): any | undefined {
  const entry = cache.get(key);
  if (!entry) return undefined;
  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return undefined;
  }
  return entry.data;
}

export function cacheInvalidatePrefix(prefix: string): void {
  for (const key of cache.keys()) {
    if (key.startsWith(prefix)) cache.delete(key);
  }
}

// ── Rate limiting ─────────────────────────────────────────────────
// HackerOne documents 600 reads/min and 25 writes/20s, plus stricter
// per-endpoint caps: 50/min on structured_scopes (documented) and an
// undocumented, much tighter cap on report_intents writes. Measured
// against the live API: ~6 report-intent creates trips it, and it stays
// tripped for ~10 minutes — polling during the lockout does not clear it.
interface LimitRule {
  label: string;
  match: RegExp;
  methods?: string[];
  capacity: number;
  windowMs: number;
  /** "wait" sleeps until a slot frees; "reject" throws immediately. */
  onFull: "wait" | "reject";
}

const WRITE_METHODS = ["POST", "PATCH", "PUT", "DELETE"];

const RULES: LimitRule[] = [
  {
    // Creates and updates each queue a HackerOne assistant job; that is what
    // trips their undocumented lockout. DELETE queues nothing, so it is left
    // to the global write limit — otherwise cleaning up a draft you just made
    // would be blocked by the very quota that created it.
    label: "report_intents writes",
    match: /\/report_intents/,
    methods: ["POST", "PATCH"],
    capacity: 4,
    windowMs: 10 * 60_000,
    onFull: "reject",
  },
  {
    label: "structured_scopes",
    match: /\/structured_scopes/,
    capacity: 45,
    windowMs: 60_000,
    onFull: "wait",
  },
  {
    label: "global writes",
    match: /./,
    methods: WRITE_METHODS,
    capacity: 20,
    windowMs: 20_000,
    onFull: "wait",
  },
  {
    label: "global reads",
    match: /./,
    methods: ["GET"],
    capacity: 500,
    windowMs: 60_000,
    onFull: "wait",
  },
];

const hits = new Map<string, number[]>();

/**
 * Server-imposed lockouts we've actually observed, keyed by rule label.
 * Once HackerOne 429s an endpoint we stop sending to it entirely rather
 * than retrying, because retrying appears to extend the window.
 */
const lockouts = new Map<string, number>();
const OBSERVED_LOCKOUT_MS = 10 * 60_000;

function rulesFor(method: string, path: string): LimitRule[] {
  return RULES.filter(
    (r) => r.match.test(path) && (!r.methods || r.methods.includes(method))
  );
}

function recentHits(label: string, windowMs: number): number[] {
  const cutoff = Date.now() - windowMs;
  const kept = (hits.get(label) ?? []).filter((t) => t > cutoff);
  hits.set(label, kept);
  return kept;
}

async function acquireSlots(method: string, path: string): Promise<void> {
  for (const rule of rulesFor(method, path)) {
    const lockedUntil = lockouts.get(rule.label);
    if (lockedUntil && Date.now() < lockedUntil) {
      throw new H1RateLimitError(
        `${rule.label} (HackerOne returned 429)`,
        lockedUntil - Date.now(),
        method,
        path
      );
    }

    // Loop: after waiting, older hits may have aged out.
    for (;;) {
      const recent = recentHits(rule.label, rule.windowMs);
      if (recent.length < rule.capacity) break;
      const waitMs = recent[0] + rule.windowMs - Date.now();
      if (waitMs <= 0) continue;
      if (rule.onFull === "reject") {
        throw new H1RateLimitError(rule.label, waitMs, method, path);
      }
      await sleep(Math.min(waitMs, 30_000));
    }
  }

  const now = Date.now();
  for (const rule of rulesFor(method, path)) {
    hits.set(rule.label, [...(hits.get(rule.label) ?? []), now]);
  }
}

function recordServerLockout(method: string, path: string): void {
  for (const rule of rulesFor(method, path)) {
    if (rule.onFull === "reject") {
      lockouts.set(rule.label, Date.now() + OBSERVED_LOCKOUT_MS);
    }
  }
}

/** True when a 429 on this endpoint should be surfaced instead of retried. */
function is429Fatal(method: string, path: string): boolean {
  return rulesFor(method, path).some((r) => r.onFull === "reject");
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ── Core request ──────────────────────────────────────────────────
export interface RequestOpts {
  method?: string;
  params?: Record<string, string | undefined>;
  body?: any;
  /** Pre-built body (e.g. FormData); sent as-is with no Content-Type header. */
  rawBody?: BodyInit;
  skipCache?: boolean;
  /** Absolute URL, used to follow JSON:API `links.next`. */
  url?: string;
  maxAttempts?: number;
}

export async function h1Request(path: string, opts: RequestOpts = {}): Promise<any> {
  const method = opts.method ?? "GET";
  const url = new URL(opts.url ?? `${H1_BASE}${path}`);
  if (opts.params) {
    for (const [k, v] of Object.entries(opts.params)) {
      if (v != null && v !== "") url.searchParams.set(k, v);
    }
  }

  const isRead = method === "GET";
  const cacheKey = `${method} ${url.toString()}`;
  if (isRead && !opts.skipCache) {
    const cached = cacheGet(cacheKey);
    if (cached !== undefined) return cached;
  }

  const maxAttempts = opts.maxAttempts ?? 3;
  let lastErr: Error | null = null;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    if (attempt > 0) await sleep(1000 * 2 ** attempt); // 2s, 4s

    await acquireSlots(method, url.pathname);

    let res: Response;
    try {
      const headers: Record<string, string> = {
        Authorization: `Basic ${getAuth()}`,
        Accept: "application/json",
      };
      let body: BodyInit | undefined;
      if (opts.rawBody !== undefined) {
        body = opts.rawBody; // fetch sets the multipart boundary itself
      } else if (opts.body !== undefined) {
        headers["Content-Type"] = "application/json";
        body = JSON.stringify(opts.body);
      }
      res = await fetch(url.toString(), { method, headers, body });
    } catch (err: any) {
      // Network-level failure: worth retrying, but never lose the reason.
      lastErr = err instanceof Error ? err : new Error(String(err));
      continue;
    }

    if (res.status === 429) {
      const retryAfter = res.headers.get("retry-after");
      const text = await res.text().catch(() => "");
      if (is429Fatal(method, url.pathname)) {
        // Retrying here demonstrably prolongs the lockout — stop immediately.
        recordServerLockout(method, url.pathname);
        throw new H1ApiError(429, text, method, url.pathname);
      }
      lastErr = new H1ApiError(429, text, method, url.pathname);
      await sleep(retryAfter ? parseInt(retryAfter, 10) * 1000 : 5000);
      continue;
    }

    if (!res.ok) {
      // 4xx/5xx are deterministic for our purposes: surface, don't retry.
      throw new H1ApiError(res.status, await res.text(), method, url.pathname);
    }

    if (!isRead) invalidateAfterWrite(url.pathname);

    const text = await res.text();
    const json = text ? JSON.parse(text) : {};
    if (isRead) cache.set(cacheKey, { data: json, expiresAt: Date.now() + CACHE_TTL_MS });
    return json;
  }

  throw lastErr ?? new Error(`${method} ${path} failed after ${maxAttempts} attempts`);
}

function invalidateAfterWrite(pathname: string): void {
  cacheInvalidatePrefix(`GET ${H1_BASE}/hackers/me/reports`);
  cacheInvalidatePrefix(`GET ${H1_BASE}/hackers/reports`);
  if (pathname.includes("/report_intents")) {
    cacheInvalidatePrefix(`GET ${H1_BASE}/hackers/report_intents`);
  }
}

// ── Pagination ────────────────────────────────────────────────────
/**
 * Walk a JSON:API collection by following `links.next`, which is exact —
 * unlike guessing page counts.
 */
export async function h1FetchAll(
  path: string,
  params?: Record<string, string | undefined>,
  maxPages = 20
): Promise<any[]> {
  const all: any[] = [];
  let page = await h1Request(path, {
    params: { "page[size]": "100", ...params },
  });

  for (let i = 0; i < maxPages; i++) {
    const rows = page.data ?? [];
    all.push(...rows);
    const next = page.links?.next;
    if (!next || rows.length === 0) break;
    page = await h1Request(path, { url: next });
  }
  return all;
}
