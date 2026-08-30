import { test, before, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";

// Env must be set before the module is imported: the client captures
// H1_ALLOW_DRAFTS / H1_ALLOW_WRITES at module load.
process.env.H1_USERNAME = "test-user";
process.env.H1_API_TOKEN = "test-token";
process.env.H1_ALLOW_DRAFTS = "true";

let client: any;
before(async () => {
  client = await import("../src/h1client.js");
});

// ── fetch mock ────────────────────────────────────────────────────
interface FetchCall {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: any;
}

let calls: FetchCall[] = [];
let responder: (call: FetchCall) => any;

function jsonResponse(status: number, body: any) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => null },
    text: async () => JSON.stringify(body),
    json: async () => body,
  };
}

beforeEach(() => {
  calls = [];
  responder = () => jsonResponse(200, {});
  (globalThis as any).fetch = async (url: any, init: any = {}) => {
    const call: FetchCall = {
      url: String(url),
      method: init.method ?? "GET",
      headers: init.headers ?? {},
      body: init.body,
    };
    calls.push(call);
    const res = responder(call);
    return res instanceof Error ? Promise.reject(res) : res;
  };
});

function intentPayload(id: string, state = "revise_intent") {
  return {
    data: {
      id,
      attributes: {
        state,
        title: "HAI title",
        description: "desc",
        has_failing_jobs: false,
        has_canceled_jobs: false,
        job_status_by_type: {},
        metadata: {},
      },
    },
  };
}

// ── updateReportIntent ────────────────────────────────────────────
test("updateReportIntent PATCHes the intent in place", async () => {
  responder = () => jsonResponse(200, intentPayload("123"));

  const result = await client.updateReportIntent("123", "new description");

  // Exactly one HTTP call: no GET of the old draft, no program lookup,
  // no POST creating a replacement, no DELETE.
  assert.equal(calls.length, 1);

  const call = calls[0];
  assert.equal(call.method, "PATCH");
  assert.equal(
    call.url,
    "https://api.hackerone.com/v1/hackers/report_intents/123"
  );
  assert.deepEqual(JSON.parse(call.body), {
    data: {
      type: "report-intent",
      attributes: { description: "new description" },
    },
  });
  assert.equal(
    call.headers.Authorization,
    `Basic ${Buffer.from("test-user:test-token").toString("base64")}`
  );
  assert.equal(call.headers["Content-Type"], "application/json");

  // Same ID is returned — attachments and {F<id>} references survive.
  assert.equal(result.id, "123");
  assert.match(result.note, /updated in place/);
  assert.match(result.note, /poll get_report_draft on this ID/);
});

test("updateReportIntent surfaces API errors without retrying", async () => {
  responder = () =>
    jsonResponse(422, { errors: [{ detail: "intent already submitted" }] });

  await assert.rejects(
    () => client.updateReportIntent("123", "x"),
    /HackerOne API error 422/
  );
  assert.equal(calls.length, 1);
});

test("updateReportIntent rejects when drafts are disabled", async () => {
  // Separate module instance with H1_ALLOW_DRAFTS unset.
  delete process.env.H1_ALLOW_DRAFTS;
  const disabled: any = await import("../src/h1client.js?drafts-off");
  process.env.H1_ALLOW_DRAFTS = "true";

  await assert.rejects(
    () => disabled.updateReportIntent("123", "x"),
    /HAI report drafts are disabled/
  );
  assert.equal(calls.length, 0);
});

// ── createReportIntent / deleteReportIntent ───────────────────────
test("createReportIntent POSTs team handle and description", async () => {
  responder = () => jsonResponse(200, intentPayload("99", "created"));

  const result = await client.createReportIntent("acme", "a bug");

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "POST");
  assert.equal(
    calls[0].url,
    "https://api.hackerone.com/v1/hackers/report_intents"
  );
  assert.deepEqual(JSON.parse(calls[0].body), {
    data: {
      type: "report-intent",
      attributes: { team_handle: "acme", description: "a bug" },
    },
  });
  assert.equal(result.id, "99");
});

test("deleteReportIntent DELETEs the intent", async () => {
  responder = () => jsonResponse(200, {});

  const result = await client.deleteReportIntent("55");

  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "DELETE");
  assert.equal(
    calls[0].url,
    "https://api.hackerone.com/v1/hackers/report_intents/55"
  );
  assert.deepEqual(result, { deleted_draft_id: "55" });
});

// ── uploadReportIntentAttachments (multipart via global fetch) ───────────
test("uploadReportIntentAttachments sends files[] as multipart form data", async () => {
  const dir = await mkdtemp(join(tmpdir(), "h1-test-"));
  const file = join(dir, "poc.txt");
  await writeFile(file, "proof of concept");
  try {
    responder = () =>
      jsonResponse(200, {
        data: [
          {
            id: "7",
            attributes: {
              file_name: "poc.txt",
              content_type: "text/plain",
              file_size: 17,
              expiring_url: "https://example.com/7",
            },
          },
        ],
      });

    const result = await client.uploadReportIntentAttachments("123", [file]);

    assert.equal(calls.length, 1);
    assert.equal(calls[0].method, "POST");
    assert.equal(
      calls[0].url,
      "https://api.hackerone.com/v1/hackers/report_intents/123/attachments"
    );
    assert.ok(calls[0].body instanceof FormData);
    const uploaded = calls[0].body.getAll("files[]");
    assert.equal(uploaded.length, 1);
    assert.equal(uploaded[0].name, "poc.txt");

    assert.equal(result.report_intent_id, "123");
    assert.equal(result.attachments[0].markdown_reference, "{F7}");
    assert.equal(result.attachments[0].markdown_embed, "!{F7}");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
