import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { inspectVirusTotal, lookupVirusTotal, trustedUploadUrl } from "../lib/virustotal";
import { parseAssessment } from "../lib/ai";
import { updateVirusTotalReport } from "../lib/virus-total-evidence";
import type { Artifact, Report, VirusTotalResult } from "../lib/types";

const sha256 = "a".repeat(64);
const artifact: Artifact = { filename: "private.jpg", kind: "jpg", size: 3, sha256, metadata: {}, strings: [], urls: [], indicators: [], limitations: [], incomplete: false };
const assessment = { risk: "low", confidence: "medium", summary: "Struktur yang diperiksa tidak menunjukkan indikasi kuat.", findings: [], recommendations: ["Verifikasi sumber file."], limitations: ["Bukan jaminan aman."] };
const stats = { malicious: 0, suspicious: 0, harmless: 2, undetected: 60, timeout: 1, failure: 0, "confirmed-timeout": 0, "type-unsupported": 2 };
const completed = (override: Partial<typeof stats> = {}, id = sha256) => Response.json({ data: { id, type: "file", attributes: { last_analysis_date: 1760000000, last_analysis_stats: { ...stats, ...override }, last_analysis_results: { ExampleAV: { category: override.malicious ? "malicious" : "undetected", engine_name: "ExampleAV", result: override.malicious ? "Test.Detection" : null } } } } });
type Call = { url: string; init?: RequestInit };
async function scenario(t: TestContext, responses: (Response | Error | (() => Response))[], run: (calls: Call[]) => Promise<void>) {
  const previous = process.env.VIRUSTOTAL_API_KEY;
  process.env.VIRUSTOTAL_API_KEY = "fake-unit-test-key";
  const calls: Call[] = [];
  t.mock.method(globalThis, "fetch", async (url: unknown, init?: RequestInit) => {
    calls.push({ url: String(url), init });
    assert.equal(new Headers(init?.headers).get("x-apikey"), "fake-unit-test-key");
    assert.ok(init?.signal instanceof AbortSignal); assert.equal(init?.redirect, "error");
    assert.ok(!String(url).includes("fake-unit-test-key"));
    const next = responses.shift(); assert.ok(next, "Unexpected provider request");
    if (next instanceof Error) throw next;
    return typeof next === "function" ? next() : next;
  });
  try { await run(calls); } finally { if (previous === undefined) delete process.env.VIRUSTOTAL_API_KEY; else process.env.VIRUSTOTAL_API_KEY = previous; t.mock.restoreAll(); }
}
const options = { requestGate: async () => true };

test("missing API key performs no provider requests and never claims antivirus coverage", async t => {
  const old = process.env.VIRUSTOTAL_API_KEY; delete process.env.VIRUSTOTAL_API_KEY;
  t.mock.method(globalThis, "fetch", () => { throw new Error("Must not call provider"); });
  try { const result = await lookupVirusTotal(sha256); assert.equal(result.status, "not_configured"); assert.equal(result.stats, undefined); }
  finally { if (old !== undefined) process.env.VIRUSTOTAL_API_KEY = old; t.mock.restoreAll(); }
});
test("known hash uses existing antivirus evidence and never uploads the file even with scan enabled", async t => {
  await scenario(t, [completed({ malicious: 2 })], async calls => {
    const result = await inspectVirusTotal(artifact, Buffer.from("jpg"), true, options);
    assert.equal(result.status, "completed"); assert.equal(result.stats?.malicious, 2); assert.equal(result.detections?.[0].engine, "ExampleAV");
    assert.equal(calls.length, 1); assert.equal(calls[0].init?.method, undefined); assert.equal(result.source, "hash_lookup");
  });
});
test("unknown hash stays not_found and never uploads without explicit sharing selection", async t => {
  await scenario(t, [new Response(null, { status: 404 })], async calls => {
    const result = await inspectVirusTotal(artifact, Buffer.from("jpg"), false, options);
    assert.equal(result.status, "not_found"); assert.equal(result.stats, undefined); assert.equal(calls.length, 1);
  });
});
test("explicit new scan submits bytes under a hash filename and includes completed analysis", async t => {
  await scenario(t, [new Response(null, { status: 404 }), Response.json({ data: { id: "scan-id", type: "analysis" } }), Response.json({ data: { id: "scan-id", type: "analysis", attributes: { status: "completed", stats: { ...stats, malicious: 1 }, date: 1760000000, results: {} } }, meta: { file_info: { sha256 } } })], async calls => {
    const result = await inspectVirusTotal(artifact, Buffer.from("jpg"), true, options);
    assert.equal(result.status, "completed"); assert.equal(result.source, "file_upload"); assert.equal(result.analysisId, "scan-id");
    const form = calls[1].init?.body as FormData; const file = form.get("file") as File;
    assert.equal(file.name, `${sha256}.jpg`); assert.equal(await file.text(), "jpg"); assert.equal(calls[1].init?.method, "POST");
  });
});
test("partial scan results remain pending when the time budget expires", async t => {
  const controller = new AbortController();
  await scenario(t, [new Response(null, { status: 404 }), Response.json({ data: { id: "scan-id", type: "analysis" } }), () => { controller.abort(); return Response.json({ data: { id: "scan-id", type: "analysis", attributes: { status: "in-progress", stats: { ...stats, malicious: 1 }, date: 1760000000 } } }); }], async () => {
    const result = await inspectVirusTotal(artifact, Buffer.from("jpg"), true, { ...options, signal: controller.signal });
    assert.equal(result.status, "pending"); assert.equal(result.stats, undefined); assert.equal(result.analysisId, "scan-id");
  });
});
test("quota, invalid credentials, network failure and malformed provider data never become clean results", async t => {
  for (const [response, expected] of [[new Response(null, { status: 429 }), "rate_limited"], [new Response(null, { status: 401 }), "error"], [new Error("Network down"), "error"], [completed({ malicious: -1 }), "error"], [completed({}, "b".repeat(64)), "error"], [new Response("invalid json"), "error"]] as const) {
    await scenario(t, [response], async () => { const result = await lookupVirusTotal(sha256, options); assert.equal(result.status, expected); assert.equal(result.stats, undefined); assert.ok(!JSON.stringify(result).includes("fake-unit-test-key")); });
  }
});
test("request gate stops all network activity when the shared provider quota is exhausted", async t => {
  await scenario(t, [], async calls => { const result = await lookupVirusTotal(sha256, { requestGate: async () => false }); assert.equal(result.status, "rate_limited"); assert.equal(calls.length, 0); });
});
test("contradictory engine counts are rejected instead of hiding a positive detection", async t => {
  await scenario(t, [Response.json({ data: { id: sha256, type: "file", attributes: { last_analysis_date: 1760000000, last_analysis_stats: stats, last_analysis_results: { ExampleAV: { category: "malicious", result: "Test.Detection" } } } } })], async () => {
    const result = await lookupVirusTotal(sha256, options); assert.equal(result.status, "error"); assert.equal(result.stats, undefined);
  });
});
test("large file scanning accepts only official HTTPS upload origins", async t => {
  for (const url of ["https://evil.test/_ah/upload/id", "https://www.virustotal.com.evil.test/_ah/upload/id", "https://user:pass@www.virustotal.com/_ah/upload/id", "http://www.virustotal.com:8080/_ah/upload/id", "https://www.virustotal.com/other"]) assert.throws(() => trustedUploadUrl(url));
  assert.equal(trustedUploadUrl("http://www.virustotal.com/_ah/upload/id"), "https://www.virustotal.com/_ah/upload/id");
  await scenario(t, [new Response(null, { status: 404 }), Response.json({ data: "https://evil.test/_ah/upload/id" })], async calls => {
    const result = await inspectVirusTotal(artifact, Buffer.alloc(33 * 1024 * 1024), true, options);
    assert.equal(result.status, "error"); assert.equal(calls.length, 2); assert.ok(calls.every(c => c.url.startsWith("https://www.virustotal.com/")));
  });
});
test("AI cannot dismiss actual malicious/suspicious detections, including incomplete local extraction", async () => {
  for (const [malicious, suspicious, risk] of [[1, 0, "high"], [0, 2, "medium"]] as const) {
    const result: VirusTotalResult = { status: "completed", sha256, checkedAt: new Date().toISOString(), source: "hash_lookup", message: "Results", url: `https://www.virustotal.com/gui/file/${sha256}`, stats: { ...stats, malicious, suspicious } };
    for (const incomplete of [false, true]) {
      const parsed = parseAssessment(JSON.stringify(assessment), { ...artifact, incomplete, virusTotal: result });
      assert.equal(parsed.risk, risk); assert.equal(parsed.findings[0].severity, risk); if (incomplete) assert.equal(parsed.confidence, "low");
    }
  }
});
test("no detections or a failed lookup never lowers a concerning static verdict", () => {
  for (const status of ["completed", "error", "pending", "not_found"] as const) {
    const result: VirusTotalResult = { status, sha256, checkedAt: new Date().toISOString(), source: "hash_lookup", message: "No result", url: "https://www.virustotal.com", ...(status === "completed" ? { stats } : {}) };
    assert.equal(parseAssessment(JSON.stringify({ ...assessment, risk: "high" }), { ...artifact, virusTotal: result }).risk, "high");
  }
});
test("refresh binds evidence to the original hash and does not duplicate VirusTotal findings", () => {
  const result: VirusTotalResult = { status: "completed", sha256, checkedAt: new Date().toISOString(), source: "hash_lookup", message: "Results", url: "https://www.virustotal.com", stats: { ...stats, malicious: 1 } };
  const report: Report = { id: "report", createdAt: new Date().toISOString(), filename: artifact.filename, kind: "jpg", size: 3, sha256, model: "gpt-6-astra", durationMs: 10, assessment: parseAssessment(JSON.stringify(assessment), artifact), artifact };
  assert.throws(() => updateVirusTotalReport(report, { ...result, sha256: "b".repeat(64) }));
  const first = updateVirusTotalReport(report, result); const second = updateVirusTotalReport(first, result);
  assert.equal(second.assessment.risk, "high"); assert.equal(second.assessment.findings.length, 1);
  const refreshed = updateVirusTotalReport(second, { ...result, stats });
  assert.ok(!refreshed.assessment.summary.startsWith("VirusTotal:"));
  assert.equal(refreshed.assessment.findings.length, 0); assert.equal(refreshed.assessment.risk, "high");
});
