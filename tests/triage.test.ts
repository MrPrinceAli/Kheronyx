import { test } from "node:test";
import assert from "node:assert/strict";
import { FIRST_CHECK_MS, INTERVAL_MS, RATE_RETRY_MS, applyTriageIndicators, checkTriage, configHosts, expire, mask, mergeTriageHosts, normalizeOverview, submitTriage, type TriageOptions } from "../lib/triage";
import { finishTriage, mergeIntel } from "../lib/sandbox";
import type { Artifact, Assessment, Report, ThreatIntelResult, TriageResult } from "../lib/types";

const sha256 = "dea110082d57d210d746c7d9fe791d8e297de82ccd5e48c2813c615a45913e8e";
const ID = "260703-jgmcvsas2l", T0 = Date.parse("2026-10-15T00:00:00.000Z");
type Call = {url: string; init?: RequestInit};
type Route = (call: Call) => Response | Promise<Response>;

// Fake fetch + fixed clock; the key must only travel in the Authorization header.
async function withTriage(route: Route, run: (options: TriageOptions, calls: Call[]) => Promise<void>, {key = "fake-triage-key", now = T0, gate = true, submit = true}: {key?: string | null; now?: number; gate?: boolean; submit?: boolean} = {}) {
  const previous = process.env.TRIAGE_API_KEY, url = process.env.TRIAGE_API_URL;
  if (key === null) delete process.env.TRIAGE_API_KEY; else process.env.TRIAGE_API_KEY = key;
  delete process.env.TRIAGE_API_URL;
  const calls: Call[] = [];
  const fetch = async (u: string, init?: RequestInit) => {
    const call = {url: u, init}; calls.push(call);
    assert.equal(new Headers(init?.headers).get("authorization"), "Bearer fake-triage-key"); assert.ok(!u.includes("fake-triage-key"));
    assert.ok(init?.signal instanceof AbortSignal); assert.equal(init?.redirect, "error");
    return route(call);
  };
  try { await run({fetch, gate: async () => gate, submitGate: async () => submit, now: () => now}, calls); }
  finally { if (previous === undefined) delete process.env.TRIAGE_API_KEY; else process.env.TRIAGE_API_KEY = previous; if (url !== undefined) process.env.TRIAGE_API_URL = url; }
}
const path = (c: Call) => c.url.replace("https://tria.ge/api/v0", "");
const iso = (t: number) => new Date(t).toISOString();
const search = (rows: object[]) => Response.json({data: rows, next: "x"});
const row = (over: object = {}) => ({id: ID, status: "reported", kind: "file", filename: `${sha256}.apk`, submitted: "2026-07-03T09:00:00Z", completed: "2026-07-03T09:05:00Z", sha256, ...over});

test("search reuses an existing public analysis without uploading; archives containing the file do not count", async () => {
  await withTriage(() => search([row({id: "260706-bb3hwsgy8z", filename: `${sha256}.zip`, sha256: "a".repeat(64)}), row({id: "260601-oldoldoldo", completed: "2026-06-01T00:00:00Z"}), row()]), async (options, calls) => {
    const {result, retryUpload} = await submitTriage({sha256, kind: "apk", buffer: Buffer.from("PK")}, undefined, options);
    assert.deepEqual(calls.map(path), [`/search?query=sha256%3A${sha256}`]);
    assert.equal(result.status, "running"); assert.equal(result.sampleId, ID); assert.equal(result.reused, true); assert.equal(result.url, `https://tria.ge/${ID}`);
    assert.equal(result.nextCheck, iso(T0)); assert.equal(retryUpload, false); assert.match(result.message || "", /tanpa mengunggah/);
  });
  // A running public analysis is reused too (checked again after 2 min).
  await withTriage(() => search([row({status: "running", completed: undefined})]), async options => {
    const {result} = await submitTriage({sha256, kind: "apk", buffer: Buffer.from("PK")}, undefined, options);
    assert.equal(result.status, "running"); assert.equal(result.reused, true); assert.equal(result.nextCheck, iso(T0 + FIRST_CHECK_MS));
  });
  // Same SHA-256 already submitted by an earlier Kheronyx report: no request at all.
  await withTriage(() => { throw new Error("must not be called"); }, async (options, calls) => {
    const {result} = await submitTriage({sha256, kind: "apk", buffer: Buffer.from("PK"), known: ID}, undefined, options);
    assert.equal(calls.length, 0); assert.equal(result.sampleId, ID); assert.equal(result.reused, true);
  });
});

test("unknown file is uploaded under its SHA-256 name only, non-interactive", async () => {
  await withTriage(({url, init}) => init?.method === "POST" ? Response.json({id: ID, status: "pending", kind: "file", filename: `${sha256}.exe`, private: false, submitted: "2026-10-15T00:00:00Z"}) : search([]), async (options, calls) => {
    const {result, retryUpload} = await submitTriage({sha256, kind: "exe", buffer: Buffer.from("MZ secret-invoice-content")}, undefined, options);
    assert.deepEqual(calls.map(c => `${c.init?.method || "GET"} ${path(c)}`), [`GET /search?query=sha256%3A${sha256}`, "POST /samples"]);
    const form = calls[1].init?.body as FormData;
    assert.deepEqual(JSON.parse(String(form.get("_json"))), {kind: "file", interactive: false, target: `${sha256}.exe`});
    assert.equal((form.get("file") as File).name, `${sha256}.exe`);
    assert.equal(result.status, "pending"); assert.equal(result.sampleId, ID); assert.equal(result.reused, false); assert.equal(result.nextCheck, iso(T0 + FIRST_CHECK_MS)); assert.equal(retryUpload, false);
  });
});

test("quota, rate limits, failures and unsupported input never throw", async () => {
  const upload = {sha256, kind: "apk" as const, buffer: Buffer.from("PK")};
  // Kheronyx daily submission quota: nothing is uploaded, final.
  await withTriage(() => search([]), async (options, calls) => {
    const {result, retryUpload} = await submitTriage(upload, undefined, options);
    assert.equal(result.status, "rate_limited"); assert.equal(result.nextCheck, undefined); assert.equal(retryUpload, false); assert.equal(calls.length, 1); assert.match(result.message || "", /per hari/);
  }, {submit: false});
  // Tria.ge 429 on upload: retried later with the kept file.
  await withTriage(({init}) => init?.method === "POST" ? new Response(null, {status: 429}) : search([]), async options => {
    const {result, retryUpload} = await submitTriage(upload, undefined, options);
    assert.equal(result.status, "rate_limited"); assert.equal(result.nextCheck, iso(T0 + RATE_RETRY_MS)); assert.equal(retryUpload, true);
  });
  // Network down: pending retry; 30 min after the first submission it gives up and the file is released.
  await withTriage(() => { throw new Error("down"); }, async options => {
    const first = await submitTriage(upload, undefined, options);
    assert.equal(first.result.status, "pending"); assert.equal(first.result.nextCheck, iso(T0 + INTERVAL_MS)); assert.equal(first.retryUpload, true);
    const late = await submitTriage(upload, first.result, {...options, now: () => T0 + 31 * 60_000});
    assert.equal(late.result.status, "failed"); assert.equal(late.result.nextCheck, undefined); assert.equal(late.retryUpload, false); assert.equal(late.result.submittedAt, iso(T0));
  });
  // Own per-minute request gate: no network request.
  await withTriage(() => { throw new Error("must not be called"); }, async (options, calls) => {
    const {result} = await submitTriage(upload, undefined, options);
    assert.equal(result.status, "rate_limited"); assert.ok(result.nextCheck); assert.equal(calls.length, 0);
  }, {gate: false});
  // 401: message never echoes the key.
  await withTriage(() => new Response("bad key fake-triage-key", {status: 401}), async options => {
    const {result} = await submitTriage(upload, undefined, options);
    assert.match(result.message || "", /ditolak/); assert.ok(!JSON.stringify(result).includes("fake-triage-key"));
  });
  // File already deleted and unknown to Tria.ge; PDFs; missing key.
  await withTriage(() => search([]), async options => assert.equal((await submitTriage({sha256, kind: "apk"}, undefined, options)).result.status, "skipped"));
  await withTriage(() => { throw new Error("must not be called"); }, async options => assert.equal((await submitTriage({sha256, kind: "pdf", buffer: Buffer.from("%PDF")}, undefined, options)).result.status, "skipped"));
  await withTriage(() => { throw new Error("must not be called"); }, async options => assert.equal((await submitTriage(upload, undefined, options)).result.status, "skipped"), {key: null});
});

// Shape of real overview.json / report_triage.json (SpyNote APK + AgentTesla-style exfiltration config).
const overview = () => ({
  version: "0.3.0", sample: {id: ID, target: `${sha256}.apk`, sha256, iocs: {}},
  analysis: {score: 10, family: ["spynote"], tags: ["family:spynote", "android", "banker", "rat", "infostealer", "<b>x</b>"]},
  tasks: {
    [`${ID}-static1`]: {kind: "static", name: "static1", status: "reported", score: 10},
    [`${ID}-behavioral1`]: {kind: "behavioral", name: "behavioral1", os: "android-11-x64", status: "reported", score: 7},
    [`${ID}-behavioral2`]: {kind: "behavioral", name: "behavioral2", os: "android-9-x86", status: "failed", failure: "unable to install"},
  },
  signatures: [
    {name: "Declares services with permission to bind to the system", score: 6},
    {label: "spynote", name: "Family: Spynote", score: 10, desc: "Spynote is a Remote Access Trojan first seen in 2017.", tags: ["family:spynote"]},
    {label: "reads_sms_message", name: "Reads the content of the SMS messages.", score: 6},
  ],
  targets: [{
    sha256, tasks: ["behavioral1"], score: 7,
    iocs: {domains: ["android.apis.google.com", "www.youtube.com", "c.pki.goog", "api.ipify.org", "portbuddy.dev", "plqoj8czwx.localto.net"], ips: ["224.0.0.251", "1.1.1.1", "142.250.137.101", "104.26.13.205", "158.160.75.185", "45.9.20.11"], urls: ["http://c.pki.goog/r/r1.crl", "https://portbuddy.dev/api/v1/connect?token=victim-secret"]},
    signatures: [{label: "reads_sms_message", name: "Reads the content of the SMS messages.", score: 7, ttp: ["T1636.004", "bogus"]}, {label: "accessibility_service_usage", name: "Makes use of the framework's Accessibility service", score: 7}],
  }],
  extracted: [
    {config: {family: "spynote", rule: "Spynote4", c2: ["185.107.74.104:7771", "https://api.telegram.org/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw0/sendMessage"], botnet: "victim-farm", keys: [{kind: "aes_key", key: "config", value: "00112233445566778899aabbccddeeff"}], raw: "{\"host\":\"185.107.74.104\",\"password\":\"hunter2secret\"}"}, tasks: ["static1"]},
    {config: {family: "spynote", rule: "Spynote5", c2: ["185.107.74.104:7771", "plqoj8czwx.localto.net:5667"]}, tasks: ["behavioral1"]},
    {config: {family: "agenttesla", credentials: [{host: "ftp://ftp.vilimorin.com", password: "ODqJo~U!=@pQ(@;1", port: 21, protocol: "ftp", username: "ug03@vilimorin.com"}]}},
    {credentials: {flow: 52, host: "smtp.yandex.ru", password: "graceofgod@amen", port: 587, protocol: "smtp", username: "negozio@depadova.cf"}},
    {config: {family: "spynote", rule: "Spynote4"}},
  ],
});
const dynamic = () => ({network: {
  requests: [
    {flow: 6, dns_request: {domains: ["api.ipify.org"]}}, {flow: 6, dns_response: {domains: ["api.ipify.org"], ip: ["104.26.13.205"]}},
    {flow: 7, dns_request: {domains: ["portbuddy.dev"]}}, {flow: 7, dns_response: {domains: ["portbuddy.dev"], ip: ["158.160.75.185"]}},
    {flow: 9, http_request: {method: "POST", url: "http://45.9.20.11:8080/gate.php?id=victim-123"}},
    {flow: 13, http_request: {method: "GET", url: "http://ip-api.com/line/?fields=hosting"}},
  ],
  flows: [
    {id: 1, src: "10.127.0.175:5353", dst: "224.0.0.251:5353", proto: "udp"},
    {id: 5, src: "10.127.0.175:45604", dst: "142.250.137.101:443", proto: "tcp", protocols: ["tls", "https"]},
    {id: 6, src: "10.127.0.175:40021", dst: "1.1.1.1:53", proto: "udp", protocols: ["dns"], domain: "api.ipify.org"},
    {id: 8, src: "10.127.0.175:41000", dst: "104.26.13.205:443", proto: "tcp", protocols: ["tls"], tls_sni: "api.ipify.org"},
    {id: 10, src: "10.127.0.175:41002", dst: "158.160.75.185:443", proto: "tcp", protocols: ["tls"], tls_sni: "portbuddy.dev"},
    {id: 11, src: "10.127.0.175:41004", dst: "45.9.20.11:8080", proto: "tcp", protocols: ["http"]},
    {id: 12, src: "10.127.0.175:41006", dst: "not-an-ip", proto: "tcp"},
    {id: 13, src: "10.127.0.175:41008", dst: "208.95.112.1:80", proto: "tcp", protocols: ["http"], domain: "ip-api.com"},
  ],
}});

test("overview normalization: configs with C2s, masked secrets, noise-filtered IOCs, ranked signatures", () => {
  const {result: r, behavioral} = normalizeOverview(overview(), sha256);
  assert.deepEqual(behavioral, ["behavioral1"]);
  assert.equal(r.score, 10); assert.deepEqual(r.family, ["spynote"]); assert.deepEqual(r.tags, ["banker", "rat", "infostealer"]); assert.deepEqual(r.platforms, ["android-11-x64", "android-9-x86"]);
  const [spy, tesla] = r.configs!;
  assert.equal(r.configs!.length, 2);
  assert.deepEqual(spy.c2, ["185.107.74.104:7771", "https://api.telegram.org/bot123456789:…saw0/sendMessage", "plqoj8czwx.localto.net:5667"]);
  assert.equal(spy.rule, "Spynote4"); assert.equal(spy.botnet, "victim-farm");
  assert.deepEqual(spy.keys, [{kind: "aes_key", key: "config", value: "…eeff"}]);
  assert.equal(spy.raw, "{\"host\":\"185.107.74.104\",\"password\":\"…\"}");
  // Exfiltration credentials (config and flow-level) merged under the family; passwords masked.
  assert.equal(tesla.family, "agenttesla");
  assert.deepEqual(spy.credentials, [{protocol: "smtp", host: "smtp.yandex.ru", port: 587, username: "negozio@depadova.cf", password: "…amen"}]);
  assert.deepEqual(tesla.credentials, [{protocol: "ftp", host: "ftp://ftp.vilimorin.com", port: 21, username: "ug03@vilimorin.com", password: "…(@;1".slice(-5)}]);
  const text = JSON.stringify(r);
  for (const secret of ["AAHdqTcvCH1vGWJxfSeofSAs0K5PALD", "hunter2secret", "ODqJo~U!=@pQ", "graceofgod", "00112233445566778899aabbcc", "victim-secret"]) assert.ok(!text.includes(secret), secret);
  // Overview-only IOCs: Google/CDN/resolver/multicast/certificate noise dropped, query strings stripped.
  assert.deepEqual(r.contacted, [
    {kind: "http", host: "portbuddy.dev", url: "https://portbuddy.dev/api/v1/connect"},
    {kind: "ip", ip: "104.26.13.205"}, {kind: "ip", ip: "158.160.75.185"}, {kind: "ip", ip: "45.9.20.11"},
    {kind: "dns", host: "plqoj8czwx.localto.net"},
  ]);
  assert.deepEqual(r.signatures!.map(s => [s.label ?? s.name, s.score]), [["spynote", 10], ["reads_sms_message", 7], ["accessibility_service_usage", 7], ["Declares services with permission to bind to the system", 6]]);
  assert.deepEqual(r.signatures![1].ttp, ["T1636.004"]);
  assert.equal(r.message, undefined);
  assert.throws(() => normalizeOverview({...overview(), sample: {sha256: "b".repeat(64)}}, sha256), /tidak cocok/);
  assert.throws(() => normalizeOverview("nope", sha256));
});

test("dynamic report adds ports and SNI hostnames and drops IPs that only served filtered hosts", () => {
  const {result: r} = normalizeOverview(overview(), sha256, [dynamic()]);
  assert.deepEqual(r.contacted, [
    {kind: "http", ip: "45.9.20.11", url: "http://45.9.20.11:8080/gate.php", port: 8080, protocol: "HTTP"},
    {kind: "http", host: "portbuddy.dev", url: "https://portbuddy.dev/api/v1/connect", ip: "158.160.75.185", port: 443, protocol: "TLS"},
    {kind: "dns", host: "plqoj8czwx.localto.net"},
  ]);
  for (const noise of ["104.26.13.205", "victim-123", "ip-api", "208.95.112.1"]) assert.ok(!JSON.stringify(r).includes(noise), noise);
  // No behavioral task ran: only static results, said explicitly.
  const blind = overview(); for (const t of Object.values(blind.tasks)) if (t.kind === "behavioral") t.status = "failed";
  assert.match(normalizeOverview(blind).result.message || "", /tidak berhasil menjalankan/);
  // Bounded output.
  const big = overview(); big.targets[0].iocs.domains = Array.from({length: 100}, (_, i) => `c2-${i}.evil${i}.xyz`);
  big.signatures = Array.from({length: 80}, (_, i) => ({name: `sig ${i} ${"x".repeat(300)}`, score: i % 10, label: `l${i}`, desc: "y".repeat(500)})) as never;
  const b = normalizeOverview(big).result; assert.ok(b.contacted!.length <= 20 && b.signatures!.length <= 12 && JSON.stringify(b).length < 12000);
  assert.equal(mask("short"), "…"); assert.equal(mask(undefined), undefined); assert.equal(mask({k: "abcdefghijklmnop"}), "…op\"}");
});

test("status polling: waiting, failed, rate limited, timeout and reported transitions", async () => {
  const waiting: TriageResult = {status: "pending", sampleId: ID, submittedAt: iso(T0), checkedAt: iso(T0), nextCheck: iso(T0 + FIRST_CHECK_MS)};
  const at = T0 + 5 * 60_000;
  for (const [status, expected] of [["static_analysis", "pending"], ["scheduled", "pending"], ["running", "running"], ["processing", "running"]] as const) {
    await withTriage(() => Response.json({id: ID, status}), async options => {
      const r = await checkTriage(waiting, sha256, options);
      assert.equal(r.status, expected); assert.equal(r.nextCheck, iso(at + INTERVAL_MS)); assert.equal(r.checkedAt, iso(at));
    }, {now: at});
  }
  await withTriage(() => Response.json({id: ID, status: "failed"}), async options => { const r = await checkTriage(waiting, sha256, options); assert.equal(r.status, "failed"); assert.equal(r.nextCheck, undefined); });
  await withTriage(() => new Response(null, {status: 404}), async options => assert.equal((await checkTriage(waiting, sha256, options)).status, "failed"));
  await withTriage(() => new Response(null, {status: 429}), async options => { const r = await checkTriage(waiting, sha256, options); assert.equal(r.status, "rate_limited"); assert.equal(r.nextCheck, iso(at + RATE_RETRY_MS)); }, {now: at});
  await withTriage(() => new Response(null, {status: 502}), async options => { const r = await checkTriage(waiting, sha256, options); assert.equal(r.status, "pending"); assert.ok(r.nextCheck); });
  await withTriage(() => Response.json({id: "260101-otherother", status: "reported"}), async options => assert.equal((await checkTriage(waiting, sha256, options)).status, "pending"));
  // Still running 30 minutes after submission: stop polling.
  await withTriage(() => Response.json({id: ID, status: "running"}), async options => { const r = await checkTriage(waiting, sha256, options); assert.equal(r.status, "failed"); assert.equal(r.nextCheck, undefined); assert.match(r.message || "", /30 menit/); }, {now: T0 + 31 * 60_000});
  assert.equal(expire({...waiting, status: "rate_limited"}, T0 + 31 * 60_000).status, "rate_limited");
  // Reported: overview + the reported behavioral task's dynamic report; a failing dynamic report is optional.
  for (const dyn of [true, false]) {
    await withTriage(c => path(c) === `/samples/${ID}` ? Response.json({id: ID, status: "reported"}) : path(c).endsWith("/overview.json") ? Response.json(overview()) : dyn ? Response.json(dynamic()) : new Response(null, {status: 500}), async (options, calls) => {
      const r = await checkTriage({...waiting, message: "old"}, sha256, options);
      assert.deepEqual(calls.map(path), [`/samples/${ID}`, `/samples/${ID}/overview.json`, `/samples/${ID}/behavioral1/report_triage.json`]);
      assert.equal(r.status, "reported"); assert.equal(r.nextCheck, undefined); assert.equal(r.message, undefined); assert.equal(r.score, 10); assert.equal(r.url, `https://tria.ge/${ID}`);
      assert.equal(r.contacted!.some(c => c.port === 443), dyn);
    }, {now: at});
  }
  // Mismatched hash in the overview is not stored.
  await withTriage(c => path(c) === `/samples/${ID}` ? Response.json({id: ID, status: "reported"}) : Response.json({...overview(), sample: {sha256: "b".repeat(64)}}), async options => {
    const r = await checkTriage(waiting, sha256, options); assert.notEqual(r.status, "reported"); assert.ok(r.nextCheck);
  }, {now: at});
});

const assessment = (risk: Assessment["risk"]): Assessment => ({risk, confidence: "medium", summary: `ringkasan ${risk}`, findings: [], recommendations: ["Jangan pasang."], limitations: ["Analisis statis."]});
const report = (): Report => {
  const artifact: Artifact = {filename: "kurir.apk", kind: "apk", size: 10, sha256, metadata: {campaign: {hosts: ["panel.kurir-paket.my.id"], telegramBots: ["123456789"]}}, strings: [], urls: [], indicators: [{name: "Izin SMS", evidence: "READ_SMS"}], limitations: [], incomplete: false,
    threatIntel: {checkedAt: iso(T0), hosts: ["panel.kurir-paket.my.id"], urlhaus: [], threatfox: [], domains: [{domain: "kurir-paket.my.id", ageDays: 12}], skipped: ["x"]}};
  return {id: "11111111-1111-4111-8111-111111111111", createdAt: iso(T0), filename: "kurir.apk", kind: "apk", size: 10, sha256, model: "m1", durationMs: 1, assessment: assessment("medium"), artifact};
};

test("reported sandbox data is merged into hosts, checked for reputation and re-assessed by the AI", async () => {
  const {result} = normalizeOverview(overview(), sha256, [dynamic()]);
  const triage: TriageResult = {...result, status: "reported", sampleId: ID, submittedAt: iso(T0), checkedAt: iso(T0)};
  assert.deepEqual(configHosts(triage), ["185.107.74.104", "plqoj8czwx.localto.net", "ftp.vilimorin.com"]);
  const probes: Artifact[] = [], seen: Artifact[] = [];
  const fresh: ThreatIntelResult = {checkedAt: iso(T0 + 1), hosts: ["185.107.74.104"], urlhaus: [], threatfox: [{term: "185.107.74.104", family: "SpyNote", matches: 1}], domains: [], errors: ["y"]};
  const deps = {now: () => T0 + 9, inspect: async (a: Artifact) => { probes.push(a); return fresh; }};
  const before = report();
  const out = await finishTriage(before, triage, {...deps, assess: async (a: Artifact, o?: {budgetMs?: number}) => { seen.push(a); assert.ok((o?.budgetMs ?? 0) > 0); return {assessment: assessment("critical"), model: "m2"}; }});
  // Config C2s first, then sandbox contacts; earlier static hosts kept; at most 8 fresh.
  const hosts = (out.artifact.metadata.campaign as {hosts: string[]}).hosts;
  assert.deepEqual(hosts, ["185.107.74.104", "plqoj8czwx.localto.net", "ftp.vilimorin.com", "portbuddy.dev", "45.9.20.11", "158.160.75.185", "panel.kurir-paket.my.id"]);
  assert.deepEqual((out.artifact.metadata.campaign as {telegramBots: string[]}).telegramBots, ["123456789"]);
  // Reputation only for the new hosts, no hash lookup; merged with the stored result.
  assert.equal(probes.length, 1); assert.equal(probes[0].sha256, ""); assert.deepEqual((probes[0].metadata.campaign as {hosts: string[]}).hosts, hosts.slice(0, 6));
  assert.equal(out.artifact.threatIntel!.domains.length, 1); assert.equal(out.artifact.threatIntel!.threatfox[0].family, "SpyNote"); assert.deepEqual(out.artifact.threatIntel!.skipped, ["x"]); assert.deepEqual(out.artifact.threatIntel!.errors, ["y"]);
  assert.match(out.artifact.indicators[0].name, /ThreatFox/);
  assert.ok(out.artifact.indicators.some(i => /^Sandbox Tria\.ge menilai berbahaya \(skor 10\/10, famili spynote\)/.test(i.name)));
  assert.ok(out.artifact.indicators.some(i => /^Konfigurasi malware diekstrak sandbox Tria\.ge \(spynote\/agenttesla\)/.test(i.name)));
  // The AI saw the enriched artifact; the report keeps its id and records the update.
  assert.equal(seen[0].triage?.status, "reported"); assert.equal(out.id, before.id); assert.equal(out.assessment.risk, "critical"); assert.equal(out.model, "m2");
  assert.equal(out.artifact.triage?.reassessedAt, iso(T0 + 9)); assert.ok(out.assessment.limitations.some(l => l.startsWith("Sandbox Tria.ge:")));
  assert.equal((before.artifact.metadata.campaign as {hosts: string[]}).hosts.length, 1, "input report is not mutated");
  // AI failure: sandbox data is still stored, the earlier verdict stays.
  const kept = await finishTriage(report(), triage, {...deps, assess: async () => { throw new Error("gateway down"); }});
  assert.equal(kept.assessment.risk, "medium"); assert.equal(kept.model, "m1"); assert.equal(kept.artifact.triage?.reassessedAt, undefined); assert.match(kept.artifact.triage?.message || "", /penilaian awal tetap/);
  assert.equal(kept.artifact.triage?.configs?.length, 2);
  // Failed reputation lookup does not block the re-assessment.
  const noIntel = await finishTriage(report(), triage, {inspect: async () => { throw new Error("x"); }, assess: async () => ({assessment: assessment("high"), model: "m3"})});
  assert.equal(noIntel.assessment.risk, "high");
  // Not reported (failed/timeout): stored as is, no AI call, no host changes.
  const failed = await finishTriage(report(), {status: "failed", submittedAt: iso(T0), checkedAt: iso(T0), message: "x"}, {assess: async () => { throw new Error("must not be called"); }});
  assert.equal(failed.artifact.triage?.status, "failed"); assert.deepEqual((failed.artifact.metadata.campaign as {hosts: string[]}).hosts, ["panel.kurir-paket.my.id"]);
  // Re-applying is idempotent.
  const a = report().artifact; a.triage = triage; mergeTriageHosts(a); applyTriageIndicators(a); applyTriageIndicators(a);
  assert.equal(a.indicators.filter(i => i.name.startsWith("Sandbox Tria.ge")).length, 1); assert.deepEqual(mergeTriageHosts(a), []);
});

test("reputation merge keeps earlier hits and deduplicates", () => {
  const old: ThreatIntelResult = {checkedAt: "a", hosts: ["x.com"], urlhaus: [{target: "x.com", kind: "host"}], threatfox: [], domains: [{domain: "x.com"}]};
  const merged = mergeIntel(old, {checkedAt: "b", hosts: ["x.com", "y.com"], urlhaus: [{target: "x.com", kind: "host"}, {target: "y.com", kind: "host"}], threatfox: [], domains: []});
  assert.deepEqual(merged.hosts, ["x.com", "y.com"]); assert.equal(merged.urlhaus.length, 2); assert.equal(merged.checkedAt, "b"); assert.equal(merged.skipped, undefined);
});
