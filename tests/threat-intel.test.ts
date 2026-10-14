import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { applyThreatIntel, inspectThreatIntel, registrableDomain, threatIntelTargets } from "../lib/threat-intel";
import type { Artifact, ThreatIntelResult } from "../lib/types";

const sha256 = "c".repeat(64);
const artifact = (urls: string[] = [], hosts: string[] = []): Artifact => ({ filename: "kurir.apk", kind: "apk", size: 10, sha256, metadata: hosts.length ? { campaign: { hosts } } : {}, strings: [], urls, indicators: [{ name: "Izin SMS", evidence: "READ_SMS" }], limitations: [], incomplete: false });
type Call = { url: string; init?: RequestInit; body: string };
type Route = (call: Call) => Response | Promise<Response>;
const days = (n: number) => new Date(Date.now() - n * 86400000).toISOString();
const rdapBody = (domain: string, registered: string) => ({ objectClassName: "domain", ldhName: domain.toUpperCase(), events: [{ eventAction: "registration", eventDate: registered }, { eventAction: "expiration", eventDate: "2030-01-01T00:00:00Z" }], entities: [{ roles: ["registrar"], vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Contoh Registrar"]]] }] });
const none: Route = ({ url }) => url.startsWith("https://rdap.org/") ? new Response(null, { status: 404 }) : url.includes("threatfox") ? Response.json({ query_status: "no_result", data: "Your search did not yield any results" }) : url.includes("mb-api") ? Response.json({ query_status: "hash_not_found" }) : Response.json({ query_status: "no_results" });

async function run(t: TestContext, a: Artifact, route: Route, { key = "fake-abuse-key", ...options }: { key?: string | null; budgetMs?: number; timeoutMs?: number; gate?: (p: string) => Promise<boolean> } = {}) {
  const previous = process.env.ABUSE_CH_AUTH_KEY; if (key === null) delete process.env.ABUSE_CH_AUTH_KEY; else process.env.ABUSE_CH_AUTH_KEY = key;
  const calls: Call[] = [];
  t.mock.method(globalThis, "fetch", () => { throw new Error("global fetch must not be used"); });
  const fake = async (url: string, init?: RequestInit) => {
    const body = init?.body instanceof URLSearchParams ? init.body.toString() : String(init?.body ?? ""); const call = { url, init, body }; calls.push(call);
    assert.ok(init?.signal instanceof AbortSignal); assert.ok(!url.includes("fake-abuse-key"));
    if (!url.startsWith("https://rdap.org/")) { assert.equal(new Headers(init?.headers).get("auth-key"), "fake-abuse-key"); assert.equal(init?.redirect, "error"); }
    else assert.equal(new Headers(init?.headers).get("auth-key"), null);
    assert.match(new Headers(init?.headers).get("user-agent") || "", /^Kheronyx\//);
    return route(call);
  };
  try { const result = await inspectThreatIntel(a, { fetch: fake, requestGate: options.gate as never || (async () => true), budgetMs: options.budgetMs, timeoutMs: options.timeoutMs }); return { result, calls }; }
  finally { if (previous === undefined) delete process.env.ABUSE_CH_AUTH_KEY; else process.env.ABUSE_CH_AUTH_KEY = previous; t.mock.restoreAll(); }
}

test("eTLD+1 approximation handles Indonesian and multi-part suffixes, platforms and IPs", () => {
  assert.equal(registrableDomain("panel.kurir-paket.my.id"), "kurir-paket.my.id");
  assert.equal(registrableDomain("a.b.example.co.id"), "example.co.id");
  assert.equal(registrableDomain("shop.example.co.uk"), "example.co.uk");
  assert.equal(registrableDomain("api.evil-panel.xyz"), "evil-panel.xyz");
  assert.equal(registrableDomain("my.id"), null); assert.equal(registrableDomain("x.my.id"), "x.my.id");
  assert.equal(registrableDomain("tenant.firebaseio.com"), null); assert.equal(registrableDomain("45.9.1.2"), null);
});

test("benign infrastructure, private/reserved IPs, shared services and secret-bearing URLs are never looked up", () => {
  const a = artifact([
    "https://www.google.com/x", "http://schemas.android.com/apk/res/android", "https://fonts.gstatic.com/a.ttf", "https://github.com/user/repo",
    "http://192.168.1.10/panel.php", "http://10.0.0.1/", "http://127.0.0.1:8080/x", "http://100.64.1.1/a", "http://localhost/a", "http://config.json/a",
    "https://api.telegram.org/bot123456789:…abcd/sendMessage", "https://evil.example-shop.top/pay?token=abc", "https://raw.githubusercontent.com/u/r/main/payload.apk",
    "http://45.9.20.11:8080/api/upload.php", "https://panel.kurir-paket.my.id/gate.php",
  ], ["45.9.20.11:8080", "panel.kurir-paket.my.id"]);
  const { hosts, urls, domains } = threatIntelTargets(a);
  assert.deepEqual(hosts, ["45.9.20.11", "panel.kurir-paket.my.id", "evil.example-shop.top"]);
  assert.deepEqual(urls, ["https://raw.githubusercontent.com/u/r/main/payload.apk", "http://45.9.20.11:8080/api/upload.php", "https://panel.kurir-paket.my.id/gate.php"]);
  assert.deepEqual(domains, ["kurir-paket.my.id", "example-shop.top"]);
  assert.ok(!urls.some(u => /token|bot\d|…/.test(u)));
  const many = threatIntelTargets(artifact(Array.from({ length: 40 }, (_, i) => `https://h${i}.evil${i}.xyz/a/b.apk`)));
  assert.equal(many.hosts.length, 12); assert.equal(many.urls.length, 3); assert.equal(many.domains.length, 8);
});

test("MalwareBazaar, URLhaus and ThreatFox hits become high indicators; RDAP young domain is reported", async t => {
  const a = artifact(["https://panel.kurir-paket.my.id/gate.php"], ["panel.kurir-paket.my.id"]);
  const { result, calls } = await run(t, a, call => {
    if (call.url.includes("mb-api")) { assert.equal(call.body, `query=get_info&hash=${sha256}`); return Response.json({ query_status: "ok", data: [{ sha256_hash: sha256, signature: "SpyNote", tags: ["apk", "spynote", "rat"], first_seen: "2025-03-01 10:00:00", file_type: "apk", delivery_method: "web_download", vendor_intel: { "ANY.RUN": [{ malware_family: "spynote", verdict: "Malicious activity" }], ReversingLabs: { threat_name: "Android.Trojan.SpyNote", status: "MALICIOUS" }, Triage: { malware_family: null, score: "10" } }, comments: "x".repeat(5000) }] }); }
    if (call.url.endsWith("/v1/host/")) { assert.equal(call.body, "host=panel.kurir-paket.my.id"); return Response.json({ query_status: "ok", urlhaus_reference: "https://urlhaus.abuse.ch/host/panel.kurir-paket.my.id/", host: "panel.kurir-paket.my.id", firstseen: "2026-09-30 08:00:00 UTC", url_count: "3", blacklists: { spamhaus_dbl: "abused_legit_malware", surbl: "not listed" }, urls: [{ url: "https://panel.kurir-paket.my.id/a.apk", url_status: "online", threat: "malware_download", tags: ["apk", "smsspy"] }, { url_status: "offline", threat: "malware_download", tags: null }] }); }
    if (call.url.endsWith("/v1/url/")) return Response.json({ query_status: "no_results" });
    if (call.url.includes("threatfox")) { assert.deepEqual(JSON.parse(call.body), { query: "search_ioc", search_term: "panel.kurir-paket.my.id" }); return Response.json({ query_status: "ok", data: [{ id: "1234", ioc: "panel.kurir-paket.my.id", threat_type: "botnet_cc", malware_printable: "SMSspy", confidence_level: 75, first_seen: "2026-10-01 00:00:00 UTC" }, { id: "99", ioc: "other.kurir-paket.my.id", malware_printable: "Unrelated" }] }); }
    assert.equal(call.url, "https://rdap.org/domain/kurir-paket.my.id"); return Response.json(rdapBody("kurir-paket.my.id", days(12)));
  });
  assert.equal(calls.length, 5);
  assert.equal(result.malwareBazaar?.family, "SpyNote"); assert.deepEqual(result.malwareBazaar?.tags, ["apk", "spynote", "rat"]); assert.equal(result.malwareBazaar?.firstSeen, "2025-03-01");
  assert.deepEqual(result.malwareBazaar?.vendors, ["ANY.RUN: spynote", "ReversingLabs: Android.Trojan.SpyNote"]);
  assert.equal(result.urlhaus[0].urlCount, 3); assert.equal(result.urlhaus[0].online, 1); assert.deepEqual(result.urlhaus[0].blacklists, ["spamhaus_dbl: abused_legit_malware"]);
  assert.deepEqual(result.threatfox, [{ term: "panel.kurir-paket.my.id", family: "SMSspy", threatType: "botnet_cc", confidence: 75, firstSeen: "2026-10-01", matches: 1, reference: "https://threatfox.abuse.ch/ioc/1234/" }]);
  assert.equal(result.domains[0].domain, "kurir-paket.my.id"); assert.equal(result.domains[0].ageDays, 12); assert.equal(result.domains[0].registrar, "Contoh Registrar");
  assert.equal(result.skipped, undefined); assert.equal(result.errors, undefined);
  assert.ok(JSON.stringify(result).length < 4000); assert.ok(!JSON.stringify(result).includes("xxxxx"));
  applyThreatIntel(a, result); applyThreatIntel(a, result);
  assert.deepEqual(a.indicators.map(i => i.name), ["File dikenal sebagai malware di MalwareBazaar (SpyNote)", "Server tercatat sebagai penyebar malware (URLhaus)", "Indikator dikenal di ThreatFox (SMSspy)", "Domain baru didaftarkan (12 hari)", "Izin SMS"]);
  assert.match(a.indicators[0].evidence, /^Tingkat kritis: .*SpyNote/); assert.match(a.indicators[3].evidence, /^Tingkat tinggi: kurir-paket\.my\.id didaftarkan/);
  assert.equal(a.threatIntel, result);
});

test("medium-age domains and low-confidence IOCs are appended as medium indicators", () => {
  const a = artifact(); const r: ThreatIntelResult = { checkedAt: "", hosts: [], urlhaus: [], threatfox: [{ term: "x.evil.top", family: null, confidence: 25, matches: 1 }], domains: [{ domain: "evil.top", registered: "2026-07-01", ageDays: 100 }, { domain: "old.com", registered: "2001-01-01", ageDays: 9000 }] };
  applyThreatIntel(a, r);
  assert.deepEqual(a.indicators.map(i => i.name), ["Izin SMS", "Indikator dikenal di ThreatFox (famili tidak disebut)", "Domain baru didaftarkan (100 hari)"]);
  assert.ok(a.indicators.slice(1).every(i => i.evidence.startsWith("Tingkat sedang")));
});

test("MalwareBazaar family falls back to a non-generic tag when the signature is empty", () => {
  const a = artifact(); applyThreatIntel(a, { checkedAt: "", hosts: [], urlhaus: [], threatfox: [], domains: [], malwareBazaar: { family: null, tags: ["apk", "signed", "SmsSpy", "Spy.Banker"] } });
  assert.equal(a.indicators[0].name, "File dikenal sebagai malware di MalwareBazaar (SmsSpy)"); assert.match(a.indicators[0].evidence, /^Tingkat kritis: .*tag famili SmsSpy/);
  applyThreatIntel(a, { checkedAt: "", hosts: [], urlhaus: [], threatfox: [], domains: [], malwareBazaar: { family: null, tags: ["exe", "signed"] } });
  assert.equal(a.indicators[0].name, "File dikenal sebagai malware di MalwareBazaar (famili tidak disebut)"); assert.equal(a.indicators.length, 2);
});

test("missing Auth-Key skips abuse.ch entirely but still checks RDAP domain age", async t => {
  const { result, calls } = await run(t, artifact(["https://cdn.new-panel.xyz/a/b.apk"]), call => Response.json(rdapBody("new-panel.xyz", days(400))), { key: null });
  assert.deepEqual(calls.map(c => c.url), ["https://rdap.org/domain/new-panel.xyz"]);
  assert.equal(result.malwareBazaar, undefined); assert.match(result.skipped?.[0] || "", /ABUSE_CH_AUTH_KEY/);
  assert.equal(result.domains[0].ageDays, 400);
  const a = artifact(); applyThreatIntel(a, result); assert.equal(a.indicators.length, 1);
});

test("unknown hash and clean hosts produce no indicators", async t => {
  const { result } = await run(t, artifact(["https://cdn.new-panel.xyz/a/b.apk"]), none);
  assert.equal(result.malwareBazaar, null); assert.deepEqual([result.urlhaus, result.threatfox, result.domains], [[], [], []]); assert.equal(result.errors, undefined);
  const a = artifact(); applyThreatIntel(a, result); assert.equal(a.indicators.length, 1);
});

test("timeouts, network errors, malformed or oversized JSON, wrong hashes and auth failures never throw", async t => {
  const a = artifact(["https://cdn.new-panel.xyz/a/b.apk", "http://45.9.20.11/x/y.php"]);
  const cases: Route[] = [
    () => { throw new TypeError("fetch failed"); },
    () => new Response("not json"),
    () => new Response("{".padEnd(2 * 1024 * 1024, " ")),
    ({ url }) => url.includes("mb-api") ? Response.json({ query_status: "ok", data: [{ sha256_hash: "d".repeat(64), signature: "X" }] }) : Response.json({ query_status: "ok", data: "garbage", urls: 5 }),
    ({ url }) => url.includes("rdap") ? Response.json({ ldhName: "someone-else.com", events: [{ eventAction: "registration", eventDate: days(1) }] }) : new Response(null, { status: 401 }),
    () => Response.json(null), () => Response.json([1, 2]), () => new Response(null, { status: 500 }),
  ];
  for (const route of cases) {
    const { result } = await run(t, a, route);
    assert.equal(result.malwareBazaar?.family ?? null, null); assert.ok(result.urlhaus.every(h => h.urlCount === undefined || h.urlCount >= 0)); assert.equal(result.domains.filter(d => d.ageDays !== undefined && d.ageDays < 30).length, 0);
    assert.ok(result.errors?.length); assert.ok(!JSON.stringify(result).includes("fake-abuse-key"));
  }
  // Auth failure stops all further abuse.ch requests.
  const denied = await run(t, a, ({ url }) => url.includes("rdap") ? new Response(null, { status: 404 }) : new Response(null, { status: 403 }));
  assert.ok(denied.calls.filter(c => !c.url.includes("rdap")).length <= 4); assert.deepEqual(denied.result.errors, ["Auth-Key abuse.ch ditolak; periksa ABUSE_CH_AUTH_KEY."]);
  // Hanging providers: per-request timeout and total budget both hold.
  const hang: Route = ({ init }) => new Promise((_, reject) => init?.signal?.addEventListener("abort", () => reject(init.signal!.reason)));
  let start = Date.now(); let { result } = await run(t, a, hang, { timeoutMs: 50 });
  assert.ok(Date.now() - start < 2000); assert.match(result.errors?.join(" ") || "", /batas waktu/);
  start = Date.now(); ({ result } = await run(t, a, hang, { timeoutMs: 10000, budgetMs: 150 }));
  assert.ok(Date.now() - start < 1500); assert.match(result.errors?.join(" ") || "", /Batas waktu pemeriksaan reputasi tercapai/);
});

test("exhausted quota skips lookups with a note instead of failing", async t => {
  const { result, calls } = await run(t, artifact(["https://cdn.new-panel.xyz/a/b.apk"]), none, { gate: async p => p === "rdap" });
  assert.deepEqual(calls.map(c => c.url), ["https://rdap.org/domain/new-panel.xyz"]);
  assert.deepEqual(result.skipped, ["Kuota pemeriksaan abuse.ch tercapai; sebagian indikator tidak diperiksa."]); assert.equal(result.errors, undefined);
});

test("worst-case result stays compact for the AI evidence guard", async t => {
  const long = (p: string) => `${p}-${"x".repeat(300)}`;
  const urls = Array.from({ length: 30 }, (_, i) => `https://h${i}.evil${i}.xyz/a/b${i}.apk`);
  const { result } = await run(t, artifact(urls), ({ url, body }) => {
    if (url.includes("rdap")) return Response.json(rdapBody(decodeURIComponent(url.split("/").pop()!), days(3)));
    if (url.includes("mb-api")) return Response.json({ query_status: "ok", data: [{ sha256_hash: sha256, signature: long("fam"), tags: Array(50).fill(0).map((_, i) => long(`t${i}`)), vendor_intel: Object.fromEntries(Array.from({ length: 30 }, (_, i) => [long(`v${i}`), { threat_name: long("n") }])) }] });
    if (url.includes("threatfox")) { const host = JSON.parse(body).search_term; return Response.json({ query_status: "ok", data: Array(300).fill({ id: 1, ioc: host, threat_type: long("tt"), malware_printable: long("m"), confidence_level: 100 }) }); }
    const host = new URLSearchParams(body).get("host") || "x";
    return Response.json({ query_status: "ok", url_count: 999, url_status: "online", threat: long("th"), tags: Array(40).fill(0).map((_, i) => long(`g${i}`)), blacklists: { a: long("b"), b: long("c"), c: long("d"), d: long("e") }, urlhaus_reference: `https://urlhaus.abuse.ch/host/${host}/`, urls: Array(500).fill({ url_status: "online", threat: long("th"), tags: [long("x")] }), payloads: Array(60).fill({ signature: long("s") }) });
  });
  assert.equal(result.urlhaus.length + result.threatfox.length > 0, true);
  assert.ok(JSON.stringify(result).length <= 6000, `threatIntel ${JSON.stringify(result).length} chars`);
  const a = artifact(); applyThreatIntel(a, result);
  assert.ok(a.indicators.length <= 9); assert.ok(a.indicators.every(i => i.evidence.length <= 400));
});
