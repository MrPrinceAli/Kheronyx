import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { fetchBehaviour, mergeSandboxHosts, normalizeBehaviour, virusTotalKnown } from "../lib/virustotal";
import { inspectReputation } from "../lib/pipeline";
import { pickSandbox } from "../lib/virus-total-evidence";
import type { Artifact, SandboxResult } from "../lib/types";

const sha256 = "9cf45ae2bb508d6ef14f8f52999ef9c8caa7831b62355772a03d9ed1795c1825";
// Shape of a real behaviour_summary (SMS stealer APK): Google noise plus two operator servers.
const fixture = () => ({ data: {
  dns_lookups: [
    { hostname: "www.googleapis.com", resolved_ips: ["142.251.31.95", "74.125.128.95"] },
    { hostname: "c.tenor.com", resolved_ips: ["142.251.31.132"] },
    { hostname: "connectivitycheck.gstatic.com", resolved_ips: ["74.125.128.94"] },
    { hostname: "a8p.net", resolved_ips: ["64.227.112.222"] },
    { hostname: "www.happyapis.com", resolved_ips: ["195.123.224.81"] },
    { hostname: "ocsp.digicert.com", resolved_ips: ["93.184.220.29"] },
    { hostname: "wpad.localdomain", resolved_ips: ["10.0.2.2"] },
    { hostname: 42 },
  ],
  ip_traffic: [
    { destination_ip: "142.251.31.132", destination_port: 443, transport_layer_protocol: "TCP" },
    { destination_ip: "108.177.119.138", destination_port: 443, transport_layer_protocol: "TCP" },
    { destination_ip: "64.227.112.222", destination_port: 443, transport_layer_protocol: "TCP" },
    { destination_ip: "195.123.224.81", destination_port: 443, transport_layer_protocol: "TCP" },
    { destination_ip: "74.125.128.94", destination_port: 80, transport_layer_protocol: "TCP" },
    { destination_ip: "93.184.220.29", destination_port: 80, transport_layer_protocol: "TCP" },
    { destination_ip: "10.0.2.15", destination_port: 8080, transport_layer_protocol: "TCP" },
    { destination_ip: "162.159.36.2", destination_port: 53, transport_layer_protocol: "UDP" },
    { destination_ip: "45.9.20.11", destination_port: 7771, transport_layer_protocol: "TCP" },
    { destination_ip: "45.9.20.11", destination_port: "bad" },
  ],
  http_conversations: [
    { url: "http://connectivitycheck.gstatic.com/generate_204", request_method: "GET", response_status_code: 204 },
    { url: "https://www.happyapis.com/data_20/checker_20.php?id=victim-123", request_method: "POST", response_status_code: 200 },
  ],
  tags: ["OBFUSCATED", "SENDS_SMS", "REFLECTION", "OBFUSCATED", "<script>"],
  verdicts: ["MALWARE"],
  mitre_attack_techniques: [
    { id: "T1406", severity: "IMPACT_SEVERITY_INFO", signature_description: "Obfuscates method names" },
    { id: "T1412", severity: "IMPACT_SEVERITY_INFO", signature_description: "Monitors incoming SMS" },
    { id: "T1071", severity: "IMPACT_SEVERITY_INFO", signature_description: "Performs DNS lookups" },
    { id: "T1071", severity: "IMPACT_SEVERITY_LOW", signature_description: "Uses HTTPS" },
    { id: "T1448", severity: "IMPACT_SEVERITY_MEDIUM", signature_description: "Has permission to send SMS in the background" },
    { id: "not-an-id", signature_description: "x" },
  ],
  signature_matches: [
    { description: "Removes its application launcher (likely to stay hidden)", severity: "IMPACT_SEVERITY_LOW" },
    { description: "Uses HTTPS", severity: "IMPACT_SEVERITY_INFO" },
    { description: "load-code/dotnet", severity: "IMPACT_SEVERITY_MEDIUM" },
    { description: "Unable to instrument or execute APK, no dynamic information has been logged", severity: "IMPACT_SEVERITY_INFO" },
  ],
  processes_created: ["/system/bin/sh"],
} });

test("behaviour summary keeps operator servers, maps IPs to hostnames and filters vendor noise", () => {
  const r = normalizeBehaviour(fixture(), "2026-10-14T00:00:00.000Z");
  assert.equal(r.status, "completed"); assert.equal(r.source, "virustotal"); assert.equal(r.fetchedAt, "2026-10-14T00:00:00.000Z");
  assert.deepEqual(r.contacted, [
    { kind: "http", host: "www.happyapis.com", url: "https://www.happyapis.com/data_20/checker_20.php", ip: "195.123.224.81", port: 443, protocol: "TCP" },
    { kind: "ip", host: "a8p.net", ip: "64.227.112.222", port: 443, protocol: "TCP" },
    { kind: "ip", ip: "45.9.20.11", port: 7771, protocol: "TCP" },
  ]);
  const text = JSON.stringify(r.contacted);
  for (const noise of ["google", "gstatic", "tenor", "142.251", "108.177", "74.125", "digicert", "93.184", "10.0", "162.159", "victim-123", "wpad"]) assert.ok(!text.includes(noise), noise);
  assert.deepEqual(r.tags, ["OBFUSCATED", "SENDS_SMS", "REFLECTION"]); assert.deepEqual(r.verdicts, ["MALWARE"]);
  assert.deepEqual(r.mitre.map(m => [m.id, m.severity]), [["T1448", "medium"], ["T1071", "low"], ["T1406", "info"], ["T1412", "info"]]);
  assert.equal(r.mitre[1].description, "Uses HTTPS");
  assert.equal(r.highlights?.[0], "Sebagian sandbox tidak berhasil menjalankan file sepenuhnya; perilaku yang tercatat bisa belum lengkap.");
  assert.deepEqual(r.highlights?.slice(1), ["Removes its application launcher (likely to stay hidden)"]);
  assert.deepEqual(r.counts, { dns: 7, ip: 10, http: 2, processes: 1, filesDropped: 0, filtered: 12 });
});

test("contacted, MITRE and tag lists are capped", () => {
  const n = (i: number) => `${(i % 200) + 20}.${i % 250}.1.${(i % 250) + 1}`;
  const r = normalizeBehaviour({ data: {
    dns_lookups: Array.from({ length: 60 }, (_, i) => ({ hostname: `c2-${i}.evil${i}.xyz`, resolved_ips: [n(i)] })),
    ip_traffic: Array.from({ length: 60 }, (_, i) => ({ destination_ip: n(i + 100), destination_port: 4444 })),
    mitre_attack_techniques: Array.from({ length: 40 }, (_, i) => ({ id: `T${1000 + i}`, severity: "IMPACT_SEVERITY_LOW", signature_description: "x".repeat(900) })),
    tags: Array.from({ length: 40 }, (_, i) => `TAG_${i}`), verdicts: Array.from({ length: 20 }, (_, i) => `V${i}`),
  } });
  assert.equal(r.contacted.length, 20); assert.equal(r.mitre.length, 12); assert.equal(r.tags.length, 15); assert.equal(r.verdicts.length, 6);
  assert.ok(r.mitre.every(m => m.description.length <= 160)); assert.ok(JSON.stringify(r).length < 8000);
});

type Call = { url: string; init?: RequestInit };
async function withVt(t: TestContext, route: (call: Call) => Response | Promise<Response>, run: (calls: Call[]) => Promise<void>) {
  const previous = process.env.VIRUSTOTAL_API_KEY; process.env.VIRUSTOTAL_API_KEY = "fake-unit-test-key";
  const calls: Call[] = [];
  t.mock.method(globalThis, "fetch", async (url: unknown, init?: RequestInit) => {
    const call = { url: String(url), init }; calls.push(call);
    assert.equal(new Headers(init?.headers).get("x-apikey"), "fake-unit-test-key"); assert.ok(init?.signal instanceof AbortSignal); assert.equal(init?.redirect, "error");
    return route(call);
  });
  try { await run(calls); } finally { if (previous === undefined) delete process.env.VIRUSTOTAL_API_KEY; else process.env.VIRUSTOTAL_API_KEY = previous; t.mock.restoreAll(); }
}
const open = { requestGate: async () => true };

test("fetchBehaviour: one request, empty and unknown files, malformed data and quota never throw", async t => {
  await withVt(t, () => Response.json(fixture()), async calls => {
    const r = await fetchBehaviour(sha256, open);
    assert.equal(calls.length, 1); assert.equal(calls[0].url, `https://www.virustotal.com/api/v3/files/${sha256}/behaviour_summary`);
    assert.equal(r.status, "completed"); assert.equal(r.contacted.length, 3);
  });
  for (const [response, status] of [[Response.json({ data: {} }), "empty"], [new Response(null, { status: 404 }), "empty"], [new Response("invalid json"), "error"], [Response.json({ data: "nope" }), "error"], [Response.json([1, 2]), "error"], [new Response(null, { status: 429 }), "rate_limited"], [new Response(null, { status: 401 }), "error"]] as const) {
    await withVt(t, () => response, async () => {
      const r = await fetchBehaviour(sha256, open);
      assert.equal(r.status, status); assert.deepEqual(r.contacted, []); assert.ok(r.message); assert.ok(!JSON.stringify(r).includes("fake-unit-test-key"));
      if (status === "empty") assert.equal(r.message, "Belum pernah dijalankan di sandbox VirusTotal.");
    });
  }
  await withVt(t, () => { throw new Error("Network down"); }, async () => assert.equal((await fetchBehaviour(sha256, open)).status, "error"));
  // Shared quota exhausted: skipped without any network request, and the skip is noted.
  await withVt(t, () => { throw new Error("must not be called"); }, async calls => {
    const r = await fetchBehaviour(sha256, { requestGate: async () => false });
    assert.equal(r.status, "rate_limited"); assert.match(r.message || "", /dilewati/); assert.equal(calls.length, 0);
  });
  const old = process.env.VIRUSTOTAL_API_KEY; delete process.env.VIRUSTOTAL_API_KEY;
  try { assert.equal((await fetchBehaviour(sha256)).status, "not_configured"); assert.equal((await fetchBehaviour("bad", open)).status, "error"); } finally { if (old !== undefined) process.env.VIRUSTOTAL_API_KEY = old; }
});

const vtFile = () => Response.json({ data: { id: sha256, type: "file", attributes: { last_analysis_date: 1760000000, last_analysis_stats: { malicious: 20, suspicious: 0, harmless: 0, undetected: 40 }, last_analysis_results: {} } } });
const artifact = (): Artifact => ({ filename: "kurir.apk", kind: "apk", size: 10, sha256, metadata: { campaign: { hosts: ["panel.kurir-paket.my.id"], telegramBots: ["123456789"] } }, strings: [], urls: [], indicators: [], limitations: [], incomplete: false });
const rdap = (checked: string[]) => ({ fetch: async (url: string) => { checked.push(url); return new Response(null, { status: 404 }); }, requestGate: async () => true });

test("pipeline fetches behaviour for known files and merges contacted hosts into threat-intel targets", async t => {
  const previous = process.env.ABUSE_CH_AUTH_KEY; delete process.env.ABUSE_CH_AUTH_KEY;
  try {
    await withVt(t, ({ url }) => url.endsWith("/behaviour_summary") ? Response.json(fixture()) : vtFile(), async calls => {
      const a = artifact(), checked: string[] = [];
      await inspectReputation(a, Buffer.from("x"), false, { virusTotal: open, threatIntel: rdap(checked) });
      assert.deepEqual(calls.map(c => c.url.replace(/.*\/files\//, "")), [sha256, `${sha256}/behaviour_summary`]);
      assert.equal(a.virusTotal?.status, "completed"); assert.equal(a.sandbox?.status, "completed");
      const campaign = a.metadata.campaign as { hosts: string[]; telegramBots: string[] };
      assert.deepEqual(campaign.hosts, ["www.happyapis.com", "a8p.net", "195.123.224.81", "64.227.112.222", "45.9.20.11", "panel.kurir-paket.my.id"]);
      assert.deepEqual(campaign.telegramBots, ["123456789"]);
      assert.deepEqual(a.threatIntel?.hosts, campaign.hosts);
      assert.deepEqual(checked.sort(), ["https://rdap.org/domain/a8p.net", "https://rdap.org/domain/happyapis.com", "https://rdap.org/domain/kurir-paket.my.id"]);
      mergeSandboxHosts(a); assert.equal((a.metadata.campaign as { hosts: string[] }).hosts.length, 6);
    });
    // Unknown file: no behaviour request, nothing merged.
    await withVt(t, () => new Response(null, { status: 404 }), async calls => {
      const a = artifact(); await inspectReputation(a, Buffer.from("x"), false, { virusTotal: open, threatIntel: rdap([]) });
      assert.equal(calls.length, 1); assert.equal(a.sandbox, undefined); assert.deepEqual((a.metadata.campaign as { hosts: string[] }).hosts, ["panel.kurir-paket.my.id"]);
    });
    // Slow sandbox: threat intel starts after the wait budget; the digest still lands on the artifact afterwards.
    await withVt(t, async ({ url }) => { if (!url.endsWith("/behaviour_summary")) return vtFile(); await new Promise(r => setTimeout(r, 150)); return Response.json(fixture()); }, async () => {
      const a = artifact(), started = Date.now(); await inspectReputation(a, Buffer.from("x"), false, { virusTotal: open, threatIntel: rdap([]), behaviourWaitMs: 20 });
      assert.deepEqual(a.threatIntel?.hosts, ["panel.kurir-paket.my.id"]); assert.equal(a.sandbox?.status, "completed"); assert.ok(Date.now() - started < 5000);
    });
  } finally { if (previous !== undefined) process.env.ABUSE_CH_AUTH_KEY = previous; }
});

test("only hash-known files qualify, and refreshes never replace behaviour evidence with a failed lookup", () => {
  const vt = { sha256, checkedAt: "", message: "", url: "" };
  assert.ok(virusTotalKnown({ ...vt, status: "completed", source: "hash_lookup" })); assert.ok(virusTotalKnown({ ...vt, status: "pending", source: "hash_lookup" }));
  assert.ok(!virusTotalKnown({ ...vt, status: "completed", source: "file_upload" })); assert.ok(!virusTotalKnown({ ...vt, status: "not_found", source: "hash_lookup" })); assert.ok(!virusTotalKnown(undefined));
  const done = normalizeBehaviour(fixture()), limited: SandboxResult = { ...done, status: "rate_limited", contacted: [] }, empty = normalizeBehaviour({ data: {} });
  assert.equal(pickSandbox(done, limited), done); assert.equal(pickSandbox(undefined, limited), limited); assert.equal(pickSandbox(done, empty), empty); assert.equal(pickSandbox(done, undefined), done);
});
