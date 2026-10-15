import { createHash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { z } from "zod";
import { rateLimit } from "./db";
import { DOMAIN, hostOf, ipv4, publicHost, publicIpv4, under } from "./hosts";
import type { Artifact, SandboxContact, SandboxResult, VirusTotalResult, VirusTotalStats } from "./types";

const BASE = "https://www.virustotal.com/api/v3";
const count = z.number().int().min(0).max(10000);
const statsSchema = z.object({
  malicious: count, suspicious: count, harmless: count, undetected: count,
  timeout: count.default(0), failure: count.default(0),
  "confirmed-timeout": count.default(0), "type-unsupported": count.default(0),
});
const attributesSchema = z.object({
  last_analysis_stats: statsSchema.optional(), last_analysis_date: countTimestamp().optional(),
  last_analysis_results: z.record(z.string(), z.unknown()).optional(),
  stats: statsSchema.optional(), date: countTimestamp().optional(),
  results: z.record(z.string(), z.unknown()).optional(),
  status: z.enum(["queued", "in-progress", "completed"]).optional(),
});
function countTimestamp() { return z.number().int().min(1).max(253402300799); }

export function virusTotalConfigured() { return Boolean(process.env.VIRUSTOTAL_API_KEY?.trim()); }
type Options = { requestGate?: () => Promise<boolean>; signal?: AbortSignal };
class ProviderError extends Error {
  constructor(public status: "not_found" | "rate_limited" | "error", message: string) { super(message); }
}

const VT_UPLOAD_MAX = 100 * 1024 * 1024;
function initial(sha256: string): VirusTotalResult {
  if (!/^[a-f0-9]{64}$/.test(sha256)) throw new Error("Hash SHA-256 tidak valid.");
  return {
    status: "not_configured", sha256, checkedAt: new Date().toISOString(), source: "hash_lookup",
    message: "VirusTotal belum aktif. API key belum diisi.",
    url: `https://www.virustotal.com/gui/file/${sha256}/detection`,
  };
}

async function readJson(response: Response, max = 1024 * 1024) {
  if (!response.body) throw new Error("Empty provider response");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = []; let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read(); if (done) break;
      size += value.length;
      if (size > max) { await reader.cancel(); throw new Error("Oversized provider response"); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function client(options: Options, timeoutMs: number) {
  const key = process.env.VIRUSTOTAL_API_KEY?.trim() || "";
  const signal = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs);
  const identifier = createHash("sha256").update(key).digest("hex");
  const gate = options.requestGate || (async () => {
    if (!await rateLimit(`virustotal:minute:${identifier}`, 4, 60)) return false;
    return rateLimit(`virustotal:day:${identifier}`, 500, 86400);
  });
  return {
    signal,
    async request(url: string, init?: RequestInit, max?: number) {
      signal.throwIfAborted();
      if (!await gate()) throw new ProviderError("rate_limited", "Kuota VirusTotal tercapai. Coba perbarui hasil nanti.");
      const response = await fetch(url, {
        ...init, headers: { ...init?.headers, "x-apikey": key, accept: "application/json" },
        signal, cache: "no-store", redirect: "error",
      });
      if (!response.ok) {
        await response.body?.cancel().catch(() => {});
        if (response.status === 404) throw new ProviderError("not_found", "Hash file belum tercatat di VirusTotal.");
        if (response.status === 429) throw new ProviderError("rate_limited", "Kuota VirusTotal tercapai. Coba perbarui hasil nanti.");
        if ([401, 403].includes(response.status)) throw new ProviderError("error", "API key atau akses VirusTotal ditolak. Periksa konfigurasi key.");
        throw new ProviderError("error", "VirusTotal belum dapat dihubungi. Coba perbarui hasil nanti.");
      }
      return readJson(response, max);
    },
  };
}

function normalized(attributes: unknown, result: VirusTotalResult, analysis = false): VirusTotalResult {
  const data = attributesSchema.parse(attributes);
  const stats = analysis ? data.stats : data.last_analysis_stats;
  const timestamp = analysis ? data.date : data.last_analysis_date;
  if (analysis && data.status !== "completed" || !stats || !timestamp) {
    return { ...result, status: "pending", message: "Pemindaian VirusTotal belum selesai. Perbarui hasil setelah beberapa saat." };
  }
  const total = Object.values(stats).reduce((sum, n) => sum + n, 0);
  if (!total) return { ...result, status: "pending", message: "VirusTotal belum memberikan hasil engine antivirus." };
  const detections = Object.entries((analysis ? data.results : data.last_analysis_results) || {}).flatMap(([name, value]) => {
    const entry = z.object({ engine_name: z.string().max(200).optional(), category: z.string(), result: z.string().max(1000).nullable().optional() }).safeParse(value);
    if (!entry.success || !["malicious", "suspicious"].includes(entry.data.category)) return [];
    return [{ engine: (entry.data.engine_name || name).slice(0, 120), category: entry.data.category as "malicious" | "suspicious", result: entry.data.result?.slice(0, 250) || null }];
  });
  if (detections.filter(d => d.category === "malicious").length > stats.malicious || detections.filter(d => d.category === "suspicious").length > stats.suspicious) throw new Error("Inconsistent VirusTotal detection counts");
  return {
    ...result, status: "completed", stats: stats as VirusTotalStats, detections: detections.slice(0, 12),
    analysedAt: new Date(timestamp * 1000).toISOString(),
    message: "Hasil antivirus VirusTotal tersedia. Nol deteksi bukan jaminan aman.",
  };
}

function failed(error: unknown, result: VirusTotalResult): VirusTotalResult {
  if (result.analysisId) return { ...result, status: "pending", message: "File sudah dikirim ke VirusTotal. Hasil belum tersedia; perbarui setelah beberapa saat." };
  if (error instanceof ProviderError) return { ...result, status: error.status, message: error.message };
  return { ...result, status: "error", message: "Pemeriksaan VirusTotal gagal atau melewati batas waktu. Belum ada hasil antivirus." };
}

async function lookup(api: ReturnType<typeof client>, result: VirusTotalResult) {
  const body = await api.request(`${BASE}/files/${result.sha256}`);
  if (body.data?.type !== "file" || body.data?.id !== result.sha256) throw new Error("Mismatched VirusTotal file hash");
  return normalized(body.data.attributes, result);
}

export async function lookupVirusTotal(sha256: string, options: Options = {}): Promise<VirusTotalResult> {
  const result = initial(sha256); if (!virusTotalConfigured()) return result;
  try { return await lookup(client(options, 15000), result); } catch (error) { return failed(error, result); }
}

export function trustedUploadUrl(value: unknown) {
  if (typeof value !== "string") throw new Error("Invalid VirusTotal upload URL");
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.hostname !== "www.virustotal.com" || url.username || url.password || url.port || !["/_ah/upload/", "/api/v3/files/upload/"].some(prefix => url.pathname.startsWith(prefix))) throw new Error("Untrusted VirusTotal upload URL");
  // Official documentation includes legacy HTTP URLs; credentials always travel over HTTPS.
  url.protocol = "https:";
  return url.toString();
}

export async function inspectVirusTotal(artifact: Artifact, buffer: Buffer, uploadUnknown = false, options: Options = {}): Promise<VirusTotalResult> {
  let result = initial(artifact.sha256); if (!virusTotalConfigured()) return result;
  const api = client(options, 35000);
  try {
    try { return await lookup(api, result); }
    catch (error) {
      if (!(error instanceof ProviderError) || error.status !== "not_found" || !uploadUnknown) return failed(error, result);
    }
    // Uploading hundreds of MB to VirusTotal cannot finish inside the provider timeout; rely on the hash lookup.
    if (buffer.length > VT_UPLOAD_MAX) return { ...result, status: "not_found", message: "File belum dikenal VirusTotal dan terlalu besar (di atas 100 MB) untuk diunggah otomatis." };
    const url = buffer.length > 32 * 1024 * 1024 ? trustedUploadUrl((await api.request(`${BASE}/files/upload_url`)).data) : `${BASE}/files`;
    const form = new FormData();
    form.append("file", new Blob([new Uint8Array(buffer)], { type: "application/octet-stream" }), `${artifact.sha256}.${artifact.kind}`);
    const body = await api.request(url, { method: "POST", body: form });
    const analysisId = body.data?.id;
    if (body.data?.type !== "analysis" || typeof analysisId !== "string" || !/^[a-zA-Z0-9_=:-]{1,250}$/.test(analysisId)) throw new Error("Invalid VirusTotal analysis ID");
    result = { ...result, source: "file_upload", status: "pending", analysisId, message: "Menunggu hasil pemindaian VirusTotal." };
    for (let attempt = 0; attempt < 2; attempt++) {
      if (attempt) await delay(5000, undefined, { signal: api.signal });
      const analysis = await api.request(`${BASE}/analyses/${encodeURIComponent(analysisId)}`);
      if (analysis.data?.id !== analysisId || analysis.data?.type !== "analysis" || analysis.meta?.file_info?.sha256 && analysis.meta.file_info.sha256 !== artifact.sha256) throw new Error("Mismatched VirusTotal analysis");
      result = normalized(analysis.data.attributes, result, true);
      if (result.status === "completed") return result;
    }
    return result;
  } catch (error) { return failed(error, result); }
}

// ---- Sandbox behaviour (GET /files/{sha256}/behaviour_summary): what VirusTotal's sandboxes saw when THEY ran the file.
// One request through the same client/quota; Windows summaries list hundreds of files/registry keys, so the size cap is
// larger than for reputation, but only a compact, noise-filtered digest is kept. Never throws.
const BEHAVIOUR_MAX = 4 * 1024 * 1024, MAX_CONTACTED = 20, MAX_MITRE = 12, MAX_TAGS = 15, MAX_SANDBOX_HOSTS = 8;
// Sandbox noise beyond lib/hosts.ts BENIGN (shared with lib/triage.ts): OS connectivity checks, vendor telemetry/CDNs, certificate status, time sync.
const NOISE = ["tenor.com", "ggpht.com", "googlevideo.com", "googletagmanager.com", "gvt1.com", "gvt2.com", "gvt3.com", "pki.goog", "msftconnecttest.com", "msftncsi.com", "msn.com", "bing.com", "bing.net", "msedge.net", "office.net", "office365.com", "microsoftonline.com", "msauth.net", "msftauth.net", "skype.com", "s-microsoft.com", "xboxlive.com", "akamai.net", "akamaiedge.net", "akamaitechnologies.com", "edgekey.net", "edgesuite.net", "aaplimg.com", "apple-dns.net", "mzstatic.com", "mozilla.net", "ntp.org", "nist.gov", "usertrust.com", "comodoca.com", "entrust.net", "identrust.com", "lencr.org", "amazontrust.com", "godaddy.com"];
// Google/Microsoft/Apple corporate ranges (not their cloud-customer ranges): sandbox IPs without a DNS answer there are OS traffic.
const VENDOR_NETS = ["64.233.160.0/19", "66.102.0.0/20", "66.249.64.0/19", "72.14.192.0/18", "74.125.0.0/16", "108.177.0.0/17", "142.250.0.0/15", "172.217.0.0/16", "172.253.0.0/16", "173.194.0.0/16", "192.178.0.0/15", "209.85.128.0/17", "216.58.192.0/19", "216.239.32.0/19", "13.107.0.0/16", "131.253.0.0/16", "150.171.0.0/16", "204.79.197.0/24", "17.0.0.0/8"].map(n => { const [ip, bits] = n.split("/"); return [num(ip), Number(bits)] as const; });
// DNS, DHCP, NTP, NetBIOS, SSDP, mDNS/LLMNR: infrastructure chatter, not a server the file chose.
export const NOISE_PORTS = new Set([53, 67, 68, 123, 137, 138, 1900, 5353, 5355]);
function num(ip: string) { return ip.split(".").reduce((n, o) => n * 256 + Number(o), 0); }
export const vendorIp = (ip: string) => VENDOR_NETS.some(([base, bits]) => Math.floor(num(ip) / 2 ** (32 - bits)) === Math.floor(base / 2 ** (32 - bits)));
// Also sandbox-network names (wpad/isatap probes, *.localdomain) that never leave the analysis VM.
export const noisyHost = (h: string) => !publicHost(h) || under(h, NOISE) || /^(?:ocsp|crl)\d*\.|^(?:wpad|isatap)\.|\.(?:localdomain|workgroup|mshome\.net)$/.test(h);
const SEVERITY = { IMPACT_SEVERITY_INFO: "info", IMPACT_SEVERITY_LOW: "low", IMPACT_SEVERITY_MEDIUM: "medium", IMPACT_SEVERITY_HIGH: "high" } as const;
const RANK = { info: 0, low: 1, medium: 2, high: 3 };
type Severity = typeof SEVERITY[keyof typeof SEVERITY];
const severityOf = (v?: string): Severity | undefined => SEVERITY[v as keyof typeof SEVERITY];
const clean = (v: unknown, n = 160) => typeof v === "string" ? v.replace(/[\x00-\x1f\x7f]+/g, " ").trim().slice(0, n) : "";
const list = (v: unknown, max = 2000): unknown[] => Array.isArray(v) ? v.slice(0, max) : [];
const parsed = <T>(schema: z.ZodType<T>, v: unknown, max?: number) => list(v, max).flatMap(x => { const r = schema.safeParse(x); return r.success ? [r.data] : []; });
const defined = <T extends object>(o: T) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== "")) as T;
const words = (v: unknown, max: number, n = 40) => [...new Set(list(v, 200).map(x => clean(x, n)).filter(x => /^[\w .:/-]{2,}$/.test(x)))].slice(0, max);
const dnsEntry = z.object({ hostname: z.string().min(1).max(253), resolved_ips: z.array(z.string().max(64)).max(256).optional().catch(undefined) });
const ipEntry = z.object({ destination_ip: z.string().max(64), destination_port: z.number().int().min(0).max(65535).optional().catch(undefined), transport_layer_protocol: z.string().max(16).optional().catch(undefined) });
const httpEntry = z.object({ url: z.string().min(1).max(4096) });
const mitreEntry = z.object({ id: z.string().regex(/^T\d{4}(?:\.\d{3})?$/), signature_description: z.string().max(2000).optional().catch(undefined), description: z.string().max(2000).optional().catch(undefined), severity: z.string().max(40).optional().catch(undefined) });
const sigEntry = z.object({ name: z.string().max(400).optional().catch(undefined), description: z.string().max(2000).optional().catch(undefined), severity: z.string().max(40).optional().catch(undefined) });
const EMPTY = "Belum pernah dijalankan di sandbox VirusTotal.";

export function normalizeBehaviour(body: unknown, fetchedAt = new Date().toISOString()): SandboxResult {
  const data = z.object({ data: z.record(z.string(), z.unknown()) }).parse(body).data;
  const dns = parsed(dnsEntry, data.dns_lookups), traffic = parsed(ipEntry, data.ip_traffic), http = parsed(httpEntry, data.http_conversations);
  const name = (h: string) => h.toLowerCase().replace(/\.$/, "");
  // IP -> hostnames that resolved to it: an IP that only served filtered hostnames is filtered too.
  const served = new Map<string, string[]>();
  for (const d of dns) for (const ip of d.resolved_ips ?? []) served.set(ip, [...served.get(ip) ?? [], name(d.hostname)]);
  // Keyed by hostname (or IP when no hostname is known); HTTP first, then connections, then bare lookups, so the
  // strongest kind wins and later sources only fill missing fields.
  const contacts = new Map<string, SandboxContact>(); let filtered = 0;
  const add = (key: string, c: SandboxContact) => { const old = contacts.get(key); contacts.set(key, old ? { ...c, ...old } : c); };
  for (const h of http) {
    const host = hostOf(h.url), ip = ipv4(host);
    if (!host || (ip ? !publicIpv4(host) || vendorIp(host) : noisyHost(host))) { filtered++; continue; }
    let url = ""; try { const u = new URL(h.url); url = `${u.protocol}//${u.host}${u.pathname}`.slice(0, 200); } catch {}
    add(host, defined({ kind: "http" as const, host: ip ? undefined : host, ip: ip ? host : undefined, url }));
  }
  for (const t of traffic) {
    const ip = t.destination_ip, hosts = served.get(ip) ?? [], host = hosts.find(h => !noisyHost(h));
    if (!publicIpv4(ip) || hosts.length && !host || !hosts.length && (vendorIp(ip) || NOISE_PORTS.has(t.destination_port ?? 0))) { filtered++; continue; }
    const protocol = clean(t.transport_layer_protocol, 8).toUpperCase();
    add(host || ip, defined({ kind: "ip" as const, host, ip, port: t.destination_port || undefined, protocol: /^[A-Z0-9]{2,8}$/.test(protocol) ? protocol : undefined }));
  }
  for (const d of dns) {
    const host = name(d.hostname); if (contacts.has(host)) continue;
    if (!DOMAIN.test(host) || noisyHost(host)) { filtered++; continue; }
    add(host, defined({ kind: "dns" as const, host, ip: d.resolved_ips?.find(publicIpv4) }));
  }
  const mitre = new Map<string, SandboxResult["mitre"][number]>();
  for (const m of parsed(mitreEntry, data.mitre_attack_techniques, 500)) {
    const severity = severityOf(m.severity), old = mitre.get(m.id), description = clean(m.signature_description || m.description) || old?.description || m.id;
    if (!old || RANK[severity ?? "info"] > RANK[old.severity ?? "info"]) mitre.set(m.id, defined({ id: m.id, description, severity }));
  }
  const sigs = parsed(sigEntry, data.signature_matches, 1000);
  // Low/medium/high sandbox signatures, strongest first (capa rule paths such as "load-code/dotnet" are not prose).
  const notable = sigs.map(s => ({ rank: RANK[severityOf(s.severity) ?? "info"], text: clean(s.description || s.name) })).filter(s => s.rank && s.text && !/^[\w-]+(?:\/[\w-]+)+$/.test(s.text)).sort((a, b) => b.rank - a.rank).map(s => s.text);
  const blind = sigs.some(s => /unable to (?:instrument|execute)/i.test(s.description || ""));
  const highlights = [...new Set([...blind ? ["Sebagian sandbox tidak berhasil menjalankan file sepenuhnya; perilaku yang tercatat bisa belum lengkap."] : [], ...notable])].slice(0, 8);
  const tags = words(data.tags, MAX_TAGS).map(t => t.toUpperCase()).filter(t => /^[A-Z0-9_]+$/.test(t)), verdicts = words(data.verdicts, 6).map(v => v.toUpperCase()), labels = words(data.verdict_labels, 6, 60);
  const counts = { dns: dns.length, ip: traffic.length, http: http.length, processes: list(data.processes_created).length, filesDropped: list(data.files_dropped).length, filtered };
  const techniques = [...mitre.values()].sort((a, b) => RANK[b.severity ?? "info"] - RANK[a.severity ?? "info"]).slice(0, MAX_MITRE);
  const ran = dns.length || traffic.length || http.length || tags.length || techniques.length || verdicts.length || sigs.length || counts.processes || counts.filesDropped;
  return defined({
    source: "virustotal" as const, status: ran ? "completed" as const : "empty" as const, fetchedAt, message: ran ? undefined : EMPTY,
    sandboxes: words(data.sandbox_names ?? data.sandboxes, 8, 60), contacted: [...contacts.values()].slice(0, MAX_CONTACTED), tags, verdicts,
    labels: labels.length ? labels : undefined, mitre: techniques, highlights: highlights.length ? highlights : undefined, counts,
  });
}

// The file is known to VirusTotal (found by hash), so sandbox reports can exist; fresh uploads have none yet.
export const virusTotalKnown = (vt?: VirusTotalResult) => Boolean(vt && vt.source === "hash_lookup" && (vt.status === "completed" || vt.status === "pending"));

export async function fetchBehaviour(sha256: string, options: Options & { timeoutMs?: number } = {}): Promise<SandboxResult> {
  const base: SandboxResult = { source: "virustotal", status: "error", fetchedAt: new Date().toISOString(), sandboxes: [], contacted: [], tags: [], verdicts: [], mitre: [] };
  if (!/^[a-f0-9]{64}$/.test(sha256)) return { ...base, message: "Hash SHA-256 tidak valid." };
  if (!virusTotalConfigured()) return { ...base, status: "not_configured", message: "VirusTotal belum aktif. API key belum diisi." };
  try {
    return normalizeBehaviour(await client(options, options.timeoutMs ?? 10000).request(`${BASE}/files/${sha256}/behaviour_summary`, undefined, BEHAVIOUR_MAX), base.fetchedAt);
  } catch (error) {
    if (error instanceof ProviderError && error.status === "not_found") return { ...base, status: "empty", message: EMPTY };
    if (error instanceof ProviderError && error.status === "rate_limited") return { ...base, status: "rate_limited", message: "Kuota VirusTotal tercapai; data sandbox dilewati. Coba perbarui hasil nanti." };
    return { ...base, message: error instanceof ProviderError ? error.message : "Data sandbox VirusTotal gagal diambil atau melewati batas waktu." };
  }
}

// Sandbox-contacted hosts/IPs go to the front of metadata.campaign.hosts (deduplicated, at most 8 of the 12 slots, so
// statically extracted endpoints still get reputation checks); hostnames before IPs.
export function mergeSandboxHosts(artifact: Artifact) {
  const contacted = artifact.sandbox?.contacted ?? []; if (!contacted.length) return;
  const meta = artifact.metadata.campaign, campaign = meta && typeof meta === "object" && !Array.isArray(meta) ? meta as Record<string, unknown> : {};
  const old = Array.isArray(campaign.hosts) ? campaign.hosts.filter((h): h is string => typeof h === "string") : [];
  const fresh = [...new Set([...contacted.map(c => c.host), ...contacted.map(c => c.ip)].filter((h): h is string => Boolean(h)))].slice(0, MAX_SANDBOX_HOSTS);
  artifact.metadata.campaign = { ...campaign, hosts: [...new Set([...fresh, ...old])].slice(0, 12) };
}
