import { createHash } from "node:crypto";
import { z } from "zod";
import { rateLimit } from "./db";
import { redactSecrets } from "./behaviors";
import { DOMAIN, SHARED, hostOf, ipv4, publicHost, publicIpv4, under } from "./hosts";
import { NOISE_PORTS, noisyHost, vendorIp } from "./virustotal";
import type { Artifact, FileKind, SandboxContact, TriageConfig, TriageResult, TriageSibling, TriageStatus } from "./types";

// Tria.ge (Hatching Triage) cloud API v0: hash search (reuse a public analysis without uploading), opt-in upload of
// APK/EXE, status polling, overview.json (score, family, extracted malware configs, IOCs, signatures) and the dynamic
// report_triage.json network section. Bounded (timeouts, response caps, shared quotas); never throws to callers.
// Samples on the researcher account are PUBLIC: files go out under their SHA-256 name only, never the user's filename.
const DEFAULT_API = "https://tria.ge/api";
export const SAMPLE_ID = /^\d{6}-[a-z0-9]{6,16}$/;
export const TRIAGE_KINDS: readonly FileKind[] = ["apk", "exe"];
const UPLOAD_MAX = 100 * 1024 * 1024, OVERVIEW_MAX = 3 * 1024 * 1024, REPORT_MAX = 4 * 1024 * 1024, JSON_MAX = 9000;
// First status check 2 min after submission, then every 2.5 min; given up 30 min after submission.
export const FIRST_CHECK_MS = 120_000, INTERVAL_MS = 150_000, RATE_RETRY_MS = 180_000, TIMEOUT_MS = 30 * 60_000;
const MAX_CONTACTED = 20, MAX_CONFIGS = 6, MAX_C2 = 10, MAX_SIGS = 12, MAX_TAGS = 12, MAX_DYNAMIC = 2;

export function triageConfigured() { return Boolean(process.env.TRIAGE_API_KEY?.trim()); }
function apiBase() {
  const raw = process.env.TRIAGE_API_URL?.trim().replace(/\/+$/, "") || DEFAULT_API;
  try { const u = new URL(raw); return u.protocol === "https:" && !u.username && !u.password ? `${u.origin}${u.pathname.replace(/\/+$/, "")}` : DEFAULT_API; } catch { return DEFAULT_API; }
}
// Public page of a sample on the same Triage instance (https://tria.ge/<id> for the public cloud).
export const triagePage = (id: string) => SAMPLE_ID.test(id) ? `${new URL(apiBase()).origin}/${id}` : undefined;
export const dailyLimit = () => { const n = Number(process.env.TRIAGE_DAILY_LIMIT); return Number.isInteger(n) && n >= 1 && n <= 1000 ? n : 40; };

type Fetch = (input: string, init?: RequestInit) => Promise<Response>;
export type TriageOptions = {fetch?: Fetch; gate?: () => Promise<boolean>; submitGate?: () => Promise<boolean>; signal?: AbortSignal; timeoutMs?: number; now?: () => number};
class TriageError extends Error {
  constructor(public status: "not_found" | "rate_limited" | "error", message: string) { super(message); }
}
const RATE_MESSAGE = "Tria.ge membatasi permintaan; dicoba lagi otomatis.";

async function readJson(response: Response, max: number) {
  if (!response.body) throw new TriageError("error", "Respons Tria.ge kosong.");
  const reader = response.body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
  try {
    for (;;) {
      const {done, value} = await reader.read(); if (done) break;
      size += value.length; if (size > max) { await reader.cancel(); throw new TriageError("error", "Respons Tria.ge terlalu besar."); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown; } catch { throw new TriageError("error", "Respons Tria.ge tidak valid."); }
}

function client(options: TriageOptions) {
  const key = process.env.TRIAGE_API_KEY?.trim() || "", base = `${apiBase()}/v0`, doFetch = options.fetch || ((u, i) => fetch(u, i));
  const id = createHash("sha256").update(key).digest("hex").slice(0, 16);
  const gate = options.gate || (() => rateLimit(`triage:minute:${id}`, 30, 60));
  return {
    submitGate: options.submitGate || (() => rateLimit(`triage:day:${id}`, dailyLimit(), 86400)),
    async request(path: string, init: RequestInit = {}, max = 1024 * 1024, timeoutMs = options.timeoutMs ?? 15000) {
      if (!await gate()) throw new TriageError("rate_limited", "Kuota permintaan Tria.ge di Kheronyx tercapai; dicoba lagi otomatis.");
      const signal = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs);
      let response: Response;
      try { response = await doFetch(`${base}${path}`, {...init, headers: {...init.headers, authorization: `Bearer ${key}`, accept: "application/json"}, signal, cache: "no-store", redirect: "error"}); }
      catch { throw new TriageError("error", "Tria.ge belum dapat dihubungi atau melewati batas waktu."); }
      if (!response.ok) {
        await response.body?.cancel().catch(() => {});
        if (response.status === 404) throw new TriageError("not_found", "Sampel tidak ditemukan di Tria.ge.");
        if (response.status === 429) throw new TriageError("rate_limited", RATE_MESSAGE);
        if ([401, 403].includes(response.status)) throw new TriageError("error", "API key atau akses Tria.ge ditolak. Periksa TRIAGE_API_KEY.");
        throw new TriageError("error", `Tria.ge gagal merespons (${response.status}).`);
      }
      return readJson(response, max);
    },
  };
}
type Client = ReturnType<typeof client>;

// ---- small defensive parsers (all Triage JSON is untrusted)
const rec = (v: unknown) => v && typeof v === "object" && !Array.isArray(v) ? v as Record<string, unknown> : {};
const arr = (v: unknown, max = 500): unknown[] => Array.isArray(v) ? v.slice(0, max) : [];
const clean = (v: unknown, n = 160) => typeof v === "string" ? v.replace(/[\x00-\x1f\x7f]+/g, " ").trim().slice(0, n) : typeof v === "number" && Number.isFinite(v) ? String(v).slice(0, n) : "";
const strs = (v: unknown, max: number, n = 120) => [...new Set((typeof v === "string" ? [v] : arr(v)).map(x => clean(x, n)).filter(Boolean))].slice(0, max);
const int = (v: unknown, min: number, max: number) => typeof v === "number" && Number.isInteger(v) && v >= min && v <= max ? v : undefined;
const defined = <T extends object>(o: T) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== "" && !(Array.isArray(v) && !v.length))) as T;
const sampleRow = z.object({id: z.string().regex(SAMPLE_ID), status: z.string().max(40), kind: z.string().max(10).optional().catch(undefined), sha256: z.string().max(64).optional().catch(undefined), submitted: z.string().max(40).optional().catch(undefined), completed: z.string().max(40).optional().catch(undefined)});
export function mapStatus(s: string): TriageStatus {
  return s === "reported" ? "reported" : s === "failed" ? "failed" : s === "running" || s === "processing" ? "running" : "pending";
}
// Never store full secrets: at most the last 4 characters of long values (like redacted Telegram tokens).
export const mask = (v: unknown) => { const s = typeof v === "string" ? v : v === undefined || v === null ? "" : JSON.stringify(v) ?? ""; return !s ? undefined : s.length >= 12 ? `…${s.slice(-4)}` : "…"; };
const SECRET_FIELD = /((?:pass(?:word)?|pwd|token|secret|api[_-]?key|key|auth|cookie|session)["']?\s*[:=]\s*["']?)([^\s"',;}]{3,})/gi;
const scrub = (s: string) => redactSecrets(s).replace(SECRET_FIELD, (_, k: string) => `${k}…`);

// ---- configs (overview.extracted[]): C2 servers, botnet/campaign ids, exfiltration credentials, keys (masked).
function credential(v: unknown) {
  const c = rec(v), host = clean(c.host, 160), username = clean(c.username ?? c.user, 120);
  if (!host && !username) return undefined;
  const protocol = clean(c.protocol, 12).toLowerCase();
  return defined({protocol: /^[a-z0-9+.-]{2,12}$/.test(protocol) ? protocol : undefined, host: host ? scrub(host) : undefined, port: int(c.port, 1, 65535), username: username ? scrub(username) : undefined, password: mask(c.password ?? c.pass)});
}
function config(v: unknown, fallback: string): TriageConfig | undefined {
  const c = rec(v); if (!Object.keys(c).length) return undefined;
  const family = clean(c.family, 40).toLowerCase() || fallback;
  const c2 = strs(c.c2, MAX_C2, 200).map(scrub).filter(x => x.length >= 4);
  const credentials = arr(c.credentials, 10).map(credential).filter(x => x !== undefined);
  const keys = arr(c.keys, 6).map(rec).flatMap(k => { const value = mask(k.value); return value ? [defined({kind: clean(k.kind, 40) || undefined, key: clean(k.key, 60) || undefined, value})] : []; });
  const raw = clean(c.raw, 1200);
  return {...defined({
    family, rule: clean(c.rule, 60) || undefined, botnet: scrub(clean(c.botnet, 80)) || undefined, campaign: scrub(clean(c.campaign, 80)) || undefined, version: clean(c.version, 40) || undefined,
    mutex: strs(c.mutex, 3, 80), credentials, keys, wallets: strs(c.wallet, 3, 120), raw: raw ? scrub(raw).slice(0, 300) : undefined,
  }), c2};
}
function mergeConfigs(list: TriageConfig[]) {
  const out = new Map<string, TriageConfig>();
  for (const c of list) {
    const old = out.get(c.family); if (!old) { out.set(c.family, c); continue; }
    const creds = [...old.credentials ?? [], ...c.credentials ?? []].filter((x, i, a) => a.findIndex(y => y.host === x.host && y.username === x.username && y.port === x.port) === i).slice(0, 10);
    out.set(c.family, {...defined({...c, ...old, credentials: creds, keys: [...old.keys ?? [], ...c.keys ?? []].slice(0, 6), mutex: [...new Set([...old.mutex ?? [], ...c.mutex ?? []])].slice(0, 3), wallets: [...new Set([...old.wallets ?? [], ...c.wallets ?? []])].slice(0, 3)}), c2: [...new Set([...old.c2, ...c.c2])].slice(0, MAX_C2)});
  }
  // Family-only detections (no C2, credentials, ids or keys) carry no extra evidence beyond `family`.
  return [...out.values()].filter(c => c.c2.length || c.credentials?.length || c.botnet || c.campaign || c.keys?.length || c.wallets?.length || c.version || c.mutex?.length || c.raw).slice(0, MAX_CONFIGS);
}

// ---- network contacts (noise rules shared with the VirusTotal sandbox digest)
type Contacts = {map: Map<string, SandboxContact>; served: Map<string, string[]>};
const name = (h: string) => h.toLowerCase().replace(/\.$/, "");
// Public "what is my IP / where am I" services stealers query for the victim's address: not operator infrastructure.
const IP_LOOKUP = ["ip-api.com", "ipinfo.io", "ipapi.co", "ipwho.is", "ip.sb", "icanhazip.com", "ifconfig.me", "ifconfig.co", "myexternalip.com", "wtfismyip.com", "myip.com", "geoplugin.net", "freegeoip.app", "ipgeolocation.io", "checkip.amazonaws.com", "checkip.dyndns.org", "ident.me", "ipecho.net", "ip-score.com", "showip.net", "iplocation.net"];
const noisy = (h: string) => noisyHost(h) || under(h, IP_LOOKUP);
// One entry per hostname (or IP): the strongest kind wins (http > ip > dns), other sources only fill missing fields.
const KIND_RANK = {http: 0, ip: 1, dns: 2};
const addContact = (m: Map<string, SandboxContact>, key: string, c: SandboxContact) => { const old = m.get(key); m.set(key, old ? {...c, ...old, kind: KIND_RANK[c.kind] < KIND_RANK[old.kind] ? c.kind : old.kind} : c); };
const cleanUrl = (raw: string) => { try { const u = new URL(raw); return /^(?:https?|wss?):$/.test(u.protocol) ? `${u.protocol}//${u.host}${u.pathname}`.slice(0, 200) : ""; } catch { return ""; } };
// An IP that only served filtered hostnames (or Google/Microsoft/Apple corporate ranges without a hostname) is noise.
const noisyIp = (ip: string, served: Map<string, string[]>) => !publicIpv4(ip) || (served.get(ip)?.length ? served.get(ip)!.every(noisy) : vendorIp(ip));
function addUrl(ctx: Contacts, raw: string) {
  const host = hostOf(raw), ip = ipv4(host), url = cleanUrl(raw);
  if (!host || !url || (ip ? noisyIp(host, ctx.served) : noisy(host))) return;
  addContact(ctx.map, host, defined({kind: "http" as const, host: ip ? undefined : host, ip: ip ? host : undefined, url}));
}
// report_triage.json network: DNS answers (IP → hostnames), flows (dst ip:port, SNI/domain, protocols) and HTTP requests.
export function dynamicContacts(body: unknown, ctx: Contacts) {
  const net = rec(rec(body).network), requests = arr(net.requests, 3000).map(rec), flows = arr(net.flows, 3000).map(rec);
  for (const r of requests) {
    const answer = rec(r.dns_response), ips = strs(answer.ip, 50, 64), domains = strs(answer.domains, 20, 253).map(name);
    for (const ip of ips) ctx.served.set(ip, [...new Set([...ctx.served.get(ip) ?? [], ...domains])].slice(0, 20));
  }
  for (const r of requests) { const url = clean(rec(r.http_request).url, 2000); if (url) addUrl(ctx, url); }
  for (const f of flows) {
    const dst = clean(f.dst, 80), m = dst.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/); if (!m) continue;
    const ip = m[1], port = Number(m[2]), sni = name(clean(f.tls_sni, 253) || clean(f.domain, 253)), served = ctx.served.get(ip) ?? [];
    const host = [sni, ...served].find(h => h && DOMAIN.test(h) && !noisy(h));
    if (!publicIpv4(ip) || (sni || served.length) && !host || !host && (vendorIp(ip) || NOISE_PORTS.has(port))) continue;
    const proto = (strs(f.protocols, 1, 10)[0] || clean(f.proto, 8)).toUpperCase();
    addContact(ctx.map, host || ip, defined({kind: "ip" as const, host, ip, port: int(port, 1, 65535), protocol: /^[A-Z0-9]{2,8}$/.test(proto) ? proto : undefined}));
  }
  for (const r of requests) for (const d of strs(rec(r.dns_request).domains, 10, 253).map(name)) if (!ctx.map.has(d) && DOMAIN.test(d) && !noisy(d)) addContact(ctx.map, d, {kind: "dns", host: d});
}
function iocContacts(iocs: Record<string, unknown>, ctx: Contacts, dynamic: boolean) {
  for (const u of strs(iocs.urls, 100, 2000)) addUrl(ctx, u);
  for (const d of strs(iocs.domains, 100, 253).map(name)) if (!ctx.map.has(d) && DOMAIN.test(d) && !noisy(d)) addContact(ctx.map, d, {kind: "dns", host: d});
  // With a dynamic report the flows already list every real connection with its hostname; bare overview IPs would
  // only add CDN/Google addresses whose hostname was filtered.
  if (!dynamic) for (const ip of strs(iocs.ips, 100, 64)) if (!noisyIp(ip, ctx.served) && ![...ctx.map.values()].some(c => c.ip === ip)) addContact(ctx.map, ip, {kind: "ip", ip});
}

// overview.json lists tasks as an array or as an object keyed by "<sample>-<task>".
const overviewTasks = (o: Record<string, unknown>) => (Array.isArray(o.tasks) ? o.tasks : Object.entries(rec(o.tasks)).map(([k, v]) => ({...rec(v), name: rec(v).name ?? k.split("-").pop()}))).slice(0, 20).map(rec);
// ---- overview.json → compact, noise-filtered digest. `dynamic` = parsed report_triage.json bodies (optional).
const GENERIC_TAG = /^(?:android|windows|linux|macos|family:.*)$/i;
export function normalizeOverview(body: unknown, sha256?: string, dynamic: unknown[] = []) {
  const o = rec(body), analysis = rec(o.analysis), sample = rec(o.sample);
  if (!Object.keys(analysis).length && !Array.isArray(o.targets)) throw new TriageError("error", "Laporan Tria.ge tidak dikenali.");
  if (sha256 && typeof sample.sha256 === "string" && sample.sha256.toLowerCase() !== sha256) throw new TriageError("error", "Laporan Tria.ge tidak cocok dengan file ini.");
  const tags = strs(analysis.tags, 40, 40);
  const family = [...new Set([...strs(analysis.family, 3, 40), ...tags.filter(t => t.startsWith("family:")).map(t => t.slice(7))].map(f => f.toLowerCase()).filter(f => /^[\w .-]{2,40}$/.test(f)))].slice(0, 3);
  const targets = arr(o.targets, 20).map(rec);
  // Signatures: sample-level plus per-target, deduplicated by label/name, strongest first.
  const sigs = new Map<string, NonNullable<TriageResult["signatures"]>[number]>();
  for (const s of [...arr(o.signatures, 300), ...targets.flatMap(t => arr(t.signatures, 300))].map(rec)) {
    const label = clean(s.label, 60), sigName = clean(s.name, 160) || label; if (!sigName) continue;
    const score = int(s.score, 0, 10), key = label || sigName, old = sigs.get(key);
    if (old && (old.score ?? 0) >= (score ?? 0)) continue;
    sigs.set(key, defined({name: sigName, score, description: clean(s.desc, 200) || undefined, label: label || undefined, ttp: strs(s.ttp, 4, 12).filter(t => /^T\d{4}(?:\.\d{3})?$/.test(t))}));
  }
  const signatures = [...sigs.values()].sort((a, b) => (b.score ?? 0) - (a.score ?? 0)).slice(0, MAX_SIGS);
  const fallback = family[0] || "tidak diketahui", configs: TriageConfig[] = [];
  for (const e of arr(o.extracted, 50).map(rec)) {
    const c = config(e.config, fallback); if (c) configs.push(c);
    const creds = (Array.isArray(e.credentials) ? e.credentials.slice(0, 10) : e.credentials ? [e.credentials] : []).map(credential).filter(x => x !== undefined);
    if (creds.length) configs.push({family: fallback, c2: [], credentials: creds});
    const d = rec(e.dropper), urls = arr(d.urls, 20).map(u => clean(rec(u).url, 300)).filter(Boolean);
    if (urls.length) configs.push({family: clean(d.family, 40).toLowerCase() || "dropper", c2: [...new Set(urls.map(scrub))].slice(0, MAX_C2)});
  }
  const ctx: Contacts = {map: new Map(), served: new Map()};
  for (const d of dynamic) dynamicContacts(d, ctx);
  for (const t of targets) iocContacts(rec(t.iocs), ctx, dynamic.length > 0);
  iocContacts(rec(sample.iocs), ctx, dynamic.length > 0);
  // HTTP first, then connections, then bare DNS lookups (same order as the VirusTotal sandbox digest).
  const contacted = [...ctx.map.values()].sort((a, b) => KIND_RANK[a.kind] - KIND_RANK[b.kind]).slice(0, MAX_CONTACTED);
  // Behavioural tasks: which ones can provide a dynamic report, the OS they ran on, and why they did not run.
  const tasks = overviewTasks(o).filter(t => t.kind === "behavioral");
  const behavioral = tasks.filter(t => t.status === "reported").map(t => clean(t.name, 20)).filter(n => /^behavioral\d{1,2}$/.test(n));
  const platforms = [...new Set(tasks.map(t => clean(t.os ?? t.platform, 40)).filter(Boolean))].slice(0, 4);
  const blind = tasks.length > 0 && !behavioral.length;
  const result: Partial<TriageResult> = defined({
    score: int(analysis.score, 0, 10) ?? int(targets[0]?.score, 0, 10), family, tags: tags.filter(t => !GENERIC_TAG.test(t) && /^[\w:.-]{2,40}$/.test(t)).slice(0, MAX_TAGS),
    configs: mergeConfigs(configs), contacted, signatures, platforms,
    message: blind ? "Sandbox Tria.ge tidak berhasil menjalankan file (misalnya gagal dipasang); hanya analisis statis Tria.ge yang tersedia." : undefined,
  });
  return {result: compact(result), behavioral};
}
function compact<T extends Partial<TriageResult>>(r: T): T {
  // Keeps the AI evidence bounded (assess() rejects > 120k characters): normal digests are 2–6 KB.
  if (JSON.stringify(r).length > JSON_MAX) { r.signatures = r.signatures?.map(({description: _d, ...s}) => s); r.configs = r.configs?.map(({raw: _r, ...c}) => c); }
  if (JSON.stringify(r).length > JSON_MAX) { r.signatures = r.signatures?.slice(0, 6); r.contacted = r.contacted?.slice(0, 10); r.configs = r.configs?.slice(0, 3); }
  return r;
}

// ---- API steps
type Found = {id: string; status: TriageStatus};
// Exact SHA-256 matches only: Triage also returns archives that merely contain the file.
export async function searchSample(api: Client, sha256: string): Promise<Found | null> {
  const body = rec(await api.request(`/search?query=${encodeURIComponent(`sha256:${sha256}`)}`));
  const rows = arr(body.data, 50).flatMap(x => { const r = sampleRow.safeParse(x); return r.success && r.data.kind !== "url" && r.data.sha256?.toLowerCase() === sha256 ? [r.data] : []; });
  const time = (r: z.infer<typeof sampleRow>) => Date.parse(r.completed || r.submitted || "") || 0;
  const done = rows.filter(r => r.status === "reported").sort((a, b) => time(b) - time(a))[0];
  const active = rows.find(r => !["reported", "failed"].includes(r.status));
  const pick = done || active; return pick ? {id: pick.id, status: mapStatus(pick.status)} : null;
}
// Triage's automatic profile choice sometimes stops an APK after static analysis (no behavioural run at all), so APKs
// ask for two Android VMs explicitly (both run ARM and x86 code).
const APK_PROFILES = ["os:android-14-x64", "os:android-11-x64"].map(tag => ({profile: {tags: [tag], network: "internet"}, pick: "sample"}));
async function upload(api: Client, buffer: Buffer, sha256: string, kind: FileKind) {
  const form = new FormData(), filename = `${sha256}.${kind}`;
  form.append("_json", JSON.stringify({kind: "file", interactive: false, target: filename, ...kind === "apk" ? {profiles: APK_PROFILES} : {}}));
  form.append("file", new Blob([new Uint8Array(buffer)], {type: "application/octet-stream"}), filename);
  const r = sampleRow.safeParse(await api.request("/samples", {method: "POST", body: form}, 256 * 1024, 60_000));
  if (!r.success) throw new TriageError("error", "Respons pengiriman Tria.ge tidak valid.");
  return {id: r.data.id, status: mapStatus(r.data.status)};
}
// Status and number of behavioural tasks of a sample (0 = static analysis only).
async function sampleState(api: Client, id: string) {
  const body = rec(await api.request(`/samples/${id}`));
  return {status: mapStatus(clean(body.status, 40)), behavioral: arr(body.tasks, 30).map(rec).filter(t => /^behavioral\d{1,2}$/.test(clean(t.id, 20))).length};
}
const iso = (t: number) => new Date(t).toISOString();
// A result still waiting after TIMEOUT_MS (counted from the first submission) becomes final.
export function expire(r: TriageResult, now: number): TriageResult {
  if (!r.nextCheck || now - Date.parse(r.submittedAt) < TIMEOUT_MS) return r;
  const {nextCheck: _n, ...rest} = r;
  return {...rest, status: r.status === "rate_limited" ? "rate_limited" : "failed", message: r.status === "rate_limited" ? "Kuota Tria.ge tercapai selama 30 menit; sandbox dilewati untuk file ini." : `Sandbox Tria.ge belum selesai setelah 30 menit; pemeriksaan otomatis dihentikan.${r.sampleId ? " Hasilnya mungkin muncul nanti di tria.ge." : ""}`};
}

export type Submission = {result: TriageResult; retryUpload: boolean};
// Search first (reuse a public analysis: no upload), else upload when allowed. retryUpload = keep the file for a later
// retry (Triage rate limit or network failure). Never throws.
export async function submitTriage(input: {sha256: string; kind: FileKind; buffer?: Buffer; known?: string}, previous: TriageResult | undefined, options: TriageOptions = {}): Promise<Submission> {
  const now = (options.now ?? Date.now)(), at = iso(now);
  const base: TriageResult = {status: "pending", submittedAt: previous?.submittedAt || at, checkedAt: at};
  if (!triageConfigured()) return {result: {...base, status: "skipped", message: "Tria.ge belum aktif. API key belum diisi."}, retryUpload: false};
  if (!/^[a-f0-9]{64}$/.test(input.sha256) || !TRIAGE_KINDS.includes(input.kind)) return {result: {...base, status: "skipped", message: "Sandbox Tria.ge hanya untuk file APK dan EXE."}, retryUpload: false};
  const api = client(options);
  const reuse = (found: Found, message: string): Submission => ({result: {...base, status: found.status === "reported" ? "running" : found.status, sampleId: found.id, url: triagePage(found.id), reused: true, message, nextCheck: found.status === "reported" ? at : iso(now + FIRST_CHECK_MS)}, retryUpload: false});
  try {
    // Same file already sent by an earlier Kheronyx report (or analysed publicly): reused, unless that finished analysis
    // of an APK never ran it (static only) and the file is still here to send again with explicit Android profiles.
    const known = input.known && SAMPLE_ID.test(input.known) ? input.known : "";
    const state = known ? await sampleState(api, known).catch(() => ({status: "running" as TriageStatus, behavioral: 1})) : undefined;
    const found = known ? {id: known, status: state!.status} : await searchSample(api, input.sha256);
    const staticOnly = Boolean(found?.status === "reported" && input.kind === "apk" && input.buffer && (state ?? await sampleState(api, found.id)).behavioral === 0);
    if (found && !staticOnly) return reuse(found, known ? "File ini sudah pernah dikirim ke Tria.ge; hasil yang sama dipakai ulang." : found.status === "reported" ? "Analisis publik Tria.ge untuk file ini sudah ada; hasilnya dipakai tanpa mengunggah ulang." : "File ini sedang dianalisis di Tria.ge; hasilnya dipakai tanpa mengunggah ulang.");
    if (!input.buffer) return {result: {...base, status: "skipped", message: "File belum ada di Tria.ge dan salinannya sudah dihapus; tidak dikirim."}, retryUpload: false};
    if (input.buffer.length > UPLOAD_MAX) return {result: {...base, status: "skipped", message: "File belum ada di Tria.ge dan terlalu besar (di atas 100 MB) untuk dikirim otomatis."}, retryUpload: false};
    if (!await api.submitGate()) return {result: {...base, status: "rate_limited", message: `Batas ${dailyLimit()} kiriman sandbox per hari tercapai; file ini tidak dikirim ke Tria.ge.`}, retryUpload: false};
    const sample = await upload(api, input.buffer, input.sha256, input.kind);
    return {result: {...base, status: sample.status === "reported" ? "running" : sample.status, sampleId: sample.id, url: triagePage(sample.id), reused: false, message: staticOnly ? "Analisis Tria.ge sebelumnya tidak menjalankan file ini; file dikirim ulang agar dijalankan di Android." : undefined, nextCheck: iso(now + (sample.status === "reported" ? 0 : FIRST_CHECK_MS))}, retryUpload: false};
  } catch (error) {
    const e = error instanceof TriageError ? error : new TriageError("error", "Tria.ge belum dapat dihubungi.");
    const limited = e.status === "rate_limited";
    const result = expire({...base, status: limited ? "rate_limited" : "pending", message: limited ? e.message : `${e.message} Pengiriman dicoba lagi otomatis.`, nextCheck: iso(now + (limited ? RATE_RETRY_MS : INTERVAL_MS))}, now);
    return {result, retryUpload: Boolean(result.nextCheck && input.buffer)};
  }
}

// One status check of a submitted sample; when reported, fetches overview (+ up to 2 dynamic reports) and returns the
// normalized digest with status "reported". Waiting results carry nextCheck. Never throws.
export async function checkTriage(previous: TriageResult, sha256: string, options: TriageOptions = {}): Promise<TriageResult> {
  const now = (options.now ?? Date.now)(), at = iso(now), id = previous.sampleId || "";
  const base: TriageResult = {...previous, checkedAt: at};
  if (!triageConfigured()) return {...base, status: "skipped", nextCheck: undefined, message: "Tria.ge belum aktif. API key belum diisi."};
  if (!SAMPLE_ID.test(id)) return {...base, status: "failed", nextCheck: undefined, message: "ID sampel Tria.ge tidak valid."};
  const api = client(options);
  try {
    const sample = sampleRow.safeParse(await api.request(`/samples/${id}`));
    if (!sample.success || sample.data.id !== id) throw new TriageError("error", "Status Tria.ge tidak valid.");
    const status = mapStatus(sample.data.status);
    if (status === "failed") return {...base, status: "failed", nextCheck: undefined, message: "Tria.ge gagal menganalisis file ini."};
    if (status !== "reported") return expire({...base, status, message: undefined, nextCheck: iso(now + INTERVAL_MS)}, now);
    const overview = await api.request(`/samples/${id}/overview.json`, {}, OVERVIEW_MAX);
    const first = normalizeOverview(overview, sha256);
    // Dynamic reports add ports, SNI hostnames and DNS answers (filters CDN IPs); optional and bounded.
    const reports = (await Promise.all(first.behavioral.slice(0, MAX_DYNAMIC).map(task => api.request(`/samples/${id}/${task}/report_triage.json`, {}, REPORT_MAX).catch(() => null)))).filter(x => x !== null);
    const {result} = reports.length ? normalizeOverview(overview, sha256, reports) : first;
    const {nextCheck: _n, message: _m, ...kept} = base;
    return {...kept, ...result, status: "reported", url: triagePage(id)};
  } catch (error) {
    const e = error instanceof TriageError ? error : new TriageError("error", "Hasil Tria.ge belum dapat dibaca.");
    if (e.status === "not_found") return {...base, status: "failed", nextCheck: undefined, message: e.message};
    return expire({...base, status: e.status === "rate_limited" ? "rate_limited" : base.status === "rate_limited" ? "running" : base.status, message: e.status === "rate_limited" ? RATE_MESSAGE : `${e.message} Dicoba lagi otomatis.`, nextCheck: iso(now + (e.status === "rate_limited" ? RATE_RETRY_MS : INTERVAL_MS))}, now);
  }
}

// ---- sibling samples: other public samples of the same family. Operators rotate domains per build and packed APKs
// often stay silent in a sandbox, so earlier builds that did run (preferably signed with the same certificate) show the
// infrastructure behind the campaign. Bounded: 1 search + up to SIBLING_SCAN overviews + their static reports.
const SIBLING_SCAN = 6, MAX_SIBLINGS = 4, SIBLING_CONTACTS = 8;
export type SiblingInput = {family: string; sha256: string; cert?: {subject?: string; issuer?: string; validFrom?: string; validTo?: string}};
const second = (v: unknown) => { const t = Date.parse(clean(v, 40)); return Number.isFinite(t) ? Math.floor(t / 1000) : undefined; };
// Same subject, issuer and validity to the second: the same signing certificate in practice (Triage reports no thumbprint).
export function sameCert(staticReport: unknown, cert: NonNullable<SiblingInput["cert"]>) {
  const files = arr(rec(staticReport).files, 20).map(rec), file = files.find(f => f.selected === true) ?? files[0];
  const c = rec(arr(rec(rec(rec(file).metadata).code_sign).certificates, 5)[0]);
  const norm = (v: unknown) => clean(v, 300).replace(/\s+/g, "").toLowerCase();
  return Boolean(cert.subject && norm(c.subject) === norm(cert.subject) && (!cert.issuer || norm(c.issuer) === norm(cert.issuer)) && second(c.not_before) !== undefined && second(c.not_before) === second(cert.validFrom) && (!cert.validTo || second(c.not_after) === second(cert.validTo)));
}
// Public (debug/AOSP test) keys are shared by unrelated authors: never a link between samples.
const publicCert = (subject = "") => /Android Debug|android@android\.com/i.test(subject);
export function siblingContacts(overview: unknown) {
  const o = rec(overview), ctx: Contacts = {map: new Map(), served: new Map()};
  for (const t of arr(o.targets, 20).map(rec)) iocContacts(rec(t.iocs), ctx, true);
  iocContacts(rec(rec(o.sample).iocs), ctx, true);
  // A bare lookup of a shared platform (raw.githubusercontent.com) says nothing; its exact URL (a dead drop) does.
  return [...ctx.map.values()].filter(c => c.kind === "http" || !c.host || !under(c.host, SHARED)).sort((a, b) => KIND_RANK[a.kind] - KIND_RANK[b.kind]).slice(0, SIBLING_CONTACTS);
}
export async function findSiblings(input: SiblingInput, options: TriageOptions = {}): Promise<TriageSibling[]> {
  if (!triageConfigured() || !/^[\w.-]{2,40}$/.test(input.family)) return [];
  const api = client(options), cert = input.cert && !publicCert(input.cert.subject) ? input.cert : undefined;
  const body = rec(await api.request(`/search?query=${encodeURIComponent(`family:${input.family}`)}`));
  const rows = arr(body.data, 50).flatMap(x => { const r = sampleRow.safeParse(x); return r.success && r.data.status === "reported" && r.data.kind !== "url" && r.data.sha256?.toLowerCase() !== input.sha256 ? [r.data] : []; })
    .sort((a, b) => (Date.parse(b.submitted || "") || 0) - (Date.parse(a.submitted || "") || 0)).slice(0, SIBLING_SCAN);
  const out = await Promise.all(rows.map(async (row): Promise<TriageSibling | null> => {
    const overview = rec(await api.request(`/samples/${row.id}/overview.json`, {}, OVERVIEW_MAX).catch(() => null));
    // Only samples that were actually run: static IOCs are strings, not observed connections.
    const ran = overviewTasks(overview).some(t => t.kind === "behavioral" && t.status === "reported");
    const contacted = ran ? siblingContacts(overview) : [];
    if (!contacted.length) return null;
    const match = cert && sameCert(await api.request(`/samples/${row.id}/reports/static`, {}, REPORT_MAX).catch(() => null), cert) ? "cert" as const : "family" as const;
    const name = clean(rec(overview.sample).target, 80);
    return defined({sampleId: row.id, url: triagePage(row.id), name: name && !/^[a-f0-9]{32,}/i.test(name) ? name : undefined, submitted: clean(row.submitted, 40) || undefined, match, contacted});
  }));
  return out.filter(x => x !== null).sort((a, b) => Number(b.match === "cert") - Number(a.match === "cert")).slice(0, MAX_SIBLINGS);
}

// ---- report merge
const MAIL = ["gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "office365.com", "aol.com", "icloud.com", "yandex.ru", "yandex.com", "mail.ru", "zoho.com", "gmx.com", "gmx.net", "protonmail.com", "proton.me"];
// Hosts from extracted configs (C2 first, then exfiltration servers that are not shared mail providers); shared
// platforms (Telegram API, GitHub, Discord...) say nothing about the operator and are left out.
export function configHosts(t?: TriageResult) {
  const out: string[] = [];
  for (const c of t?.configs ?? []) {
    for (const v of c.c2) { const h = hostOf(v); if (h && publicHost(h) && !under(h, SHARED)) out.push(h); }
    for (const cred of c.credentials ?? []) { const h = cred.host ? hostOf(cred.host) : ""; if (h && publicHost(h) && !under(h, [...MAIL, ...SHARED])) out.push(h); }
  }
  return [...new Set(out)];
}
// Config C2s and sandbox-contacted hosts/IPs go to the front of metadata.campaign.hosts (≤ 8 of 12 slots, like the
// VirusTotal sandbox). Returns the hosts that were not there before (for the reputation lookup).
export function mergeTriageHosts(artifact: Artifact) {
  const t = artifact.triage; if (t?.status !== "reported") return [];
  const meta = artifact.metadata.campaign, campaign = meta && typeof meta === "object" && !Array.isArray(meta) ? meta as Record<string, unknown> : {};
  const old = Array.isArray(campaign.hosts) ? campaign.hosts.filter((h): h is string => typeof h === "string") : [];
  const contacted = t.contacted ?? [];
  const fresh = [...new Set([...configHosts(t), ...contacted.map(c => c.host), ...contacted.map(c => c.ip)].filter((h): h is string => Boolean(h) && publicHost(h!)))].slice(0, 8);
  if (!fresh.length) return [];
  artifact.metadata.campaign = {...campaign, hosts: [...new Set([...fresh, ...old])].slice(0, 12)};
  return fresh.filter(h => !old.includes(h));
}
export const TRIAGE_INDICATORS = /^(?:Sandbox Tria\.ge|Konfigurasi malware diekstrak sandbox Tria\.ge)/;
// Sandbox verdict and extracted configs as indicators (first), safe to re-apply.
export function applyTriageIndicators(artifact: Artifact) {
  const t = artifact.triage, out: {name: string; evidence: string}[] = [];
  if (t?.status === "reported") {
    const fam = t.family?.length ? `, famili ${t.family.join("/")}` : "";
    if (t.score !== undefined && t.score >= 6) out.push({name: `Sandbox Tria.ge menilai ${t.score >= 8 ? "berbahaya" : "mencurigakan"} (skor ${t.score}/10${fam})`, evidence: `Tria.ge (sandbox publik pihak ketiga) memberi skor ${t.score}/10${fam}${t.tags?.length ? `; tag: ${t.tags.slice(0, 8).join(", ")}` : ""}${t.signatures?.length ? `; perilaku: ${t.signatures.slice(0, 4).map(s => s.name).join("; ")}` : ""}.`.slice(0, 400)});
    const c2 = (t.configs ?? []).filter(c => c.c2.length || c.credentials?.length);
    const twins = (t.siblings ?? []).filter(x => x.contacted.length), certTwins = twins.filter(x => x.match === "cert");
    if (twins.length) out.push({name: `Sandbox Tria.ge: ${twins.length} sampel kembaran${certTwins.length ? ` (${certTwins.length} bersertifikat sama)` : ""} menghubungi server kampanye`, evidence: twins.map(x => `${x.name || x.sampleId}${x.match === "cert" ? " [sertifikat sama]" : ""}: ${x.contacted.slice(0, 4).map(c => c.host || c.ip).join(", ")}`).join("; ").slice(0, 400)});
    if (c2.length) out.push({name: `Konfigurasi malware diekstrak sandbox Tria.ge (${[...new Set(c2.map(c => c.family))].join("/")})`, evidence: c2.map(c => `${c.family}: ${[...c.c2, ...(c.credentials ?? []).map(x => `${x.protocol ? `${x.protocol}://` : ""}${x.host ?? ""}${x.username ? ` (akun ${x.username})` : ""}`)].slice(0, 6).join(", ")}${c.botnet ? `; botnet ${c.botnet}` : ""}`).join("; ").slice(0, 400)});
  }
  artifact.indicators = [...out, ...artifact.indicators.filter(i => !TRIAGE_INDICATORS.test(i.name))];
  return artifact;
}
