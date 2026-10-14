import { z } from "zod";
import { rateLimit } from "./db";
import type { Artifact, ThreatIntelResult } from "./types";
import { BENIGN, SHARED, hostOf, privateIp, publicHost, registrableDomain, under } from "./hosts";

// External reputation for a finished extraction: abuse.ch (MalwareBazaar hash, URLhaus/ThreatFox hosts) and RDAP domain age.
// Only the SHA-256, hostnames and a few clean payload URLs leave the server (never file bytes, query strings or redacted
// secrets). Bounded: 15 s total, 6 s per request, small concurrency, shared per-minute quotas; never throws.
const MB_API = "https://mb-api.abuse.ch/api/v1/", URLHAUS = "https://urlhaus-api.abuse.ch/v1/", THREATFOX = "https://threatfox-api.abuse.ch/api/v1/", RDAP = "https://rdap.org/domain/";
const MAX_HOSTS = 12, MAX_URLS = 3, MAX_DOMAINS = 8, BUDGET_MS = 15000, TIMEOUT_MS = 6000, MAX_BYTES = 1024 * 1024, MAX_JSON = 6000;
const PAYLOAD = /\.(?:apk|xapk|exe|dll|scr|msi|zip|rar|7z|jar|dex|bin|ps1|vbs|hta|sh|php)$/i;
// Host helpers live in lib/hosts.ts (pure, shared with extraction and the report UI); re-exported for existing callers.
export { privateIp, hostOf, publicHost, registrableDomain };

// Hosts (exfil/panel endpoints first) and clean payload URLs extracted by lib/extract.ts.
export function threatIntelTargets(artifact: Artifact) {
  const campaign = artifact.metadata?.campaign as {hosts?: unknown} | undefined;
  const raw = [...Array.isArray(campaign?.hosts) ? campaign.hosts : [], ...Array.isArray(artifact.urls) ? artifact.urls : []].filter((x): x is string => typeof x === "string").slice(0, 300);
  const hosts = [...new Set(raw.map(hostOf))].filter(h => h && publicHost(h) && !under(h, SHARED)).slice(0, MAX_HOSTS);
  // Full URLs only without query/userinfo/redaction marks (they may carry tokens), and never bot/webhook API paths.
  const urls = [...new Set(artifact.urls || [])].filter(u => {
    if (typeof u !== "string" || u.length > 200 || /[…?@#]|\/bot\d|webhook|token|api[_-]?key|secret|passw/i.test(u) || !/^https?:\/\/[^/]+\/./i.test(u)) return false;
    const h = hostOf(u); return Boolean(h) && (under(h, SHARED) ? PAYLOAD.test(u) : publicHost(h));
  }).sort((x, y) => Number(PAYLOAD.test(y)) - Number(PAYLOAD.test(x))).slice(0, MAX_URLS);
  const domains = [...new Set(hosts.map(registrableDomain).filter((d): d is string => Boolean(d) && !under(d!, BENIGN) && !under(d!, SHARED)))].slice(0, MAX_DOMAINS);
  return {hosts, urls, domains};
}

type Provider = "abusech" | "rdap";
type Fetch = (input: string, init?: RequestInit) => Promise<Response>;
export type ThreatIntelOptions = {fetch?: Fetch; requestGate?: (provider: Provider) => Promise<boolean>; signal?: AbortSignal; budgetMs?: number; timeoutMs?: number; now?: number};
class Note extends Error {
  constructor(public kind: "skipped" | "errors", message: string, public stop?: Provider) { super(message); }
}
type Ctx = {fetch: Fetch; key: string; signal: AbortSignal; timeoutMs: number; gate: (p: Provider) => Promise<boolean>; result: ThreatIntelResult; notes: {skipped: Set<string>; errors: Set<string>}; stopped: Set<Provider>; now: number};

const text = (v: unknown, n = 60) => typeof v === "string" ? v.replace(/[\x00-\x1f\x7f]+/g, " ").trim().slice(0, n) : typeof v === "number" ? String(v).slice(0, n) : "";
const list = (v: unknown, n = 4, m = 30) => Array.isArray(v) ? [...new Set(v.map(x => text(x, m)).filter(Boolean))].slice(0, n) : [];
const count = (v: unknown) => { const n = Number(v); return v !== null && v !== "" && Number.isInteger(n) && n >= 0 && n < 1e9 ? n : undefined; };
function day(v: unknown) {
  const s = text(v, 40); if (!s) return undefined;
  const t = Number.isFinite(Date.parse(s)) ? Date.parse(s) : Date.parse(`${s.replace(" ", "T").replace(/\s*UTC$/, "")}Z`);
  return Number.isFinite(t) && t > Date.UTC(1985, 0, 1) && t < Date.UTC(2100, 0, 1) ? new Date(t).toISOString().slice(0, 10) : undefined;
}
const reference = (v: unknown, host: string) => { const s = text(v, 120); try { return s && new URL(s).protocol === "https:" && new URL(s).hostname === host ? s : undefined; } catch { return undefined; } };
const record = (v: unknown) => v && typeof v === "object" && !Array.isArray(v) ? v as Record<string, unknown> : {};

async function readJson(response: Response) {
  if (!response.body) throw new Error("Empty provider response");
  const reader = response.body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
  try {
    while (true) {
      const {done, value} = await reader.read(); if (done) break;
      size += value.length; if (size > MAX_BYTES) { await reader.cancel(); throw new Error("Oversized provider response"); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
}
async function request(ctx: Ctx, provider: Provider, label: string, url: string, init: RequestInit) {
  if (ctx.stopped.has(provider) || ctx.signal.aborted) return null;
  if (!await ctx.gate(provider)) throw new Note("skipped", `Kuota pemeriksaan ${provider === "rdap" ? "RDAP" : "abuse.ch"} tercapai; sebagian indikator tidak diperiksa.`, provider);
  // rdap.org (Cloudflare) rejects the default Node user agent.
  const response = await ctx.fetch(url, {...init, headers: {...init.headers, "user-agent": "Kheronyx/1.0 (static file risk analysis; reputation lookup)"}, signal: AbortSignal.any([ctx.signal, AbortSignal.timeout(ctx.timeoutMs)]), cache: "no-store"});
  if (!response.ok) {
    await response.body?.cancel().catch(() => {});
    if (response.status === 404 && provider === "rdap") return null;
    if (response.status === 429) throw new Note("skipped", `${label} membatasi permintaan; sebagian indikator tidak diperiksa.`, provider);
    if ([401, 403].includes(response.status) && provider === "abusech") throw new Note("errors", "Auth-Key abuse.ch ditolak; periksa ABUSE_CH_AUTH_KEY.", provider);
    throw new Note("errors", `${label} gagal (${response.status}).`);
  }
  const body = record(await readJson(response));
  if (provider === "abusech" && /auth|key/i.test(text(body.query_status))) throw new Note("errors", "Auth-Key abuse.ch ditolak; periksa ABUSE_CH_AUTH_KEY.", provider);
  return body;
}
const abuse = (ctx: Ctx, label: string, url: string, body: URLSearchParams | Record<string, unknown>) => request(ctx, "abusech", label, url, {
  method: "POST", redirect: "error", body: body instanceof URLSearchParams ? body : JSON.stringify(body),
  headers: {"Auth-Key": ctx.key, accept: "application/json", ...body instanceof URLSearchParams ? {} : {"content-type": "application/json"}},
});
function unexpected(label: string, status: string): never { throw new Note("errors", `${label}: respons tidak dikenali${status ? ` (${status})` : ""}.`); }

const sampleSchema = z.object({sha256_hash: z.string(), signature: z.unknown(), tags: z.unknown(), first_seen: z.unknown(), file_type: z.unknown(), delivery_method: z.unknown(), vendor_intel: z.unknown()});
function vendors(v: unknown) {
  const out: string[] = [];
  for (const [name, raw] of Object.entries(record(v)).slice(0, 40)) {
    const r = record(Array.isArray(raw) ? raw[0] : raw), label = text(r.malware_family ?? r.family_name ?? r.threat_name ?? r.detection ?? r.verdict, 40);
    if (label && !/^(?:unknown|n\/a|none|null|-|not[ _]?malicious|clean|no[ _]threats?.*)$/i.test(label)) out.push(`${text(name, 20)}: ${label}`);
    if (out.length >= 5) break;
  }
  return out.length ? out : undefined;
}
async function malwareBazaar(ctx: Ctx, sha256: string) {
  const body = await abuse(ctx, "MalwareBazaar", MB_API, new URLSearchParams({query: "get_info", hash: sha256})); if (!body) return;
  const status = text(body.query_status, 40);
  if (["hash_not_found", "no_results"].includes(status)) { ctx.result.malwareBazaar = null; return; }
  if (status !== "ok") unexpected("MalwareBazaar", status);
  const sample = z.array(sampleSchema).min(1).parse(body.data)[0];
  if (sample.sha256_hash.toLowerCase() !== sha256) unexpected("MalwareBazaar", "hash tidak cocok");
  const fileType = text(sample.file_type, 20), delivery = text(sample.delivery_method, 40), firstSeen = day(sample.first_seen), vendorList = vendors(sample.vendor_intel);
  ctx.result.malwareBazaar = {family: text(sample.signature, 60) || null, tags: list(sample.tags, 6), ...firstSeen ? {firstSeen} : {}, ...fileType ? {fileType} : {}, ...delivery ? {delivery} : {}, ...vendorList ? {vendors: vendorList} : {}, reference: `https://bazaar.abuse.ch/sample/${sha256}/`};
}
const blacklists = (v: unknown) => Object.entries(record(v)).filter(([, s]) => typeof s === "string" && !/^not[ _]listed$/i.test(s)).slice(0, 3).map(([k, s]) => `${text(k, 20)}: ${text(s, 30)}`);
async function urlhausHost(ctx: Ctx, host: string) {
  const body = await abuse(ctx, "URLhaus", `${URLHAUS}host/`, new URLSearchParams({host})); if (!body) return;
  const status = text(body.query_status, 40); if (status === "no_results") return; if (status !== "ok") unexpected("URLhaus", status);
  const rows = (Array.isArray(body.urls) ? body.urls : []).slice(0, 200).map(record), urlCount = count(body.url_count) ?? rows.length;
  if (!urlCount && !rows.length) return;
  const firstSeen = day(body.firstseen), ref = reference(body.urlhaus_reference, "urlhaus.abuse.ch"), lists = blacklists(body.blacklists);
  ctx.result.urlhaus.push({target: host, kind: "host", urlCount, online: rows.filter(r => r.url_status === "online").length, threats: list(rows.map(r => r.threat), 2), tags: list(rows.flatMap(r => Array.isArray(r.tags) ? r.tags : []), 5), ...lists.length ? {blacklists: lists} : {}, ...firstSeen ? {firstSeen} : {}, ...ref ? {reference: ref} : {}});
}
async function urlhausUrl(ctx: Ctx, url: string) {
  const body = await abuse(ctx, "URLhaus", `${URLHAUS}url/`, new URLSearchParams({url})); if (!body) return;
  const status = text(body.query_status, 40); if (status === "no_results") return; if (status !== "ok") unexpected("URLhaus", status);
  const payloads = (Array.isArray(body.payloads) ? body.payloads : []).slice(0, 50).map(record), lists = blacklists(body.blacklists), firstSeen = day(body.date_added), ref = reference(body.urlhaus_reference, "urlhaus.abuse.ch"), families = list(payloads.map(p => p.signature), 3);
  ctx.result.urlhaus.push({target: url, kind: "url", status: text(body.url_status, 20) || undefined, threats: list([body.threat], 1), tags: list(body.tags, 5), ...families.length ? {families} : {}, ...lists.length ? {blacklists: lists} : {}, ...firstSeen ? {firstSeen} : {}, ...ref ? {reference: ref} : {}});
}
async function threatFox(ctx: Ctx, host: string) {
  const body = await abuse(ctx, "ThreatFox", THREATFOX, {query: "search_ioc", search_term: host}); if (!body) return;
  const status = text(body.query_status, 40); if (status === "no_result" || status === "no_results") return; if (status !== "ok") unexpected("ThreatFox", status);
  // The search may be fuzzy: only IOCs whose host is exactly the extracted host count.
  const matches = (Array.isArray(body.data) ? body.data : []).slice(0, 200).map(record).filter(r => hostOf(text(r.ioc, 300)) === host); if (!matches.length) return;
  const first = matches[0], id = count(first.id), confidence = count(first.confidence_level), firstSeen = day(first.first_seen), threatType = text(first.threat_type, 30);
  ctx.result.threatfox.push({term: host, family: text(first.malware_printable, 60) || text(first.malware, 60) || null, ...threatType ? {threatType} : {}, ...confidence !== undefined && confidence <= 100 ? {confidence} : {}, ...firstSeen ? {firstSeen} : {}, matches: matches.length, ...id !== undefined ? {reference: `https://threatfox.abuse.ch/ioc/${id}/`} : {}});
}
function registrar(entities: unknown): string | undefined {
  for (const e of (Array.isArray(entities) ? entities : []).slice(0, 20).map(record)) {
    if (!Array.isArray(e.roles) || !e.roles.includes("registrar")) continue;
    const card = Array.isArray(e.vcardArray) && Array.isArray(e.vcardArray[1]) ? e.vcardArray[1] as unknown[] : [];
    const fn = card.find(f => Array.isArray(f) && f[0] === "fn") as unknown[] | undefined, name = text(fn?.[3], 60);
    if (name) return name;
  }
  return undefined;
}
async function rdap(ctx: Ctx, domain: string) {
  const body = await request(ctx, "rdap", "RDAP", `${RDAP}${encodeURIComponent(domain)}`, {redirect: "follow", headers: {accept: "application/rdap+json, application/json"}}); if (!body) return;
  if (body.ldhName !== undefined && text(body.ldhName, 260).toLowerCase().replace(/\.$/, "") !== domain) unexpected("RDAP", "domain tidak cocok");
  const events = (Array.isArray(body.events) ? body.events : []).slice(0, 30).map(record), at = (action: string) => day(events.find(e => e.eventAction === action)?.eventDate);
  const registered = at("registration"), expires = at("expiration"), name = registrar(body.entities);
  const age = registered ? Math.floor((ctx.now - Date.parse(registered)) / 86400000) : undefined;
  ctx.result.domains.push({domain, ...registered ? {registered} : {}, ...expires ? {expires} : {}, ...age !== undefined && age >= 0 ? {ageDays: age} : {}, ...name ? {registrar: name} : {}});
}

async function pool<T>(items: T[], size: number, run: (item: T) => Promise<void>) {
  let i = 0; await Promise.all(Array.from({length: Math.min(size, items.length)}, async () => { while (i < items.length) await run(items[i++]); }));
}
function compact(r: ThreatIntelResult): ThreatIntelResult {
  // Keeps the AI evidence bound (see assess() 120k guard): normal results are a few KB; pathological ones lose detail first.
  if (JSON.stringify(r).length > MAX_JSON) for (const x of [...r.urlhaus, ...r.threatfox]) { delete x.reference; delete (x as {tags?: string[]}).tags; }
  if (JSON.stringify(r).length > MAX_JSON) { r.urlhaus = r.urlhaus.slice(0, 6); r.threatfox = r.threatfox.slice(0, 6); if (r.malwareBazaar) delete r.malwareBazaar.vendors; }
  return r;
}

export async function inspectThreatIntel(artifact: Artifact, options: ThreatIntelOptions = {}): Promise<ThreatIntelResult> {
  const result: ThreatIntelResult = {checkedAt: new Date().toISOString(), hosts: [], urlhaus: [], threatfox: [], domains: []};
  const notes = {skipped: new Set<string>(), errors: new Set<string>()}, controller = new AbortController();
  const finish = () => { const out = structuredClone(result); if (notes.skipped.size) out.skipped = [...notes.skipped].slice(0, 6); if (notes.errors.size) out.errors = [...notes.errors].slice(0, 6); return compact(out); };
  const timer = setTimeout(() => controller.abort(), options.budgetMs ?? BUDGET_MS);
  try {
    const {hosts, urls, domains} = threatIntelTargets(artifact); result.hosts = hosts;
    const key = process.env.ABUSE_CH_AUTH_KEY?.trim() || "";
    const ctx: Ctx = {
      fetch: options.fetch || ((input, init) => fetch(input, init)), key, timeoutMs: options.timeoutMs ?? TIMEOUT_MS, result, notes, stopped: new Set(), now: options.now ?? Date.now(),
      signal: options.signal ? AbortSignal.any([options.signal, controller.signal]) : controller.signal,
      gate: options.requestGate || (provider => provider === "abusech" ? rateLimit("abusech:minute", 60, 60) : rateLimit("rdap:minute", 40, 60)),
    };
    const guarded = (fn: () => Promise<void>) => async () => {
      try { await fn(); } catch (error) {
        if (ctx.signal.aborted) return;
        if (error instanceof Note) { notes[error.kind].add(error.message); if (error.stop) ctx.stopped.add(error.stop); }
        else notes.errors.add(error instanceof Error && /timeout|abort/i.test(error.name) ? "Sebagian pemeriksaan reputasi melewati batas waktu." : "Sebagian pemeriksaan reputasi gagal atau responsnya tidak valid.");
      }
    };
    const abuseTasks = key ? [
      ...(/^[a-f0-9]{64}$/.test(artifact.sha256) ? [guarded(() => malwareBazaar(ctx, artifact.sha256))] : []),
      ...hosts.flatMap(h => [guarded(() => urlhausHost(ctx, h)), guarded(() => threatFox(ctx, h))]),
      ...urls.map(u => guarded(() => urlhausUrl(ctx, u))),
    ] : [];
    if (!key) notes.skipped.add("abuse.ch (MalwareBazaar, URLhaus, ThreatFox) tidak diperiksa: ABUSE_CH_AUTH_KEY belum diisi.");
    const work = Promise.all([pool(abuseTasks, 4, task => task()), pool(domains.map(d => guarded(() => rdap(ctx, d))), 3, task => task())]);
    const aborted = new Promise<void>(resolve => ctx.signal.aborted ? resolve() : ctx.signal.addEventListener("abort", () => resolve(), {once: true}));
    await Promise.race([work, aborted]);
    if (ctx.signal.aborted) notes.errors.add("Batas waktu pemeriksaan reputasi tercapai; sebagian indikator tidak diperiksa.");
  } catch { notes.errors.add("Pemeriksaan reputasi eksternal gagal."); }
  finally { clearTimeout(timer); controller.abort(); }
  try { return finish(); } catch { return {checkedAt: result.checkedAt, hosts: [], urlhaus: [], threatfox: [], domains: [], errors: ["Pemeriksaan reputasi eksternal gagal."]}; }
}

const GENERIC_TAG = /^(?:apk|exe|dll|elf|msi|jar|zip|rar|7z|iso|lnk|js|vbs|ps1|bat|hta|doc|docx|xls|xlsx|pdf|android|windows|linux|macos|signed|unsigned|upx|dotnet|\.net|golang|nsis|inno|32|64|x86|x64|arm|malware|trojan|rat|stealer|banker|spyware|dropper|loader|botnet|ransomware|miner|backdoor|phishing|sms|[a-z]{2,3}|dropped-by-.*|.*\.(?:banker|spy|trojan|rat))$/i;
export const THREAT_INTEL_INDICATORS = /^(?:File dikenal sebagai malware di MalwareBazaar|Server tercatat sebagai penyebar malware \(URLhaus\)|Indikator dikenal di ThreatFox|Domain baru didaftarkan)/;
export function threatIntelIndicators(r: ThreatIntelResult) {
  const high: {name: string; evidence: string}[] = [], other: typeof high = [];
  // MalwareBazaar often leaves signature empty while the tags still name the family (e.g. ["apk", "signed", "SmsSpy"]).
  const mb = r.malwareBazaar, family = mb && (mb.family || mb.tags.find(t => !GENERIC_TAG.test(t)));
  if (mb) high.push({name: `File dikenal sebagai malware di MalwareBazaar (${family || "famili tidak disebut"})`, evidence: `Tingkat ${family ? "kritis" : "tinggi"}: SHA-256 file ini tercatat di MalwareBazaar (abuse.ch)${mb.family ? ` sebagai ${mb.family}` : family ? ` dengan tag famili ${family}` : ""}${mb.tags.length ? `; tag: ${mb.tags.join(", ")}` : ""}${mb.firstSeen ? `; pertama terlihat ${mb.firstSeen}` : ""}${mb.fileType ? `; tipe ${mb.fileType}` : ""}${mb.delivery ? `; penyebaran: ${mb.delivery}` : ""}${mb.vendors?.length ? `; vendor: ${mb.vendors.join(", ")}` : ""}.`.slice(0, 400)});
  if (r.urlhaus.length) high.push({name: "Server tercatat sebagai penyebar malware (URLhaus)", evidence: `Tingkat tinggi: ${r.urlhaus.map(h => `${h.target} (${[h.kind === "host" ? `${h.urlCount ?? 0} URL malware tercatat${h.online ? `, ${h.online} masih online` : ", semua offline"}` : `URL tercatat, status ${h.status || "tidak diketahui"}`, ...h.threats || [], ...h.families?.length ? [`payload: ${h.families.join("/")}`] : [], ...h.tags?.slice(0, 3) || [], h.firstSeen ? `sejak ${h.firstSeen}` : ""].filter(Boolean).join(", ")})`).join("; ")}.`.slice(0, 400)});
  const families = new Map<string, typeof r.threatfox>();
  for (const t of r.threatfox) { const k = t.family || "famili tidak disebut"; families.set(k, [...families.get(k) || [], t]); }
  for (const [family, hits] of [...families].slice(0, 3)) {
    const strong = hits.some(h => (h.confidence ?? 100) >= 50);
    (strong ? high : other).push({name: `Indikator dikenal di ThreatFox (${family})`, evidence: `Tingkat ${strong ? "tinggi" : "sedang"}: ${hits.map(h => `${h.term} (${[h.threatType, h.confidence !== undefined ? `keyakinan ${h.confidence}%` : "", h.firstSeen ? `sejak ${h.firstSeen}` : ""].filter(Boolean).join(", ")})`).join("; ")}.`.slice(0, 400)});
  }
  for (const d of r.domains.filter(d => d.ageDays !== undefined && d.ageDays < 180).sort((a, b) => a.ageDays! - b.ageDays!).slice(0, 3)) {
    const young = d.ageDays! < 30;
    (young ? high : other).push({name: `Domain baru didaftarkan (${d.ageDays} hari)`, evidence: `Tingkat ${young ? "tinggi" : "sedang"}: ${d.domain} didaftarkan ${d.registered}${d.registrar ? ` lewat ${d.registrar}` : ""} (data RDAP); domain yang sangat baru sering dipakai sebagai panel atau penampung data penipuan.`.slice(0, 400)});
  }
  return {high, other};
}
// Stores the result and surfaces hits as indicators (high first) for the AI and report; safe to re-apply.
export function applyThreatIntel(artifact: Artifact, result: ThreatIntelResult) {
  const {high, other} = threatIntelIndicators(result);
  artifact.threatIntel = result;
  artifact.indicators = [...high, ...artifact.indicators.filter(i => !THREAT_INTEL_INDICATORS.test(i.name)), ...other];
  return artifact;
}
