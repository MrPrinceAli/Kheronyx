import { member, redactSecrets, sourceLabel } from "./behaviors";
import { decodeHidden } from "./deobfuscate";
import { impersonatedBrand, type Lookalike } from "./brands";
import { BENIGN, DDNS_HINT, DDNS_HOST, DOMAIN, SHARED, customerHost, deadDrop, ipv4, publicHost, publicIpv4, under, validPort, zoneOf } from "./hosts";
// C2/exfiltration endpoints from candidate strings (DEX/payload strings, deobfuscated values, native .so strings,
// resources.arsc, manifest meta-data, EXE ASCII/UTF-16 and .NET user strings). Strings are only pattern-matched; no
// address is ever resolved or contacted. Bare IPs need context (port, URL, deobfuscation, native code or a link to
// network code) so resolvers, OIDs and version numbers are not reported.
// deaddrop: public service hosting the C2 address (paste/raw/export document), label "Sumber konfigurasi pelaku (dead drop)".
// phishing: web address on a look-alike domain of a bank/e-wallet/marketplace/courier/government brand (lib/brands.ts),
// label "Domain peniru merek (<brand>)"; `brand` is also set on DDNS/tunnel/Firebase endpoints whose host imitates a brand.
export type EndpointKind = "panel" | "telegram" | "webhook" | "firebase" | "ip" | "ddns" | "tunnel" | "deaddrop" | "phishing" | "url" | "email";
// source: dex | payload | resources | manifest | exe | dotnet | native:<lib> | deobfuscated:<technique>
export type Endpoint = {value: string; host: string; port?: number; kind: EndpointKind; source: string; via?: string; brand?: Lookalike};
type Raw = {text: string; source: string; context: boolean; via?: string; callers?: string[]};
type Scored = Endpoint & {score: number};
const MAX_RAW = 6000, PER_CALL = 1500, MAX_SCAN = 2_000_000, MAX_DECODE = 20000, MAX = 25;
// Cheap gate: URL, dotted quad, bot token, SMTP host, e-mail address, DDNS/tunnel zone.
const HINT = /:\/\/|(?<![\d.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d)|\d{6,12}:AA[\w-]{30}|\bsmtp\.|@[a-z0-9-]+\.[a-z]{2}/i;
const IP_HINT = /(?<![\d.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?![\d.])/;
// Bare IP or DDNS/tunnel host: what parseDex should record const-string call sites for (to link them to socket code).
export const hostHint = (s: string) => s.length >= 7 && s.length <= 300 && (IP_HINT.test(s) || DDNS_HINT.test(s));
const URL_RE = /\b(?:https?|wss?|tcp|udp|ftp|rtmp):\/\/[^\s"'<>\\`{}|^]{3,300}/gi;
const URL_PARTS = /^([a-z][\w+.-]*):\/\/(?:[^@/?#\s]*@)?([^:/?#\s]+)(?::(\d{1,5}))?([^?#\s]*)(\?[^#\s]*)?/i;
const TOKEN = /(?<![\d])(\d{6,12}):(AA[\w-]{30,40})(?![\w-])/g;
const BARE_IP = /(?<![\w.\/:@%-])((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?(?![\w.]|:\d|\/\d)/g;
const SMTP = /(?<![\w.-])(smtp\.[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,24})(?::(\d{2,5}))?(?![\w-])/gi;
const EMAIL = /(?<![\w.%+-])[a-z0-9._%+-]{1,64}@((?:[a-z0-9-]+\.)+[a-z]{2,24})(?![\w-])/gi;
const VERSION = /\b(?:version|ver|build|release|sdk|chrome|firefox|safari|mozilla|applewebkit|gecko|opera|edge|msie|android|ios|v)\b[\s:=/]*\d|\/\d+\.\d/i;
const PANEL = /\.(?:php\d?|aspx?|jsp|cgi)(?:[/?#;]|$)|\/(?:gate|panel|admin|api|bot|inject|upload|receive|submit|send|data|log|post)\w{0,3}(?:[/?#.]|$)/i;
const FIREBASE = ["firebaseio.com", "firebasedatabase.app", "cloudfunctions.net"];
// SDK/CDN/docs hosts that are noise as "endpoints" (on top of BENIGN shared with threat-intel lookups).
// Protocol identifiers, certificate revocation/OCSP hosts and bug trackers embedded in bundled libraries (WebRTC, BoringSSL,
// Chromium): URL-shaped strings that are never contacted.
const IDENTIFIER = /^(?:crl\d*|ocsp\d*|cacerts?|certs?)\./i, IDENTIFIER_PATH = /\.(?:crl|crt|cer|der|p7c)\d?$|\/experiments\/|\/rtp-hdrext\//i;
const QUIET = ["webrtc.org", "crbug.com", "chromium.org", "globalsign.net", "globalsign.com", "public-trust.com", "digicert.com", "sectigo.com", "usertrust.com", "entrust.net", "letsencrypt.org", "lencr.org", "identrust.com", "godaddy.com", "starfieldtech.com", "comodoca.com", "verisign.com", "symcb.com", "symcd.com", "thawte.com", "geotrust.com", "pki.goog", "amazontrust.com", "quovadisglobal.com", "certum.pl", "buypass.no", "swisssign.net", "schemas.android.com", "googlesource.com", "googletagmanager.com", "gravatar.com", "jquery.com", "bootstrapcdn.com", "unpkg.com", "akamaihd.net", "akamai.net", "branch.io", "app.link", "appsflyer.com", "adjust.com", "onesignal.com", "sentry.io", "amplitude.com", "mixpanel.com", "facebook.net", "fb.com", "fb.me", "openstreetmap.org", "mapbox.com", "bing.com", "baidu.com", "qq.com", "umeng.com", "xiaomi.com", "huawei.com", "hicloud.com", "samsung.com", "stackoverflow.com", "sourceforge.net", "gnu.org", "opensource.org", "creativecommons.org", "json.org", "ietf.org", "iana.org", "openssl.org", "curl.se", "haxx.se", "sqlite.org", "zlib.net", "libpng.org", "fontawesome.com", "gradle.org", "kotlinlang.org", "jetbrains.com", "oracle.com", "java.com", "sun.com", "ns.adobe.com", "xmlsoap.org", "openxmlformats.org", "firebase.com", "go.dev", "golang.org", "tempuri.org", "whatwg.org", "g.co", "eclipse.org", "netty.io", "slf4j.org", "jivesoftware.com", "semrush.com", "ip-api.com", "ipinfo.io", "ip.sb", "dyn.com", "noip.com", "no-ip.com", "dynu.com", "ngrok.com", "afraid.org", "changeip.com", "dynv6.com", "duckdns.com", "playit.gg", "localxpose.io", "yandex.ru", "yandex.net", "yandex.com", "localhost"];
const MAIL = ["gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "office365.com", "aol.com", "icloud.com", "yandex.ru", "yandex.com", "mail.ru", "zoho.com", "gmx.com", "gmx.net", "protonmail.com", "proton.me"];
const BASE: Record<EndpointKind, number> = {telegram: 1, ddns: 1, ip: 2, webhook: 2, tunnel: 2, panel: 3, deaddrop: 3, phishing: 3, email: 4, firebase: 5, url: 6};
const CAPS: Partial<Record<EndpointKind, number>> = {url: 8, panel: 10, deaddrop: 6, phishing: 8, firebase: 4, email: 4};
// Only deliberate obfuscation is strong context. Native libraries are full of dotted version numbers ("6.7.8.5" in libvlc),
// so their bare IPs need a port or URL like any other string.
const hidden = (source: string) => source.startsWith("deobfuscated");
// "example" in many languages (localized help texts ship hosts like exemple.duckdns.org) and other sample placeholders.
const PLACEHOLDER = /(?:^|\.)(?:example|exemple|ejemplo|esempio|exemplo|exempel|beispiel|eksempel|esimerkki|voorbeeld|przyklad|przykład|contoh|ornek|örnek|primer|primjer|priklad|příklad|pelda|példa|paradigma|yourdomain|your-domain|mydomain|my-domain|yourserver|myserver|yourhost|myhost|sample|domain)[.-]/i;
const owner = (ref: string) => ref.slice(0, ref.indexOf(";->") + 1);

export class EndpointCollector {
  private raw: Raw[] = []; private seen = new Set<string>(); private decoded = 0;
  // `context`: bare IPs (no port/URL) in these strings are plausible endpoints; `callers`: methods that load the string
  // (const-string sites), linked to network code at finish(); `decode`: also try base64/hex (sources not already deobfuscated).
  // `library(s)`: the string is only loaded by third-party SDK code (decoded bytecode), so it is not the app's endpoint.
  add(list: Iterable<string>, source: string, opts: {context?: boolean | ((s: string) => boolean); via?: string; callers?: (s: string) => string[] | undefined; library?: (s: string) => boolean; decode?: boolean} = {}) {
    // Per-call share keeps one huge DEX full of SDK URLs from crowding out later sources; deobfuscated values get headroom.
    let scanned = 0; const cap = Math.min(MAX_RAW, this.raw.length + PER_CALL);
    for (const s of list) {
      if (this.raw.length >= cap || ++scanned > MAX_SCAN) break;
      if (typeof s !== "string" || s.length < 7) continue;
      const text = s.length > 1200 ? s.slice(0, 1200) : s;
      if (opts.decode && this.decoded < MAX_DECODE && text.length >= 16 && text.length <= 2048 && /^[A-Za-z0-9+/=_-]+$/.test(text)) {
        this.decoded++; const h = decodeHidden(text);
        if (h && (HINT.test(h.value) || DDNS_HINT.test(h.value))) this.push({text: h.value.slice(0, 1200), source: `deobfuscated:${h.technique}`, context: true, via: opts.via}, cap);
        continue;
      }
      if (!text.includes(".") && !text.includes(":AA") || !HINT.test(text) && !DDNS_HINT.test(text) || opts.library?.(text)) continue;
      this.push({text, source, context: typeof opts.context === "function" ? opts.context(text) : Boolean(opts.context), via: opts.via, callers: opts.callers?.(text)?.slice(0, 6)}, cap);
    }
  }
  // Values recovered by lib/deobfuscate.ts / lib/dex.ts (where = "Lcls;->method" or "native libx.so").
  hidden(list: {value: string; technique: string; where?: string}[]) {
    for (const h of list.slice(0, 300)) this.push({text: h.value.slice(0, 1200), source: `deobfuscated:${h.technique}`, context: true, via: h.where ? (h.where.includes(";->") ? member(h.where) : h.where).slice(0, 120) : undefined}, MAX_RAW + 300);
  }
  private push(r: Raw, cap: number) {const key = `${r.source}\0${r.text}`; if (this.seen.has(key) || this.raw.length >= cap) return; this.seen.add(key); this.raw.push(r);}
  // `linked(method)`: the calling method's class also uses network/socket APIs. `smtp`: SMTP sending code was seen.
  finish(opts: {linked?: (method: string) => boolean; smtp?: boolean; max?: number} = {}): Endpoint[] {
    const linked = opts.linked || (() => false), smtp = opts.smtp || this.raw.some(r => /\bsmtp\.[a-z0-9-]+\./i.test(r.text));
    const best = new Map<string, Scored>();
    for (const r of this.raw) for (const e of classify(r, smtp, linked)) {
      const key = e.value.toLowerCase(), prev = best.get(key);
      if (!prev || e.score < prev.score) best.set(key, prev?.via && !e.via ? {...e, via: prev.via} : e); else if (!prev.via && e.via) prev.via = e.via;
    }
    const all = [...best.values()].sort((a, b) => a.score - b.score), max = opts.max ?? MAX;
    const fuller = new Set(all.filter(e => e.port || e.value.includes("://")).map(e => e.host)), count = new Map<EndpointKind, number>(), out: Endpoint[] = [];
    for (const e of all) {
      if (out.length >= max) break;
      if (!e.port && !e.value.includes("://") && e.kind !== "email" && e.kind !== "telegram" && fuller.has(e.host)) continue;
      const n = (count.get(e.kind) ?? 0) + 1; if (n > (CAPS[e.kind] ?? max)) continue; count.set(e.kind, n);
      const {score: _, ...rest} = e; out.push(rest);
    }
    return out;
  }
}
function classify(r: Raw, smtp: boolean, linked: (m: string) => boolean): Scored[] {
  const out: Scored[] = [], strong = hidden(r.source), via = r.via || pickVia(r.callers, linked), context = r.context || strong || Boolean(r.callers?.some(linked));
  const push = (kind: EndpointKind, value: string, host: string, port?: number, brand?: Lookalike | null) => out.push({value: redactSecrets(value).slice(0, 160), host, ...port ? {port} : {}, kind, source: r.source, ...via ? {via} : {}, ...brand ? {brand} : {}, score: BASE[kind] * 2 - (kind === "ip" && port ? 2 : 0) - (brand?.severity === "high" ? 1 : 0) + (strong ? 0 : 1)});
  let rest = r.text;
  for (const m of r.text.matchAll(URL_RE)) {
    rest = rest.replace(m[0], " ");
    const p = m[0].replace(/[).,;:'"\]]+$/, "").match(URL_PARTS); if (!p) continue;
    const scheme = p[1].toLowerCase(), host = p[2].toLowerCase().replace(/\.$/, ""), port = p[3] && validPort(p[3]) ? Number(p[3]) : undefined, path = redactSecrets(p[4] || ""), value = `${scheme}://${host}${port ? `:${port}` : ""}${path.slice(0, 100)}${p[5] ? "?…" : ""}`;
    if (p[3] && !port) continue;
    if (ipv4(host)) {if (publicIpv4(host)) push("ip", value, host, port); continue;}
    // Dead drops sit on shared/benign platforms (GitHub, Google Docs/Drive, Telegram...), so they are matched before those
    // filters: raw/paste/export documents always, share pages only when hidden or loaded by network code, social links only hidden.
    const drop = deadDrop(m[0].replace(/[).,;:'"\]]+$/, ""));
    if (drop && (drop === "raw" || strong || drop === "linked" && Boolean(r.callers?.some(linked)))) {
      const query = p[5] && p[5].length <= 120 && /^\?[\w=&.%-]+$/.test(p[5]) && !/token|key|secret|sig|auth|pass|session/i.test(p[5]) ? p[5] : p[5] ? "?…" : "";
      push("deaddrop", `${scheme}://${host}${port ? `:${port}` : ""}${path.slice(0, 100)}${query}`, host, port); continue;
    }
    if (!plausible(host)) continue;
    // Bot API on api.telegram.org, or relayed through the attacker's own proxy (e.g. a workers.dev "/bot<token>/sendMessage").
    if (host === "api.telegram.org" || /^\/bot[^/]*\/(?:send\w+|getUpdates|getMe|setWebhook|getFile|forwardMessage)\b/i.test(path)) {push("telegram", value, host, port); continue;}
    if (/^(?:www\.|ptb\.|canary\.)?discord(?:app)?\.com$/.test(host) && /^\/api\/webhooks\//i.test(path) || host === "hooks.slack.com" && /^\/services\//i.test(path)) {push("webhook", value, host, port); continue;}
    if (under(host, BENIGN) || under(host, QUIET) || PLACEHOLDER.test(host)) continue;
    // Look-alike brand domains (official brand domains never match) are phishing pages, not neutral URLs or shared noise.
    const brand = impersonatedBrand(host, path);
    if (under(host, FIREBASE)) {push("firebase", value, host, port, brand); continue;}
    if (brand && /^(?:https?|wss?)$/.test(scheme)) {push("phishing", value, host, port, brand); continue;}
    const zone = zoneOf(host); if (zone) {if (customerHost(host)) push(zone as EndpointKind, value, host, port, brand); continue;}
    if (under(host, SHARED)) continue;
    if (IDENTIFIER.test(host) || IDENTIFIER_PATH.test(path)) continue;
    const kind: EndpointKind = PANEL.test(path) || /^(?:ftp|tcp|udp)$/.test(scheme) ? "panel" : "url";
    // Native libraries are full of documentation/spec links; only server-like kinds from them are worth listing.
    if (kind === "url" && r.source.startsWith("native:")) continue;
    push(kind, value, host, port);
  }
  if (rest.includes(":AA")) for (const m of rest.matchAll(TOKEN)) push("telegram", `bot ${m[1]}:…${m[2].slice(-4)}`, "api.telegram.org");
  for (const m of rest.matchAll(DDNS_HOST)) {
    const host = m[1].toLowerCase(), port = m[2] && validPort(m[2]) ? Number(m[2]) : undefined;
    if (customerHost(host) && (!m[2] || port)) push(zoneOf(host) as EndpointKind, `${host}${port ? `:${port}` : ""}`, host, port, impersonatedBrand(host));
  }
  for (const m of rest.matchAll(BARE_IP)) {
    const ip = m[1], port = m[2] && validPort(m[2]) ? Number(m[2]) : undefined;
    if (m[2] && !port || !publicIpv4(ip)) continue;
    if (!port) {
      // Without a port: needs context, and OID-like (1.x/2.x), mostly-zero (x.0.0.y) or version-labelled strings are dropped.
      const octets = ip.split(".").map(Number);
      if (!context || octets[0] <= 2 || octets.slice(1).filter(o => o === 0).length >= 2 || VERSION.test(rest)) continue;
    }
    push("ip", `${ip}${port ? `:${port}` : ""}`, ip, port);
  }
  if (/smtp\./i.test(rest)) for (const m of rest.matchAll(SMTP)) {const host = m[1].toLowerCase(), port = m[2] && validPort(m[2]) ? Number(m[2]) : undefined; if (DOMAIN.test(host)) push("email", `${host}${port ? `:${port}` : ""}`, host, port);}
  if (smtp && rest.includes("@")) for (const m of rest.matchAll(EMAIL)) {
    const host = m[1].toLowerCase(); if (!DOMAIN.test(host) || under(host, BENIGN) || under(host, QUIET) || PLACEHOLDER.test(host) || /\.(?:png|jpe?g|gif|webp|svg|xml|json)$/.test(host)) continue;
    push("email", m[0].toLowerCase(), host);
  }
  return out;
}
// Real-looking public hostname: not an internal/file-like name, not "www.<word>" or a glued string ("api.ipify.orgcookies").
const plausible = (host: string) => publicHost(host) && !/^www\.[^.]+$/.test(host) && /\.(?:[a-z]{2,7}|xn--[a-z0-9-]+|[a-z]{8,}(?<=online|website|digital|finance|services|network|systems|company|solutions|support|security|software|services|download|business|exchange))$/.test(host);
function pickVia(callers: string[] | undefined, linked: (m: string) => boolean) {
  if (!callers?.length) return undefined;
  const m = callers.find(linked) || callers[0]; return member(m).slice(0, 120);
}
// Hosts worth a reputation lookup (URLhaus/ThreatFox/RDAP), strongest first (look-alike brand domains, then servers, then
// plain URLs); shared platforms and big mail providers skipped.
export function endpointHosts(list: Endpoint[], max = 10) {
  const pick = (e: Endpoint) => e.kind !== "webhook" && !under(e.host, SHARED) && !(e.kind === "email" && under(e.host.replace(/^smtp\./, ""), MAIL));
  const rank = (e: Endpoint) => e.brand ? 0 : e.kind === "url" ? 2 : 1;
  return [...new Set(list.filter(pick).map((e, i) => ({e, i})).sort((a, b) => rank(a.e) - rank(b.e) || a.i - b.i).map(x => x.e.host))].slice(0, max);
}
// Callers whose class also uses network APIs (Signals.codeClasses "net").
export const netLinker = (classes: Set<string> | undefined) => (method: string) => Boolean(classes?.has(owner(method)));
export { sourceLabel };
