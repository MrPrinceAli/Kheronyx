import { createDecipheriv, createHash } from "node:crypto";
import { DDNS_HINT, DOMAIN, endpointOnly, publicIpv4, validPort } from "./hosts";
import { member } from "./behaviors";
import type { CryptoFacts } from "./dex";
// Static recovery of encrypted C2 configs: malware has to ship the key it decrypts with at runtime, so the key material
// next to javax.crypto/RC4/XOR code (const-strings, byte arrays, class constants, MD5/SHA of strings or the package name)
// is tried against ciphertext-shaped strings, bounded by attempt and time caps. Nothing is executed; a plaintext is only
// accepted when it is printable and clearly a config (endpoint, bot token, webhook, e-mail or host/port/url fields).
// recipe: how the key was formed ("raw", "md5hex16"...), so a recipe that worked is tried first for the next ciphertext.
export type Material = {bytes: Buffer; label: string; evp?: boolean; recipe?: string};
// pair: keys passed in the same call as this ciphertext (string-encryption helpers like decrypt(data, key)).
export type CipherText = {bytes: Buffer; origin: string; via?: string; local?: boolean; pair?: Material[]};
export type DecryptJob = {via: string; algorithms: string[]; keys: Material[]; ivs: Material[]; data: CipherText[]};
export type Decrypted = {algorithm: string; via: string; keySource: string; plaintext: string};
// opened: ciphertexts that decrypted to readable text which is not a config (proof the key was right, nothing reported).
export type DecryptResult = {found: Decrypted[]; attempts: number; timedOut: boolean; opened: number};
type Spec = {family: "aes" | "des" | "3des" | "rc4" | "xor"; mode: string; pad: boolean};
type Try = {spec: Spec; key: Material; iv: Buffer | null; ivLabel: string; data: CipherText; body: Buffer};
export const MAX_ATTEMPTS = 2000, BUDGET_MS = 300, MAX_FOUND = 20, MAX_JOBS = 12;
const TRANSFORM = /^(AES(?:_(?:128|192|256))?|DESede|TripleDES|3DES|DES|RC4|ARCFOUR|Blowfish)(?:\/([A-Z0-9-]+)\/([A-Z0-9]+))?$/i;
const NOT_KEY = /^(?:AES|DES|DESede|TripleDES|RC4|ARCFOUR|Blowfish|RSA|EC|HmacSHA\d+|PBKDF2\w*|MD5|SHA-?\d+|UTF-?8|UTF-16\w*|US-ASCII|ISO-8859-1|PKCS\d\w*|NoPadding|CBC|ECB|CTR|GCM|BC|AndroidOpenSSL|AndroidKeyStore)$|\//i;
// ---- plaintext acceptance ----
const URL_HOST = /\b(?:https?|wss?|tcp|udp|ftp|rtmp):\/\/(?:[^\s"'<>@/]*@)?([a-z0-9.-]+\.[a-z]{2,24}|(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?/gi;
const IP = /(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?(?![\w.])/g;
const TOKEN = /(?<!\d)\d{6,12}:AA[\w-]{30,40}/, HOOK = /discord(?:app)?\.com\/api\/webhooks\/\d|hooks\.slack\.com\/services\//i;
const EMAIL = /(?<![\w.%+-])[a-z0-9._%+-]{1,64}@((?:[a-z0-9-]+\.)+[a-z]{2,24})\b/i;
// Config fields with values of the right shape (host-like for host/url fields, a port number, a token-like secret).
const FIELD = /["']?\b(host(?:name)?|server|srv|domain|ip|addr(?:ess)?|c2|cnc|panel|gate|endpoint|url|uri|api|webhook|port|token|chat_?id|bot|key|secret)\b["']?\s*(?::|=(?!=))\s*["']?([^\s"',;}&]{2,200})/gi;
function fields(text: string) {
  if (/==|!=|\|\||&&|\breturn\b|\bnull\b.*\bnull\b/.test(text)) return 0; let n = 0;
  for (const [, k, v] of text.matchAll(FIELD)) {
    const key = k.toLowerCase();
    if (key === "port" ? /^\d{2,5}$/.test(v) && validPort(v) : /^(?:host|server|srv|domain|ip|addr|c2|cnc|panel|gate|endpoint|url|uri|api|webhook)/.test(key) ? /^(?:[a-z][\w+.-]*:\/\/)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d{1,5})?(?:\/|$)/i.test(v) : /^[\w:+/=.-]{6,}$/.test(v) && !/^(?:null|true|false|undefined|none)$/i.test(v)) n++;
  }
  return n;
}
// Printable UTF-8 (tabs/newlines allowed, almost all ASCII) after stripping block padding/NULs; null otherwise.
export function plaintextOf(buf: Buffer): string | null {
  let end = buf.length; const last = buf[end - 1];
  if (last >= 1 && last <= 16 && end >= last && buf.subarray(end - last, end).every(x => x === last)) end -= last;
  while (end > 0 && (buf[end - 1] === 0 || buf[end - 1] === 32 || buf[end - 1] === 10 || buf[end - 1] === 13)) end--;
  if (end < 6 || end > 8192) return null;
  let text: string; try {text = new TextDecoder("utf-8", {fatal: true}).decode(buf.subarray(0, end));} catch {return null;}
  let wide = 0;
  for (let i = 0; i < text.length; i++) {const c = text.charCodeAt(i); if (c < 0x20 && c !== 9 && c !== 10 && c !== 13 || c === 0x7f || c === 0xfffd || c >= 0x80 && c < 0xa0) return null; if (c > 0x7e) wide++;}
  return wide <= text.length * 0.1 && /[A-Za-z0-9]{2}/.test(text) ? text : null;
}
// Clearly a server/exfil config: endpoint, Telegram bot token, webhook, e-mail, or a JSON/key=value config with host/port/url... fields.
export function meaningfulConfig(text: string) {
  if (TOKEN.test(text) || HOOK.test(text) || DDNS_HINT.test(text) || endpointOnly(text.trim())) return true;
  for (const m of text.matchAll(URL_HOST)) {const h = m[1].toLowerCase(); if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(h) ? publicIpv4(h) : DOMAIN.test(h) && !/^(?:localhost|example\.(?:com|org|net))$/.test(h)) return true;}
  for (const m of text.matchAll(IP)) if (publicIpv4(m[1]) && (m[2] || Number(m[1].split(".")[0]) > 2)) return true;
  const mail = text.match(EMAIL); if (mail && DOMAIN.test(mail[1].toLowerCase())) return true;
  return fields(text) >= 2 && (/^\s*[{[]/.test(text) || /^["']?[\w.-]+["']?\s*(?::|=(?!=))/m.test(text));
}
// ---- key/IV/ciphertext material ----
const hex4 = (b: Buffer) => b.toString("hex").slice(0, 4);
// Never the full key: first 4 characters (or hex digits) and the length.
export const keyLabel = (kind: "string" | "bytes", v: string | Buffer) => kind === "string" ? `string "${String(v).slice(0, 4)}…" (${String(v).length})` : `bytes ${hex4(v as Buffer)}… (${(v as Buffer).length})`;
const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$|^[A-Za-z0-9_-]+$/;
// String-encryption tools tag their ciphertexts ("ScKit-<hex>", "enc:<base64>"): the tag is dropped before decoding.
const TAGGED = /^[A-Za-z][A-Za-z0-9]{1,15}[-:_|$#]([A-Za-z0-9+/=_-]{16,})$/;
// Hex or base64 (standard/URL-safe) to bytes; null for anything else.
export function decodeText(s: string, tagged = true): Buffer | null {
  const t = s.trim(); if (t.length < 8) return null;
  if (/^(?:[0-9a-fA-F]{2})+$/.test(t)) return Buffer.from(t, "hex");
  const m = tagged ? t.match(TAGGED) : null; if (m && /^(?:[0-9a-fA-F]{2})+$/.test(m[1])) return Buffer.from(m[1], "hex");
  if (t.length % 4 !== 1 && B64.test(t.replace(/\s+/g, ""))) {const b = Buffer.from(t.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/"), "base64"); return b.length ? b : null;}
  return m ? decodeText(m[1], false) : null;
}
const mostlyText = (b: Buffer) => {let n = 0; for (const c of b) if (c >= 0x20 && c < 0x7f || c === 10 || c === 13 || c === 9) n++; return n >= b.length * 0.85;};
// Encoded-looking: hex, or base64 with mixed case, digits/+/ and many distinct characters (identifiers such as
// "androidx_security_master_key" also fit the URL-safe alphabet but are not ciphertext).
const HEXS = /^(?:[0-9a-fA-F]{2})+$/;
export const encodedLike = (s: string) => {const t = s.match(TAGGED)?.[1] ?? s; return HEXS.test(t) || /[A-Z]/.test(t) && /[a-z]/.test(t) && /[0-9+/]/.test(t) && !/[a-z]{3,}[_.-][a-z]{3,}/i.test(t) && new Set(t).size >= Math.min(12, t.length / 2);};
// Ciphertext candidate: encoded (hex/base64) or raw binary-looking string; readable data is not ciphertext.
export function cipherText(s: string, origin: string, via?: string, local = false): CipherText | null {
  if (s.length < 8 || s.length > 12000) return null;
  // Prose and identifiers are not ciphertext (base64 decoding ignores spaces, so "called on unattached node" would decode).
  const d = /^[\w+/=:$|#-]+\s*$/.test(s) && encodedLike(s.trim()) || /^[A-Za-z0-9+/=\r\n]{64,}$/.test(s) ? decodeText(s) : null;
  if (d) return d.length >= 6 && !mostlyText(d) ? {bytes: d.subarray(0, 4096), origin, via, local} : null;
  if (s.length >= 8 && [...s].every(c => c.charCodeAt(0) < 256) && !mostlyText(Buffer.from(s, "latin1"))) return {bytes: Buffer.from(s, "latin1").subarray(0, 4096), origin, via, local};
  return null;
}
const digest = (alg: string, v: string | Buffer) => createHash(alg).update(v).digest();
const SIZES = new Set([8, 16, 24, 32]);
// Keys/IVs/passphrases from strings and byte arrays near the crypto code (+ MD5/SHA derivations when MessageDigest is used,
// and of the package name). Ordered: exact-size literals first, then derivations, then padded/truncated strings.
export function keyMaterial(strings: string[], arrays: number[][], opts: {digest?: boolean; pkg?: string} = {}) {
  const keys: Material[] = [], ivs: Material[] = [], later: Material[] = [], seen = new Set<string>();
  const add = (list: Material[], bytes: Buffer, label: string, recipe: string, evp?: boolean) => {const k = `${evp ? "e" : ""}${bytes.toString("hex")}`; if (!seen.has(k) && list.length < 120) {seen.add(k); list.push({bytes, label, recipe, ...evp ? {evp} : {}});}};
  // Log/error messages ("encrypt key is null") are not keys: strings with three or more words go last.
  const usable = strings.filter(s => s.length >= 4 && s.length <= 64 && !NOT_KEY.test(s) && !/\s{2}|^\W+$/.test(s)), words = (s: string) => (s.match(/[a-z]{2,} /gi) || []).length >= 2;
  const text = [...usable.filter(s => !words(s)), ...usable.filter(words)];
  for (const s of text) {
    const raw = Buffer.from(s, "utf8");
    if (SIZES.has(raw.length)) add(keys, raw, keyLabel("string", s), "raw");
    if (raw.length === 16 || raw.length === 8 || raw.length === 12) ivs.push({bytes: raw, label: keyLabel("string", s)});
    const d = s.length >= 12 ? decodeText(s) : null; if (d && SIZES.has(d.length)) {add(keys, d, keyLabel("string", s), "decoded"); if (d.length === 16) ivs.push({bytes: d, label: keyLabel("string", s)});}
  }
  for (const a of arrays) {const b = Buffer.from(a.map(v => v & 0xff)); if (SIZES.has(b.length)) add(keys, b, keyLabel("bytes", b), "bytes"); else if (b.length >= 2 && b.length <= 64) add(later, b, keyLabel("bytes", b), "bytes"); if (b.length === 16 || b.length === 8 || b.length === 12) ivs.push({bytes: b, label: keyLabel("bytes", b)});}
  // Raw digests, and the hex-string forms Java helpers produce (full MD5 hex = 32 chars, "MD5 16" = hex chars 8..24).
  const derive = (v: string, label: string) => {
    const md5 = digest("md5", v), hex = md5.toString("hex");
    add(keys, md5, `md5(${label})`, "md5"); add(keys, Buffer.from(hex.slice(8, 24)), `md5hex(${label})[8..24]`, "md5hex16"); add(keys, Buffer.from(hex), `md5hex(${label})`, "md5hex");
    add(keys, digest("sha256", v), `sha256(${label})`, "sha256"); add(keys, digest("sha256", v).subarray(0, 16), `sha256(${label})[0..16]`, "sha256-16"); add(keys, digest("sha1", v).subarray(0, 16), `sha1(${label})[0..16]`, "sha1-16");
    add(keys, Buffer.from(hex.slice(8, 24).toUpperCase()), `MD5HEX(${label})[8..24]`, "md5hex16u");
  };
  if (opts.digest) for (const s of text.slice(0, 24)) derive(s, keyLabel("string", s));
  if (opts.pkg) derive(opts.pkg, opts.pkg);
  // Stream ciphers/XOR take any length; block keys are often zero-padded or cut to 16/32 bytes; passphrases for "Salted__".
  for (const s of text.slice(0, 32)) {
    const raw = Buffer.from(s, "utf8");
    if (!SIZES.has(raw.length)) {add(later, raw, keyLabel("string", s), "raw"); for (const n of [16, 32]) add(later, Buffer.concat([raw, Buffer.alloc(n)]).subarray(0, n), `${keyLabel("string", s)} → ${n}`, `pad${n}`);}
    add(later, raw, keyLabel("string", s), "evp", true);
  }
  return {keys: [...keys, ...later], ivs: ivs.slice(0, 16)};
}
// ---- algorithms ----
export function specsOf(algorithms: string[]): Spec[] {
  const out: Spec[] = [], push = (s: Spec) => {if (!out.some(x => x.family === s.family && x.mode === s.mode && x.pad === s.pad)) out.push(s);};
  for (const a of algorithms) {
    if (a === "rc4" || a === "xor") {push({family: a, mode: "stream", pad: false}); continue;}
    const m = a.match(TRANSFORM); if (!m) continue;
    const name = m[1].toUpperCase(), mode = (m[2] || "ECB").toLowerCase(), pad = !m[3] || !/^NoPadding$/i.test(m[3]);
    if (name === "RC4" || name === "ARCFOUR") {push({family: "rc4", mode: "stream", pad: false}); continue;}
    if (name === "BLOWFISH" || !/^(?:ecb|cbc|ctr|gcm|cfb|ofb)$/.test(mode)) continue;
    const family = name.startsWith("AES") ? "aes" : name === "DES" ? "des" : "3des";
    if (family !== "aes" && (mode === "gcm" || mode === "ctr")) continue;
    push({family, mode, pad: mode === "ecb" || mode === "cbc" ? pad : false});
    // A bare "AES" key spec usually pairs with a transformation elsewhere: CBC is the common alternative to the default.
    if (!m[2]) push({family, mode: "cbc", pad: true});
  }
  return out.slice(0, 8);
}
const label = (s: Spec) => s.family === "rc4" || s.family === "xor" ? s.family : `${s.family}-${s.mode}`;
function rc4(key: Buffer, data: Buffer) {
  const S = new Uint8Array(256); for (let i = 0; i < 256; i++) S[i] = i;
  for (let i = 0, j = 0; i < 256; i++) {j = j + S[i] + key[i % key.length] & 255; const t = S[i]; S[i] = S[j]; S[j] = t;}
  const out = Buffer.alloc(data.length);
  for (let n = 0, i = 0, j = 0; n < data.length; n++) {i = i + 1 & 255; j = j + S[i] & 255; const t = S[i]; S[i] = S[j]; S[j] = t; out[n] = data[n] ^ S[S[i] + S[j] & 255];}
  return out;
}
function run(t: Try): Buffer | null {
  const {spec, iv, body} = t, key = t.key.bytes;
  if (spec.family === "rc4") return rc4(key, body);
  if (spec.family === "xor") return Buffer.from(body.map((c, i) => c ^ key[i % key.length]));
  // Single DES runs as 3DES with K1=K2=K3 (OpenSSL 3 keeps plain DES in the legacy provider); 2-key 3DES as K1K2K1.
  const k = spec.family === "des" ? Buffer.concat([key, key, key]) : spec.family === "3des" && key.length === 16 ? Buffer.concat([key, key.subarray(0, 8)]) : key;
  const name = spec.family === "aes" ? `aes-${key.length * 8}-${spec.mode}` : spec.mode === "ecb" ? "des-ede3" : "des-ede3-cbc";
  try {
    const d = createDecipheriv(name, k, spec.mode === "ecb" ? null : iv);
    if (spec.mode === "gcm") return body.length > 16 ? d.update(body.subarray(0, body.length - 16)) : null;  // tag not checked
    d.setAutoPadding(spec.pad); return Buffer.concat([d.update(body), d.final()]);
  } catch {return null;}
}
const ZERO16 = Buffer.alloc(16);
// How many characters of a (first) block look like config text.
const clean = (s: string) => (s.match(/[\w{}\[\]":/.,=&?@ +-]/g) || []).length;
// Every (spec, IV, body) to try for one key and ciphertext; incompatible sizes yield nothing (no attempt is spent).
function* variants(specs: Spec[], key: Material, ivs: Material[], data: CipherText): Generator<Try> {
  const salted = data.bytes.length > 16 && data.bytes.toString("latin1", 0, 8) === "Salted__";
  if (key.evp) {
    // OpenSSL/CryptoJS passphrase format: EVP_BytesToKey(MD5) -> AES-256-CBC key + IV.
    if (!salted) return; const salt = data.bytes.subarray(8, 16); let d = Buffer.alloc(0), prev = Buffer.alloc(0);
    while (d.length < 48) {prev = digest("md5", Buffer.concat([prev, key.bytes, salt])); d = Buffer.concat([d, prev]);}
    yield {spec: {family: "aes", mode: "cbc", pad: true}, key: {bytes: d.subarray(0, 32), label: `evp(${key.label})`}, iv: d.subarray(32, 48), ivLabel: "evp", data, body: data.bytes.subarray(16)};
    return;
  }
  for (const spec of specs) {
    const n = key.bytes.length, block = spec.family === "aes" ? 16 : 8;
    if (spec.family === "aes" && n !== 16 && n !== 24 && n !== 32 || spec.family === "des" && n !== 8 || spec.family === "3des" && n !== 16 && n !== 24 || spec.family === "rc4" && n < 4 || spec.family === "xor" && n < 2) continue;
    if (spec.family === "rc4" || spec.family === "xor") {yield {spec, key, iv: null, ivLabel: "", data, body: data.bytes}; continue;}
    const aligned = (b: Buffer) => b.length >= block && (!spec.pad && spec.mode !== "ecb" && spec.mode !== "cbc" || b.length % block === 0);
    if (spec.mode === "ecb") {if (aligned(data.bytes)) yield {spec, key, iv: null, ivLabel: "", data, body: data.bytes}; continue;}
    const size = spec.mode === "gcm" ? 12 : block, seen = new Set<string>();
    const options: [Buffer, string, Buffer][] = [...ivs.filter(v => v.bytes.length === size).map(v => [v.bytes, v.label, data.bytes] as [Buffer, string, Buffer]), [key.bytes.subarray(0, size), "kunci", data.bytes], [ZERO16.subarray(0, size), "nol", data.bytes], [data.bytes.subarray(0, size), "awal data", data.bytes.subarray(size)]];
    for (const [iv, ivLabel, body] of options) {
      if (iv.length !== size || !aligned(body) || seen.has(`${iv.toString("hex")}:${body.length}`)) continue; seen.add(`${iv.toString("hex")}:${body.length}`);
      yield {spec, key, iv, ivLabel, data, body};
    }
  }
}
type Prefer = {recipe?: string; spec?: string};
const specKey = (s: Spec) => `${s.family}-${s.mode}-${s.pad}`;
// Keys passed with the ciphertext first (the recipe/mode that already worked leads), then a diagonal walk over
// (ciphertext, key) priorities so local material is paired first; done ciphertexts are skipped.
function* attempts(job: DecryptJob, done: Set<CipherText>, prefer: Prefer): Generator<Try> {
  const specs = specsOf(job.algorithms), D = job.data, K = job.keys; if (!specs.length && !K.some(k => k.evp)) return;
  for (const d of D) {
    if (!d.pair?.length || done.has(d)) continue;
    const keys = [...d.pair.filter(k => k.recipe === prefer.recipe), ...d.pair.filter(k => k.recipe !== prefer.recipe)], sp = [...specs.filter(x => specKey(x) === prefer.spec), ...specs.filter(x => specKey(x) !== prefer.spec)];
    for (const k of keys) {if (done.has(d)) break; for (const t of variants(sp, k, job.ivs, d)) {if (done.has(d)) break; yield t;}}
  }
  for (let sum = 0; sum < D.length + K.length - 1; sum++) for (let di = Math.max(0, sum - K.length + 1); di <= Math.min(sum, D.length - 1); di++) {
    if (done.has(D[di])) continue;
    for (const t of variants(specs, K[sum - di], job.ivs, D[di])) {if (done.has(D[di])) break; yield t;}
  }
}
// Round-robin over jobs (one per crypto class) under the attempt/time caps. A working key+mode is replayed on every other
// ciphertext right away (configs are usually all encrypted the same way).
export function decryptConfigs(jobs: DecryptJob[], o: {maxAttempts?: number; budgetMs?: number; max?: number} = {}): DecryptResult {
  const maxAttempts = o.maxAttempts ?? MAX_ATTEMPTS, deadline = Date.now() + (o.budgetMs ?? BUDGET_MS), max = o.max ?? MAX_FOUND;
  const found: Decrypted[] = [], done = new Set<CipherText>(), texts = new Set<string>(), prefer: Prefer = {}; let n = 0, opened = 0, timedOut = false;
  const accept = (t: Try, job: DecryptJob) => {
    n++; const out = run(t); let text = out && plaintextOf(out); if (!text) return false;
    if (!meaningfulConfig(text)) {
      // Valid PKCS#5 padding plus readable text is the right key (an ordinary string, e.g. from a string-encryption tool):
      // learn the recipe for the next ciphertexts, report nothing.
      if (t.spec.pad && t.ivLabel !== "awal data" && (t.spec.mode === "ecb" || t.spec.mode === "cbc")) {done.add(t.data); opened++; prefer.recipe = t.key.recipe; prefer.spec = specKey(t.spec);}
      return false;
    }
    let keySource = t.key.label;
    // CBC with a wrong IV only garbles the first block: keep the IV whose first block reads cleanest, else drop that block.
    if (t.spec.mode === "cbc" && t.ivLabel !== "evp") {
      const block = t.spec.family === "aes" ? 16 : 8; let best = clean(text.slice(0, block));
      for (const v of variants([t.spec], t.key, job.ivs, t.data)) {
        if (best === block || n >= maxAttempts) break; if (v.ivLabel === t.ivLabel && v.body.length === t.body.length) continue;
        n++; const o = run(v), x = o && plaintextOf(o); if (!x || !meaningfulConfig(x)) continue;
        const sc = clean(x.slice(0, block)); if (sc > best) {best = sc; text = x; t = v;}
      }
      if (best < block * 0.75) {text = text.slice(block).replace(/^[^\w{["]+/, ""); keySource += ", IV tidak diketahui (blok pertama dibuang)";}
    }
    done.add(t.data); prefer.recipe = t.key.recipe; prefer.spec = specKey(t.spec); if (text.length >= 6 && !texts.has(text) && found.length < max) {texts.add(text); found.push({algorithm: label(t.spec), via: t.data.via || job.via, keySource, plaintext: text.slice(0, 2000)});}
    return true;
  };
  const gens = jobs.slice(0, MAX_JOBS).map(j => ({job: j, it: attempts(j, done, prefer)}));
  while (gens.length && n < maxAttempts && found.length < max) {
    for (let i = 0; i < gens.length && n < maxAttempts; i++) {
      if ((n & 15) === 0 && Date.now() > deadline) {timedOut = true; return {found, attempts: n, timedOut, opened};}
      const g = gens[i], r = g.it.next(); if (r.done) {gens.splice(i--, 1); continue;}
      if (!accept(r.value, g.job)) continue;
      const win = r.value; if (win.key.label.startsWith("evp(") || win.data.pair?.length) continue;
      for (const j of jobs.slice(0, MAX_JOBS)) for (const d of j.data) {
        if (done.has(d) || n >= maxAttempts) continue;
        const size = win.iv?.length ?? 0, prefix = win.ivLabel === "awal data";
        if (prefix && d.bytes.length <= size) continue;
        accept({...win, data: d, iv: prefix ? d.bytes.subarray(0, size) : win.iv, body: prefix ? d.bytes.subarray(size) : d.bytes}, j);
      }
    }
  }
  return {found, attempts: n, timedOut: timedOut || Date.now() > deadline, opened};
}
// ---- jobs from decoded bytecode ----
const SALTED = /^U2FsdGVkX1/;
// SDK crypto helpers (cloud storage, analytics, vendor security kits) that are not on the global library list: they keep
// their jobs, ranked after the app's own crypto classes.
const SDK_CRYPTO = /^L(?:com\/(?:huawei|amazonaws|flurry|tencent|alibaba|baidu|xiaomi|vivo|oppo|heytap|meizu|igexin|getui|umeng|sina|bytedance|pangle|kwai|unity3d|ironsource|chartboost|vungle|appodeal|yandex|vk|mopub|smaato|inmobi|startapp|my)\/|cz\/msebera\/|org\/spongycastle\/|io\/jsonwebtoken\/|net\/lingala\/)/;
// One job per app crypto class (most local material first): transformations, keys from the crypto methods, strings
// handed to the class at call sites, class constants; ciphertexts local first, then app-wide candidates and asset files.
export function cryptoJobs(facts: CryptoFacts[], o: {pkg?: string; assets?: {name: string; bytes: Buffer}[]} = {}) {
  const classes = facts.flatMap(f => f.classes), passed = facts.flatMap(f => f.passed), pool = facts.flatMap(f => f.pool);
  const jobs: (DecryptJob & {score: number})[] = [];
  for (const c of classes.slice(0, 400)) {
    const into = passed.filter(p => p.to.startsWith(c.name)).slice(0, 400), via = member(c.methods[0] || `${c.name}->?`), digests = c.apis.includes("MessageDigest");
    // Arguments of the same call: the other strings are that ciphertext's key candidates.
    const coArgs = (i: number) => into.filter((q, j) => j !== i && q.call === into[i].call && q.from === into[i].from).map(q => q.value).slice(0, 4);
    const algorithms = [...new Set([...c.strings.filter(s => TRANSFORM.test(s)), ...c.loops])];
    if (c.apis.includes("Cipher") && !algorithms.some(a => TRANSFORM.test(a) && !/^(?:RC4|ARCFOUR)$/i.test(a))) algorithms.push("AES", "AES/CBC/PKCS5Padding");
    const data: CipherText[] = [], seen = new Set<string>();
    const put = (s: string, origin: string, v?: string, local = false, pair?: string[]) => {
      if (data.length >= 160 || seen.has(s)) return; const ct = cipherText(s, origin, v, local); if (!ct) return; seen.add(s);
      if (pair?.length) ct.pair = keyMaterial(pair, [], {digest: digests}).keys.filter(k => !k.evp).slice(0, 24); data.push(ct);
    };
    for (const s of c.site) put(s, "metode kripto", undefined, true);
    into.forEach((p, i) => put(p.value, "argumen pemanggil", member(p.to), true, coArgs(i)));
    for (const s of c.strings) put(s, "konstanta kelas", undefined, true);
    // Hand-rolled XOR/RC4 classes usually keep both the encrypted bytes and the key as byte arrays.
    if (c.loops.length) for (const a of c.arrays) if (a.length >= 6 && !SIZES.has(a.length) && data.length < 160) {const b = Buffer.from(a); if (!mostlyText(b)) data.push({bytes: b, origin: "array byte", local: true});}
    const pkg = c.name.slice(0, c.name.lastIndexOf("/") + 1);
    for (const p of [...pool.filter(x => x.where.startsWith(pkg)), ...pool.filter(x => !x.where.startsWith(pkg) || SALTED.test(x.value))].slice(0, 40)) put(p.value, "string aplikasi", undefined);
    for (const a of (o.assets || []).slice(0, 8)) if (data.length < 64 && !seen.has(a.name)) {seen.add(a.name); const t = a.bytes.toString("latin1"), d = /^[\x20-\x7e\s]+$/.test(t) ? decodeText(t) : a.bytes; if (d && d.length >= 8 && !mostlyText(d)) data.push({bytes: d.subarray(0, 4096), origin: `aset ${a.name}`});}
    if (!data.length) continue;
    const {keys, ivs} = keyMaterial([...c.site, ...into.slice(0, 80).map(p => p.value), ...c.strings], c.arrays, {digest: digests, pkg: o.pkg});
    if (!keys.length && !data.some(d => d.pair?.length)) continue;
    // Real javax.crypto users before hand-rolled loop heuristics; local ciphertexts and per-call keys raise the rank.
    jobs.push({via, algorithms, keys, ivs, data, score: Math.min(data.filter(d => d.local).length, 10) * 4 + Math.min(data.filter(d => d.pair?.length).length, 10) * 2 + Math.min(keys.length, 8) + (c.apis.includes("Cipher") || c.apis.includes("SecretKeySpec") ? 12 : c.loops.length ? 2 : 0) - (SDK_CRYPTO.test(c.name) ? 40 : 0)});
  }
  return jobs.sort((a, b) => b.score - a.score).slice(0, MAX_JOBS).map(({score: _, ...j}) => j);
}
