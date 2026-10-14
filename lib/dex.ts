import { recoverable } from "./deobfuscate";
// Bounded DEX reader (header, string_ids, type_ids, field_ids, method_ids, class_defs) plus an optional linear
// Dalvik instruction walk (class_data_item -> encoded_method -> code_item) that records who calls sensitive APIs and
// recovers simply-obfuscated strings. Bytecode is decoded, never executed; every offset/count is checked first.
export type DexClass = {name: string; superclass: string};
export type CallSite = {ref: string; app: string[]; lib: string[]};
export type Recovered = {value: string; technique: string; where: string; lib: boolean};
export type DexCode = {complete: boolean; reason?: string; methods: number; units: number; sites: CallSite[]; strings: CallSite[]; recovered: Recovered[]};
export type CodeOptions = {deadline: number; ref: (ref: string) => boolean; string: (s: string) => boolean; library?: (cls: string) => boolean};
export type Dex = {version: string; strings: string[]; types: string[]; methods: string[]; fields: string[]; classes: DexClass[]; code?: DexCode};
const NO_INDEX = 0xffffffff, MAX_STRING = 4096, MAX_IDS = 65536, MAX_STRINGS = 1_000_000;
const fail = (message: string): never => {throw new Error(message);};
const clip = (s: string) => s.length > 200 ? s.slice(0, 200) : s;
export function parseDex(b: Buffer, deadline = Infinity, opts?: {code?: CodeOptions}): Dex {
  if (b.length < 0x70 || b.toString("latin1", 0, 4) !== "dex\n" || b[7] !== 0) fail("Header DEX tidak valid.");
  const version = b.toString("latin1", 4, 7); if (!/^0[3-4]\d$/.test(version)) fail("Versi DEX tidak dikenal.");
  if (b.readUInt32LE(0x28) !== 0x12345678) fail("Urutan byte DEX tidak didukung.");
  const header = b.readUInt32LE(0x24); if (header < 0x70 || header > b.length) fail("Ukuran header DEX tidak valid.");
  if (b.readUInt32LE(0x20) > b.length) fail("File DEX terpotong.");
  const table = (at: number, item: number, max: number) => {
    const n = b.readUInt32LE(at), off = b.readUInt32LE(at + 4);
    if (n > max || n && (off < header || off + n * item > b.length)) fail("Tabel DEX di luar batas atau terlalu besar.");
    return [n, off];
  };
  const [ns, os] = table(0x38, 4, MAX_STRINGS), [nt, ot] = table(0x40, 4, MAX_IDS), [nf, of] = table(0x50, 8, MAX_IDS), [nm, om] = table(0x58, 8, MAX_IDS), [nc, oc] = table(0x60, 32, MAX_IDS);
  const tick = (i: number) => {if ((i & 0xffff) === 0 && Date.now() > deadline) fail("Batas waktu pembacaan DEX tercapai.");};
  // Overlapping string offsets could otherwise multiply decoding work; distinct legit strings never exceed the file size.
  let budget = b.length + 65536; const strings = new Array<string>(ns);
  for (let i = 0; i < ns; i++) {
    tick(i); let p = b.readUInt32LE(os + i * 4), units = 0;
    for (let s = 0; ; s += 7) {if (s > 28 || p >= b.length) fail("Panjang string DEX rusak."); const x = b[p++]; units += (x & 0x7f) * 2 ** s; if (!(x & 0x80)) break;}
    const n = Math.min(units, MAX_STRING); if ((budget -= n) < 0) fail("Tabel string DEX tidak wajar.");
    strings[i] = mutf8(b, p, n);
  }
  const str = (i: number) => i < ns ? strings[i] : fail("Indeks string DEX tidak valid.");
  const types = Array.from({length: nt}, (_, i) => str(b.readUInt32LE(ot + i * 4)));
  const type = (i: number) => i < nt ? types[i] : fail("Indeks tipe DEX tidak valid.");
  const refs = (n: number, o: number) => Array.from({length: n}, (_, i) => {tick(i); const q = o + i * 8; return `${clip(type(b.readUInt16LE(q)))}->${clip(str(b.readUInt32LE(q + 4)))}`;});
  const fields = refs(nf, of), methods = refs(nm, om);
  const classes = Array.from({length: nc}, (_, i) => {const q = oc + i * 32, s = b.readUInt32LE(q + 8); return {name: type(b.readUInt32LE(q)), superclass: s === NO_INDEX ? "" : type(s)};});
  const dex: Dex = {version, strings, types, methods, fields, classes};
  if (opts?.code) dex.code = decodeCode(b, header, dex, oc, opts.code);
  return dex;
}
// MUTF-8 (DEX string_data_item): decodes at most n UTF-16 units; stray bytes become U+FFFD instead of throwing.
function mutf8(b: Buffer, p: number, n: number) {
  const end = Math.min(b.length, p + n); let ascii = end - p === n;
  for (let i = p; ascii && i < end; i++) if (b[i] === 0 || b[i] > 0x7f) ascii = false;
  if (ascii) return b.toString("latin1", p, end);
  const out = new Uint16Array(n); let k = 0;
  while (k < n && p < b.length) {
    const c = b[p++]; if (c === 0) break;
    if (c < 0x80) out[k++] = c;
    else if ((c & 0xe0) === 0xc0 && p < b.length) out[k++] = (c & 0x1f) << 6 | b[p++] & 0x3f;
    else if ((c & 0xf0) === 0xe0 && p + 1 < b.length) {out[k++] = (c & 0x0f) << 12 | (b[p] & 0x3f) << 6 | b[p + 1] & 0x3f; p += 2;}
    else out[k++] = 0xfffd;
  }
  return String.fromCharCode(...out.subarray(0, k));
}
// Third-party namespaces whose calls to sensitive APIs are weaker evidence than the app's own code (heuristic list).
const LIBRARY = new RegExp(`^L(?:${[
  "androidx/", "android/support/", "kotlin/", "kotlinx/", "okhttp3/", "okio/", "retrofit2/", "dagger/", "javax/", "java/", "sun/", "dalvik/", "libcore/", "bolts/", "butterknife/", "timber/",
  "com/google/(?:android/(?:gms|material|exoplayer2|play|datatransport|libraries|ads|odml|recaptcha|youtube/player)|firebase|gson|common|protobuf|zxing|crypto/tink|errorprone|auto|mlkit|ads|j2objc|thirdparty|maps)/",
  "org/(?:apache|json|jetbrains|intellij|chromium|bouncycastle|conscrypt|greenrobot|reactivestreams|slf4j|xmlpull|w3c|kxml2|java_websocket|jsoup|joda|threeten)/",
  "io/(?:reactivex|flutter|sentry|grpc|realm|branch|fabric|perfmark|ktor|invertase|github/inflationx)/",
  "com/(?:facebook|squareup|bumptech|airbnb|fasterxml|crashlytics|unity3d|applovin|ironsource|mopub|inmobi|vungle|chartboost|adcolony|bytedance/sdk|pgl|startapp|appsflyer|adjust|onesignal|huawei/hms|amazon|microsoft|jakewharton|umeng|alibaba|alipay|xiaomi/push|mbridge|my/target|yandex|smaato|fyber|tapjoy|kochava|mixpanel|amplitude|segment|clevertap|moengage|braze|appboy|zendesk|stripe|paypal|midtrans|xendit|journeyapps|scottyab|orhanobut|blankj|loopj|koushikdutta|nimbusds|auth0|nostra13|afollestad|android/volley|android/installreferrer|android/billingclient|tencent/(?:bugly|mm/opensdk|smtt)|reactnativecommunity|swmansion|th3rdwave|horcrux|oblador|dylanvann)/",
  "cn/(?:jpush|jiguang)/", "net/(?:sqlcipher|zetetic)/",
].join("|")})`);
export const libraryClass = (descriptor: string) => LIBRARY.test(descriptor);
// Code units per opcode from the Dalvik instruction-format table (0 = unused/invalid), and which register an op
// overwrites (1 vAA, 2 vA nibble, 3 vAAAA, 4/5/6 the same for wide pairs) so stale tracked constants are dropped.
const WIDTH = new Uint8Array(256), DEST = new Uint8Array(256);
const op = (from: number, to: number, w: number, d = 0) => {for (let i = from; i <= to; i++) {WIDTH[i] = w; DEST[i] = d;}};
op(0x00, 0x00, 1); op(0x01, 0x01, 1, 2); op(0x02, 0x02, 2, 1); op(0x03, 0x03, 3, 3); op(0x04, 0x04, 1, 5); op(0x05, 0x05, 2, 4); op(0x06, 0x06, 3, 6);
op(0x07, 0x07, 1, 2); op(0x08, 0x08, 2, 1); op(0x09, 0x09, 3, 3); op(0x0a, 0x0a, 1, 1); op(0x0b, 0x0b, 1, 4); op(0x0c, 0x0d, 1, 1); op(0x0e, 0x11, 1);
op(0x12, 0x12, 1, 2); op(0x13, 0x13, 2, 1); op(0x14, 0x14, 3, 1); op(0x15, 0x15, 2, 1); op(0x16, 0x16, 2, 4); op(0x17, 0x17, 3, 4); op(0x18, 0x18, 5, 4); op(0x19, 0x19, 2, 4);
op(0x1a, 0x1a, 2, 1); op(0x1b, 0x1b, 3, 1); op(0x1c, 0x1c, 2, 1); op(0x1d, 0x1e, 1); op(0x1f, 0x1f, 2); op(0x20, 0x20, 2, 2); op(0x21, 0x21, 1, 2); op(0x22, 0x22, 2, 1); op(0x23, 0x23, 2, 2);
op(0x24, 0x26, 3); op(0x27, 0x28, 1); op(0x29, 0x29, 2); op(0x2a, 0x2c, 3); op(0x2d, 0x31, 2, 1); op(0x32, 0x3d, 2); op(0x3e, 0x43, 0);
op(0x44, 0x4a, 2, 1); op(0x45, 0x45, 2, 4); op(0x4b, 0x51, 2); op(0x52, 0x58, 2, 2); op(0x53, 0x53, 2, 5); op(0x59, 0x5f, 2); op(0x60, 0x66, 2, 1); op(0x61, 0x61, 2, 4); op(0x67, 0x6d, 2);
op(0x6e, 0x72, 3); op(0x73, 0x73, 0); op(0x74, 0x78, 3); op(0x79, 0x7a, 0); op(0x7b, 0x8f, 1, 2); for (const x of [0x7d, 0x7e, 0x80, 0x81, 0x83, 0x86, 0x88, 0x89, 0x8b]) DEST[x] = 5;
op(0x90, 0x9a, 2, 1); op(0x9b, 0xa5, 2, 4); op(0xa6, 0xaa, 2, 1); op(0xab, 0xaf, 2, 4); op(0xb0, 0xba, 1, 2); op(0xbb, 0xc5, 1, 5); op(0xc6, 0xca, 1, 2); op(0xcb, 0xcf, 1, 5);
op(0xd0, 0xd7, 2, 2); op(0xd8, 0xe2, 2, 1); op(0xe3, 0xf9, 0); op(0xfa, 0xfb, 4); op(0xfc, 0xfd, 3); op(0xfe, 0xff, 2, 1);
// Special methods understood by the string-recovery emulation.
const SPECIAL: Record<string, number> = {"Ljava/lang/String;-><init>": 1, "Ljava/lang/String;->valueOf": 2, "Ljava/lang/String;->copyValueOf": 2, "Ljava/lang/StringBuilder;-><init>": 3, "Ljava/lang/StringBuilder;->append": 4, "Ljava/lang/StringBuilder;->toString": 5, "Ljava/lang/StringBuffer;-><init>": 3, "Ljava/lang/StringBuffer;->append": 4, "Ljava/lang/StringBuffer;->toString": 5};
type Arr = {a: number[]; w: number; src: string; done?: boolean};
type Val = {s: string} | {n: number} | Arr | {sb: string[]; ok: boolean};
const MAX_SITES = 4000, MAX_RECOVERED = 1500, MAX_ARRAY = 4096;
// Linear walk over every code_item (no control flow): invoke-* (35c/3rc), sget/sput, const-string(/jumbo), plus tiny
// constant tracking for new-array/fill-array-data/aput, new String(...), StringBuilder chains and xor keys. Bounded by
// the deadline, a code-unit budget proportional to the file size, and caps on recorded sites/strings.
function decodeCode(b: Buffer, header: number, dex: Dex, oc: number, o: CodeOptions): DexCode {
  const {strings, types, methods, fields, classes} = dex, nm = methods.length, nf = fields.length;
  const out: DexCode = {complete: true, methods: 0, units: 0, sites: [], strings: [], recovered: []};
  const tracked = new Uint8Array(nm), special = new Uint8Array(nm), fieldTracked = new Uint8Array(nf), strState = new Uint8Array(strings.length);
  for (let i = 0; i < nm; i++) {if (o.ref(methods[i])) tracked[i] = 1; special[i] = SPECIAL[methods[i]] || 0;}
  for (let i = 0; i < nf; i++) if (o.ref(fields[i])) fieldTracked[i] = 1;
  const isLib = o.library || libraryClass;
  const sites = new Map<string, {app: Set<number>; lib: Set<number>}>(), strSites = new Map<number, {app: Set<number>; lib: Set<number>}>(), seen = new Set<string>();
  const site = <K>(m: Map<K, {app: Set<number>; lib: Set<number>}>, k: K, caller: number, lib: boolean) => {
    let s = m.get(k); if (!s) {if (m.size >= MAX_SITES) return; m.set(k, s = {app: new Set(), lib: new Set()});}
    const set = lib ? s.lib : s.app; if (set.size < (lib ? 4 : 48)) set.add(caller);
  };
  const recover = (value: string, technique: string, caller: number, lib: boolean) => {
    if (out.recovered.length >= MAX_RECOVERED || !recoverable(value) || seen.has(value)) return; seen.add(value);
    out.recovered.push({value: value.slice(0, 1000), technique, where: methods[caller], lib});
  };
  const vals: (Val | undefined)[] = new Array(65536 + 260), gens = new Uint32Array(65536 + 260); let g = 0;
  const get = (r: number) => gens[r] === g ? vals[r] : undefined, set = (r: number, v: Val | undefined) => {gens[r] = v ? g : 0; vals[r] = v;};
  const num = (r: number) => {const v = get(r); return v && "n" in v ? v.n : undefined;};
  const arrText = (x: Arr, key = 0) => x.w === 1 ? Buffer.from(x.a.map(c => (c ^ key) & 0xff)).toString("latin1") : String.fromCharCode(...x.a.map(c => c & 0xffff));
  let unitBudget = b.length + 65536, itemBudget = b.length + 65536, stop = "";
  const uleb = (st: {p: number}) => {let r = 0; for (let s = 0; ; s += 7) {if (s > 28 || st.p >= b.length) fail("uleb128 rusak."); const x = b[st.p++]; r += (x & 0x7f) * 2 ** s; if (!(x & 0x80)) return r;}};
  const method = (caller: number, off: number, lib: boolean) => {
    if (off & 3 || off < header || off + 16 > b.length) {out.complete = false; return;}
    const n = b.readUInt32LE(off + 12), base = off + 16;
    if (n > 1 << 20 || base + n * 2 > b.length) {out.complete = false; return;}
    if ((unitBudget -= n) < 0) {stop = "batas instruksi"; return;}
    out.methods++; out.units += n; g = g + 1 >>> 0 || 1;
    let pending: Val | undefined; const keys: number[] = [], arrays: Arr[] = [];
    for (let pc = 0; pc < n;) {
      const p = base + pc * 2, x = b[p], a = b[p + 1]; let w = WIDTH[x];
      if (x === 0 && a) {
        // Payload pseudo-instructions sit in the instruction stream (normally after the code) and are skipped by size.
        if (pc + (a === 3 ? 4 : 2) > n) {out.complete = false; return;}
        w = a === 1 ? b.readUInt16LE(p + 2) * 2 + 4 : a === 2 ? b.readUInt16LE(p + 2) * 4 + 2 : a === 3 ? Math.ceil(b.readUInt16LE(p + 2) * b.readUInt32LE(p + 4) / 2) + 4 : 0;
      }
      if (!w || pc + w > n) {out.complete = false; return;}
      switch (x) {
        case 0x12: set(a & 15, {n: a << 24 >> 28}); break;
        case 0x13: set(a, {n: b.readInt16LE(p + 2)}); break;
        case 0x14: set(a, {n: b.readInt32LE(p + 2)}); break;
        case 0x15: set(a, {n: b.readInt16LE(p + 2) * 65536}); break;
        case 0x1a: case 0x1b: {
          const i = x === 0x1a ? b.readUInt16LE(p + 2) : b.readUInt32LE(p + 2); if (i >= strings.length) {set(a, undefined); break;}
          if (!strState[i]) strState[i] = o.string(strings[i]) ? 1 : 2;
          if (strState[i] === 1) site(strSites, i, caller, lib);
          set(a, {s: strings[i]}); break;
        }
        case 0x22: {const t = types[b.readUInt16LE(p + 2)]; set(a, t === "Ljava/lang/StringBuilder;" || t === "Ljava/lang/StringBuffer;" ? {sb: [], ok: true} : undefined); break;}
        case 0x23: {
          const t = types[b.readUInt16LE(p + 2)], size = num(a >> 4);
          if ((t === "[B" || t === "[C") && size !== undefined && size > 0 && size <= MAX_ARRAY && arrays.length < 32) {const arr: Arr = {a: new Array(size).fill(0), w: t === "[B" ? 1 : 2, src: "aput"}; arrays.push(arr); set(a & 15, arr);}
          else set(a & 15, undefined);
          break;
        }
        case 0x26: {
          const t = pc + b.readInt32LE(p + 2), q = base + t * 2;
          if (t >= 0 && t + 4 <= n && b.readUInt16LE(q) === 0x0300 && arrays.length < 32) {
            const ew = b.readUInt16LE(q + 2), size = b.readUInt32LE(q + 4);
            if ((ew === 1 || ew === 2) && size > 0 && size <= MAX_ARRAY && t + 4 + Math.ceil(size * ew / 2) <= n) {
              const arr: Arr = {a: Array.from({length: size}, (_, k) => ew === 1 ? b[q + 8 + k] : b.readUInt16LE(q + 8 + k * 2)), w: ew, src: "fill-array-data"}; arrays.push(arr); set(a, arr); break;
            }
          }
          break;
        }
        case 0x4b: case 0x4f: case 0x50: case 0x51: {
          const arr = get(b[p + 2]), i = num(b[p + 3]), v = num(a);
          if (arr && "a" in arr && i !== undefined && v !== undefined && i >= 0 && i < arr.a.length) arr.a[i] = v;
          break;
        }
        case 0x07: set(a & 15, get(a >> 4)); break;
        case 0x08: set(a, get(b.readUInt16LE(p + 2))); break;
        case 0x0c: set(a, pending); pending = undefined; break;
        case 0xdf: if (keys.length < 8) keys.push(b[p + 3]); set(a, undefined); break;
        case 0xd7: if (keys.length < 8) keys.push(b[p + 2]); set(a & 15, undefined); break;
        case 0x97: {const k = num(b[p + 3]) ?? num(b[p + 2]); if (k !== undefined && keys.length < 8) keys.push(k & 0xff); set(a, undefined); break;}
        case 0xb7: {const k = num(a >> 4); if (k !== undefined && keys.length < 8) keys.push(k & 0xff); set(a & 15, undefined); break;}
        default:
          if (x >= 0x60 && x <= 0x6d) {const f = b.readUInt16LE(p + 2); if (f < nf && fieldTracked[f]) site(sites, fields[f], caller, lib);}
          if (x >= 0x6e && x <= 0x78 && x !== 0x73) {
            const m = b.readUInt16LE(p + 2); pending = undefined; if (m >= nm) break;
            if (tracked[m]) site(sites, methods[m], caller, lib);
            const kind = special[m]; if (!kind) break;
            const range = x >= 0x74, count = range ? a : a >> 4, first = b.readUInt16LE(p + 4);
            const reg = (k: number) => range ? first + k : k < 4 ? b[p + 4 + (k >> 1)] >> (k & 1) * 4 & 15 : a & 15;
            if (count < 1) break;
            const v0 = get(reg(0)), v1 = count > 1 ? get(reg(1)) : undefined;
            if (kind === 1 && v1 && "a" in v1) {const s = arrText(v1); if (recoverable(s)) {v1.done = true; recover(s, `array ${v1.w === 1 ? "byte" : "char"} (${v1.src})`, caller, lib);} set(reg(0), {s});}
            else if (kind === 2 && v0 && "a" in v0) {const s = arrText(v0); if (recoverable(s)) {v0.done = true; recover(s, `array char (${v0.src})`, caller, lib);} pending = {s};}
            else if (kind === 3 && v0 && "sb" in v0) {if (count > 1) {if (v1 && "s" in v1) v0.sb.push(v1.s); else if (!v1 || !("n" in v1)) v0.ok = false;}}
            else if (kind === 4 && v0 && "sb" in v0) {if (v1 && "s" in v1 && v0.sb.length < 64) v0.sb.push(v1.s); else if (v1 && "n" in v1 && v0.sb.length < 64) v0.sb.push(String.fromCharCode(v1.n & 0xffff)); else v0.ok = false; pending = v0;}
            else if (kind === 5 && v0 && "sb" in v0) {const s = v0.sb.join(""); if (v0.ok && v0.sb.length >= 3 && v0.sb.every(part => part.length <= 24)) recover(s, "StringBuilder", caller, lib); pending = {s};}
            break;
          }
          if (x === 0x24 || x === 0x25 || x === 0xfa || x === 0xfb || x === 0xfc || x === 0xfd) {pending = undefined; break;}
          switch (DEST[x]) {
            case 1: set(a, undefined); break; case 2: set(a & 15, undefined); break; case 3: set(b.readUInt16LE(p + 2), undefined); break;
            case 4: set(a, undefined); set(a + 1, undefined); break; case 5: set(a & 15, undefined); set((a & 15) + 1, undefined); break;
            case 6: {const r = b.readUInt16LE(p + 2); set(r, undefined); set(r + 1, undefined); break;}
          }
      }
      pc += w;
    }
    // Arrays never turned into readable text directly: plain literal text, or single-byte XOR with a key seen in
    // this method (xor-int/lit*) or implied by an "http" prefix.
    for (const arr of arrays) {
      if (arr.a.length < 6 || arr.src === "aput" && !arr.a.some(Boolean)) continue;
      if (!arr.done) {const plain = arrText(arr); if (recoverable(plain)) recover(plain, `array ${arr.w === 1 ? "byte" : "char"} (${arr.src})`, caller, lib);}
      if (arr.w !== 1) continue;
      // XOR-ed literals are often printable too, so a key is always tried; the caller keeps only meaningful values.
      const guess = (arr.a[0] ^ 0x68) & 0xff;
      for (const k of new Set([...keys, guess])) {
        if (!k) continue; const s = arrText(arr, k);
        if (recoverable(s) && (keys.includes(k) || /^https?:\/\//.test(s))) {recover(s, `XOR 0x${k.toString(16).padStart(2, "0")}`, caller, lib); break;}
      }
    }
  };
  try {
    for (let ci = 0; ci < classes.length && !stop; ci++) {
      if ((ci & 63) === 0 && Date.now() > o.deadline) {stop = "batas waktu"; break;}
      const q = oc + ci * 32, data = b.readUInt32LE(q + 24); if (!data) continue;
      if (data < header || data >= b.length) {out.complete = false; continue;}
      const lib = isLib(classes[ci].name), st = {p: data};
      try {
        const sf = uleb(st), inf = uleb(st), dm = uleb(st), vm = uleb(st);
        if ((itemBudget -= sf + inf + dm + vm) < 0 || (sf + inf) * 2 + (dm + vm) * 3 > b.length - st.p) {out.complete = false; if (itemBudget < 0) stop = "batas struktur"; continue;}
        for (let i = 0; i < sf + inf; i++) {uleb(st); uleb(st);}
        for (const count of [dm, vm]) {
          let idx = 0;
          for (let i = 0; i < count && !stop; i++) {
            idx += uleb(st); uleb(st); const code = uleb(st);
            if (idx >= nm) {out.complete = false; break;}
            if (code) method(idx, code, lib);
            if ((out.methods & 1023) === 1023 && Date.now() > o.deadline) stop = "batas waktu";
          }
        }
      } catch {out.complete = false;}
    }
  } catch {out.complete = false;}
  if (stop) {out.complete = false; out.reason = stop;}
  // No decodable code at all (stub/table-only DEX): callers stay unknown rather than "never called".
  if (!out.methods) {out.complete = false; out.reason ||= "tanpa kode";}
  const list = <K>(m: Map<K, {app: Set<number>; lib: Set<number>}>, name: (k: K) => string) => [...m].map(([k, s]) => ({ref: name(k), app: [...s.app].map(i => methods[i]), lib: [...s.lib].map(i => methods[i])}));
  out.sites = list(sites, k => k); out.strings = list(strSites, i => strings[i].slice(0, 300));
  return out;
}
