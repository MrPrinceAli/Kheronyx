import { test } from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, createHash, randomBytes } from "node:crypto";
import AdmZip from "adm-zip";
import { cipherText, decryptConfigs, keyMaterial, meaningfulConfig, plaintextOf, specsOf, type DecryptJob } from "../lib/config-decrypt";
import { EndpointCollector } from "../lib/endpoints";
import { deadDrop } from "../lib/hosts";
import { Signals, evaluate, manifestModel } from "../lib/behaviors";
import { threatIntelTargets } from "../lib/threat-intel";
import { extractFile } from "../lib/extract";
import type { Artifact } from "../lib/types";

const CONFIG = `{"host":"103.146.158.229","port":7771,"panel":"https://panel-kurir.xyz/gate.php"}`;
const enc = (name: string, key: Buffer, iv: Buffer | null, text: string) => {const c = createCipheriv(name, key, iv); return Buffer.concat([c.update(text), c.final()]);};
const rc4 = (key: Buffer, data: Buffer) => {
  const S = [...Array(256).keys()]; let j = 0;
  for (let i = 0; i < 256; i++) {j = (j + S[i] + key[i % key.length]) % 256; [S[i], S[j]] = [S[j], S[i]];}
  let i = 0; j = 0; return Buffer.from(data.map(b => {i = (i + 1) % 256; j = (j + S[i]) % 256; [S[i], S[j]] = [S[j], S[i]]; return b ^ S[(S[i] + S[j]) % 256];}));
};
const job = (algorithms: string[], strings: string[], data: string[], opts: {pkg?: string; digest?: boolean} = {}): DecryptJob => {
  const {keys, ivs} = keyMaterial(strings, [], opts);
  return {via: "com.evil.Cfg.d", algorithms, keys, ivs, data: data.map(d => cipherText(d, "test")!).filter(Boolean)};
};

test("config decrypt: AES-CBC with string key and IV, AES-ECB (bare \"AES\"), RC4 and key = MD5(package)", () => {
  const key = "0123456789abcdef", iv = "fedcba9876543210";
  const cbc = enc("aes-128-cbc", Buffer.from(key), Buffer.from(iv), CONFIG).toString("base64");
  const r1 = decryptConfigs([job(["AES/CBC/PKCS5Padding"], ["AES/CBC/PKCS5Padding", key, iv, "UTF-8"], [cbc])]);
  assert.equal(r1.found.length, 1); assert.equal(r1.found[0].algorithm, "aes-cbc"); assert.equal(r1.found[0].plaintext, CONFIG);
  assert.equal(r1.found[0].via, "com.evil.Cfg.d");
  // The key is never shown in full: first 4 characters and the length only.
  assert.equal(r1.found[0].keySource, `string "0123…" (16)`); assert.ok(!r1.found[0].keySource.includes(key));
  const ecb = enc("aes-256-ecb", Buffer.from("k".repeat(32)), null, "http://45.61.136.12:8080/api/bot").toString("hex");
  const r2 = decryptConfigs([job(["AES"], ["k".repeat(32)], [ecb])]);
  assert.equal(r2.found[0]?.algorithm, "aes-ecb"); assert.equal(r2.found[0].plaintext, "http://45.61.136.12:8080/api/bot");
  const stream = rc4(Buffer.from("s3cr3t-k3y"), Buffer.from("https://api.telegram.org/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/sendMessage")).toString("base64");
  const r3 = decryptConfigs([job(["rc4"], ["s3cr3t-k3y"], [stream])]);
  assert.equal(r3.found[0]?.algorithm, "rc4"); assert.match(r3.found[0].plaintext, /api\.telegram\.org/);
  const pkg = "com.evil.kurir", md5 = createHash("md5").update(pkg).digest();
  const r4 = decryptConfigs([job(["AES/ECB/PKCS5Padding"], [], [enc("aes-128-ecb", md5, null, "c2.duckdns.org:4444").toString("base64")], {pkg})]);
  assert.equal(r4.found[0]?.keySource, `md5(${pkg})`); assert.equal(r4.found[0].plaintext, "c2.duckdns.org:4444");
  // IV carried in the first 16 bytes of the ciphertext, and 2-key... single DES via 3DES(K,K,K).
  const iv2 = randomBytes(16), pre = Buffer.concat([iv2, enc("aes-128-cbc", Buffer.from(key), iv2, CONFIG)]).toString("base64");
  assert.equal(decryptConfigs([job(["AES/CBC/PKCS5Padding"], [key], [pre])]).found[0]?.plaintext, CONFIG);
  // IV not available anywhere: the key still opens everything after the first block (never a garbled first block).
  const lost = decryptConfigs([job(["AES/CBC/PKCS5Padding"], [key], [enc("aes-128-cbc", Buffer.from(key), randomBytes(16), CONFIG).toString("base64")])]).found[0];
  assert.ok(lost && CONFIG.endsWith(lost.plaintext) && lost.plaintext.includes("panel-kurir.xyz"), JSON.stringify(lost));
  const des = enc("des-ede3-cbc", Buffer.concat(Array(3).fill(Buffer.from("8bytekey"))), Buffer.from("initvect"), CONFIG).toString("base64");
  assert.equal(decryptConfigs([job(["DES/CBC/PKCS5Padding"], ["8bytekey", "initvect"], [des])]).found[0]?.algorithm, "des-cbc");
});

test("config decrypt: wrong keys, gibberish and non-config plaintexts are rejected; caps hold", () => {
  const key = "0123456789abcdef", data = enc("aes-128-cbc", Buffer.from(key), Buffer.alloc(16), CONFIG).toString("base64");
  assert.equal(decryptConfigs([job(["AES/CBC/PKCS5Padding"], ["fedcba9876543210", "aaaaaaaaaaaaaaaa"], [data])]).found.length, 0);
  // Correct key but the plaintext is ordinary text without any endpoint/config field: no "discovery".
  const prose = enc("aes-128-ecb", Buffer.from(key), null, "Selamat datang di aplikasi kami, semoga harimu menyenangkan").toString("base64");
  assert.equal(decryptConfigs([job(["AES"], [key], [prose])]).found.length, 0);
  for (let i = 0; i < 200; i++) {const t = plaintextOf(randomBytes(48)); assert.ok(!t || !meaningfulConfig(t));}
  assert.equal(meaningfulConfig("hello world"), false); assert.equal(meaningfulConfig("http://localhost/x"), false);
  assert.equal(meaningfulConfig(`{"server":"c2.kurir-paket.net","port":"4444"}`), true); assert.equal(meaningfulConfig("user=admin"), false);
  assert.equal(meaningfulConfig(`{"server":"x","port":"1"}`), false); assert.equal(meaningfulConfig("key == null || value == null"), false);
  assert.equal(meaningfulConfig("10.0.0.5:8080"), false); assert.equal(meaningfulConfig("185.22.10.7:1177"), true);
  // Readable base64 is plain encoding, not ciphertext; RC4 with no key/stream spec gives nothing to try.
  assert.equal(cipherText(Buffer.from("https://example.org/path/x").toString("base64"), "t"), null);
  assert.deepEqual(specsOf(["Blowfish/CBC/PKCS5Padding", "AES/GCM-SIV/NoPadding"]), []);
  // Attempt cap: 40 jobs x many keys never exceed the cap; a zero time budget stops immediately.
  const keys = Array.from({length: 60}, (_, i) => `k${String(i).padStart(15, "0")}`);
  const many = Array.from({length: 40}, () => job(["AES/CBC/PKCS5Padding", "AES/CTR/NoPadding", "rc4"], keys, [data, randomBytes(64).toString("base64")]));
  const capped = decryptConfigs(many, {maxAttempts: 150}); assert.ok(capped.attempts <= 150, String(capped.attempts)); assert.equal(capped.found.length, 0);
  const t = Date.now(), full = decryptConfigs(many); assert.ok(full.attempts <= 2000); assert.ok(Date.now() - t < 1500);
  assert.equal(decryptConfigs(many, {budgetMs: -1}).timedOut, true);
});

test("dead drops: raw/paste/export URLs count, generic GitHub/docs/support links do not", () => {
  const cases: [string, string][] = [
    ["https://pastebin.com/raw/aB3dE5fG", "raw"], ["https://pastebin.com/aB3dE5fG", "raw"], ["https://pastebin.com/doc_api", ""], ["https://pastebin.com/", ""],
    ["https://raw.githubusercontent.com/user/repo/main/c2.txt", "raw"], ["https://github.com/user/repo", ""], ["https://github.com/user/repo/issues", ""], ["https://github.com/user/repo/raw/main/cfg", "raw"],
    ["https://gist.githubusercontent.com/u/abc123/raw/x.json", "raw"], ["https://gitlab.com/u/r/-/raw/main/x.txt", "raw"], ["https://gitlab.com/u/r/-/blob/master/LICENSE", ""],
    ["https://docs.google.com/document/d/1QyEKOaDvwQ0E2GBixoCoJiBxSq1vLxc6/export?format=txt", "raw"], ["https://docs.google.com/document/d/1QyEKOaDvwQ0E2GBixoCoJiBxSq1vLxc6/edit", "linked"],
    ["https://docs.google.com/forms/d/e/1FAIpQLSf/viewform", ""], ["https://support.google.com/accounts/answer/185839", ""],
    ["https://drive.google.com/uc?export=download&id=1GONwHA_2awwNyOoYj3qvaryaYl9RBBpS", "raw"], ["https://t.me/s/kurir_update", "raw"], ["https://t.me/Fossify", "hidden"], ["https://t.me/+LjSk2YQX2mY5NDA5", ""],
    ["https://steamcommunity.com/profiles/76561199724331900", "raw"], ["https://firebaseremoteconfig.googleapis.com/v1/projects/%s/namespaces/%s:fetch", ""],
    ["https://gateway.ipfs.io/ipfs/", ""], ["https://cdn.example-x.workers.dev/config.txt", "raw"], ["https://update-two-tau.vercel.app/payment-receipt", ""],
  ];
  for (const [url, kind] of cases) assert.equal(deadDrop(url), kind, url);
  const collect = (strings: string[], source = "dex", callers?: string[]) => {const c = new EndpointCollector(); c.add(strings, source, {callers: () => callers}); return c.finish({linked: m => m.startsWith("Lcom/evil/Net;")});};
  const plain = collect(["https://pastebin.com/raw/aB3dE5fG", "https://github.com/user/repo", "https://docs.google.com/document/d/1QyEKOaDvwQ0E2GBixoCoJiBxSq1vLxc6/edit", "https://t.me/Fossify", "https://drive.google.com/uc?export=download&id=1GONwHA_2awwNyOoYj3qvaryaYl9RBBpS"]);
  assert.deepEqual(plain.filter(e => e.kind === "deaddrop").map(e => e.value), ["https://pastebin.com/raw/aB3dE5fG", "https://drive.google.com/uc?export=download&id=1GONwHA_2awwNyOoYj3qvaryaYl9RBBpS"]);
  // A share page loaded by networking code counts; a Telegram channel link only when hidden.
  assert.equal(collect(["https://docs.google.com/document/d/1QyEKOaDvwQ0E2GBixoCoJiBxSq1vLxc6/edit"], "dex", ["Lcom/evil/Net;->fetch"])[0]?.kind, "deaddrop");
  assert.equal(collect(["https://t.me/Fossify"], "dex", ["Lcom/evil/Net;->fetch"]).length, 0);
  const c = new EndpointCollector(); c.hidden([{value: "https://t.me/kurir_c2_chan", technique: "base64", where: "Lcom/evil/Cfg;->d"}]);
  assert.deepEqual(c.finish().map(e => [e.kind, e.source, e.via]), [["deaddrop", "deobfuscated:base64", "com.evil.Cfg.d"]]);
  // Full dead-drop URL goes to URLhaus (shared host itself is never looked up).
  const a = {urls: [], metadata: {campaign: {hosts: [], deadDrops: ["https://pastebin.com/raw/aB3dE5fG", "https://pastebin.com/raw/x?token=1"]}}} as unknown as Artifact;
  assert.deepEqual(threatIntelTargets(a).urls, ["https://pastebin.com/raw/aB3dE5fG"]); assert.deepEqual(threatIntelTargets(a).hosts, []);
});

test("dead_drop behavior: gated low in a clean app, high when hidden or next to stealer code", () => {
  const ep = (source: string) => ({value: "https://pastebin.com/raw/aB3dE5fG", host: "pastebin.com", kind: "deaddrop" as const, source});
  const by = (endpoints: ReturnType<typeof ep>[]) => evaluate(new Signals(), manifestModel(null), [], {endpoints}).find(b => b.id === "dead_drop");
  assert.equal(by([ep("dex")])?.severity, "low");
  assert.equal(by([ep("deobfuscated:aes-cbc")])?.severity, "high");
  const encrypted = {id: "encrypted_config", name: "x", severity: "high" as const, evidence: ["e"]};
  // encrypted_config (high) is malicious context, so a plain dead drop next to it stays medium.
  assert.equal(evaluate(new Signals(), manifestModel(null), [encrypted], {endpoints: [ep("dex")]}).find(b => b.id === "dead_drop")?.severity, "medium");
});

test("decrypted plaintext endpoints carry source deobfuscated:<algo> and the decrypting method", () => {
  const c = new EndpointCollector(); c.hidden([{value: CONFIG, technique: "aes-cbc", where: "com.evil.Cfg.d"}]);
  const list = c.finish();
  assert.ok(list.some(e => e.value === "103.146.158.229" && e.kind === "ip" && e.source === "deobfuscated:aes-cbc" && e.via === "com.evil.Cfg.d"), JSON.stringify(list));
  assert.ok(list.some(e => e.kind === "panel" && e.host === "panel-kurir.xyz" && e.source === "deobfuscated:aes-cbc"));
});

// ---- end to end: hand-assembled DEX (javax.crypto call site, key/IV constants, ciphertext passed from another class) ----
const uleb = (n: number) => {const out: number[] = []; do {let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; out.push(b);} while (n); return out;};
type Method = {name: string; code: number[]};
class Dex {
  strings: string[] = []; types: number[] = []; methods: [number, number][] = []; fields: [number, number][] = []; classes: {cls: number; sup: number; methods: [number, Method][]}[] = [];
  s(x: string) {let i = this.strings.indexOf(x); if (i < 0) i = this.strings.push(x) - 1; return i;}
  t(x: string) {const si = this.s(x); let i = this.types.indexOf(si); if (i < 0) i = this.types.push(si) - 1; return i;}
  m(c: string, n: string) {const k: [number, number] = [this.t(c), this.s(n)]; let i = this.methods.findIndex(x => x[0] === k[0] && x[1] === k[1]); if (i < 0) i = this.methods.push(k) - 1; return i;}
  f(c: string, n: string) {const k: [number, number] = [this.t(c), this.s(n)]; let i = this.fields.findIndex(x => x[0] === k[0] && x[1] === k[1]); if (i < 0) i = this.fields.push(k) - 1; return i;}
  cls(name: string, sup: string, methods: Method[] = []) {const cls = this.t(name), s = this.t(sup); this.classes.push({cls, sup: s, methods: methods.map(x => [this.m(name, x.name), x] as [number, Method])}); return this;}
  build() {
    const oStr = 0x70, oType = oStr + this.strings.length * 4, oField = oType + this.types.length * 4, oMethod = oField + this.fields.length * 8, oClass = oMethod + this.methods.length * 8, oData = oClass + this.classes.length * 32;
    const data: number[] = [], strOff: number[] = [], pad = () => {while ((oData + data.length) % 4) data.push(0);};
    for (const s of this.strings) {strOff.push(oData + data.length); data.push(...uleb(s.length), ...Buffer.from(s, "utf8"), 0);}
    const codeOff = new Map<Method, number>();
    for (const c of this.classes) for (const [, m] of c.methods) {pad(); codeOff.set(m, oData + data.length); const h = Buffer.alloc(16); h.writeUInt16LE(16, 0); h.writeUInt32LE(m.code.length, 12); data.push(...h); for (const u of m.code) data.push(u & 0xff, u >> 8 & 0xff);}
    const classData = this.classes.map(c => {
      if (!c.methods.length) return 0; const at = oData + data.length, sorted = [...c.methods].sort((a, b) => a[0] - b[0]); let prev = 0;
      data.push(0, 0, ...uleb(sorted.length), 0); for (const [idx, m] of sorted) {data.push(...uleb(idx - prev), 1, ...uleb(codeOff.get(m)!)); prev = idx;}
      return at;
    });
    const b = Buffer.alloc(oData + data.length);
    b.write("dex\n035\0", 0, "latin1"); b.writeUInt32LE(b.length, 0x20); b.writeUInt32LE(0x70, 0x24); b.writeUInt32LE(0x12345678, 0x28);
    b.writeUInt32LE(this.strings.length, 0x38); b.writeUInt32LE(oStr, 0x3c); b.writeUInt32LE(this.types.length, 0x40); b.writeUInt32LE(oType, 0x44);
    b.writeUInt32LE(this.fields.length, 0x50); b.writeUInt32LE(oField, 0x54); b.writeUInt32LE(this.methods.length, 0x58); b.writeUInt32LE(oMethod, 0x5c); b.writeUInt32LE(this.classes.length, 0x60); b.writeUInt32LE(oClass, 0x64);
    strOff.forEach((o, i) => b.writeUInt32LE(o, oStr + i * 4)); this.types.forEach((s, i) => b.writeUInt32LE(s, oType + i * 4));
    this.fields.forEach(([c, n], i) => {b.writeUInt16LE(c, oField + i * 8); b.writeUInt32LE(n, oField + i * 8 + 4);});
    this.methods.forEach(([c, n], i) => {b.writeUInt16LE(c, oMethod + i * 8); b.writeUInt32LE(n, oMethod + i * 8 + 4);});
    this.classes.forEach((c, i) => {const q = oClass + i * 32; b.writeUInt32LE(c.cls, q); b.writeUInt32LE(c.sup, q + 8); b.writeUInt32LE(0xffffffff, q + 12); b.writeUInt32LE(0xffffffff, q + 16); b.writeUInt32LE(classData[i], q + 24);});
    Buffer.from(data).copy(b, oData); return b;
  }
}
const str = (r: number, s: number) => [r << 8 | 0x1a, s], invoke = (op: number, m: number, regs: number[]) => [(regs.length << 4) << 8 | op, m, (regs[0] ?? 0) | (regs[1] ?? 0) << 4 | (regs[2] ?? 0) << 8];
const sput = (r: number, f: number) => [r << 8 | 0x69, f], sget = (r: number, f: number) => [r << 8 | 0x62, f], ret = () => [0x0e];
function manifest(pkg: string) {
  const strings: string[] = [], idx = (s: string) => {let i = strings.indexOf(s); if (i < 0) i = strings.push(s) - 1; return i;};
  const elements: [string, Record<string, string>][] = [["manifest", {package: pkg}], ["uses-permission", {name: "android.permission.INTERNET"}], ["activity", {name: `${pkg}.Main`}], ["action", {name: "android.intent.action.MAIN"}], ["category", {name: "android.intent.category.LAUNCHER"}]];
  const chunks = elements.map(([tag, attrs]) => {
    const entries = Object.entries(attrs), c = Buffer.alloc(36 + entries.length * 20);
    c.writeUInt16LE(0x102, 0); c.writeUInt16LE(16, 2); c.writeUInt32LE(c.length, 4); c.writeUInt32LE(0xffffffff, 12); c.writeUInt32LE(0xffffffff, 16); c.writeUInt32LE(idx(tag), 20);
    c.writeUInt16LE(20, 24); c.writeUInt16LE(20, 26); c.writeUInt16LE(entries.length, 28);
    entries.forEach(([k, v], i) => {const a = 36 + i * 20; c.writeUInt32LE(0xffffffff, a); c.writeUInt32LE(idx(k), a + 4); c.writeUInt32LE(idx(v), a + 8); c.writeUInt16LE(8, a + 12); c[a + 15] = 3; c.writeUInt32LE(idx(v), a + 16);});
    return c;
  });
  const bodies = strings.map(s => {const u = Buffer.from(s, "utf8"); return Buffer.concat([Buffer.from([s.length, u.length]), u, Buffer.from([0])]);});
  let data = Buffer.concat(bodies); data = Buffer.concat([data, Buffer.alloc((4 - data.length % 4) % 4)]);
  const pool = Buffer.alloc(28 + strings.length * 4); let off = 0;
  pool.writeUInt16LE(1, 0); pool.writeUInt16LE(28, 2); pool.writeUInt32LE(28 + strings.length * 4 + data.length, 4); pool.writeUInt32LE(strings.length, 8); pool.writeUInt32LE(256, 16); pool.writeUInt32LE(28 + strings.length * 4, 20);
  bodies.forEach((b, i) => {pool.writeUInt32LE(off, 28 + i * 4); off += b.length;});
  const body = Buffer.concat([pool, data, ...chunks]), head = Buffer.alloc(8); head.writeUInt16LE(3, 0); head.writeUInt16LE(8, 2); head.writeUInt32LE(8 + body.length, 4);
  return Buffer.concat([head, body]);
}
test("APK: config encrypted with an embedded AES key is decrypted statically and reported as attacker endpoints", async () => {
  const key = "Kh3r0nyxT3stK3y!", iv = "iv-1234567890abc", plain = "https://kurir-paket.duckdns.org:8443/panel/gate.php", d = new Dex();
  const ct = enc("aes-128-cbc", Buffer.from(key), Buffer.from(iv), plain).toString("base64");
  const Cfg = "Lcom/evil/kurir/Cfg;", getInstance = d.m("Ljavax/crypto/Cipher;", "getInstance"), spec = d.m("Ljavax/crypto/spec/SecretKeySpec;", "<init>"), dec = d.m(Cfg, "d"), ivField = d.f("Lcom/evil/kurir/Keys;", "IV");
  // Cfg.d(String) holds the key and reads the IV from a static field set in Keys.<clinit>; Main passes the ciphertext.
  d.cls(Cfg, "Ljava/lang/Object;", [{name: "d", code: [...str(0, d.s("AES/CBC/PKCS5Padding")), ...invoke(0x71, getInstance, [0]), ...str(1, d.s(key)), ...str(2, d.s("AES")), ...invoke(0x70, spec, [3, 1, 2]), ...sget(4, ivField), ...ret()]}]);
  d.cls("Lcom/evil/kurir/Main;", "Landroid/app/Activity;", [{name: "onCreate", code: [...str(0, d.s(ct)), ...invoke(0x71, dec, [0]), ...ret()]}]);
  d.cls("Lcom/evil/kurir/Keys;", "Ljava/lang/Object;", [{name: "<clinit>", code: [...str(0, d.s(iv)), ...sput(0, ivField), ...ret()]}]);
  const zip = new AdmZip(); zip.addFile("AndroidManifest.xml", manifest("com.evil.kurir")); zip.addFile("classes.dex", d.build());
  const r = await extractFile(zip.toBuffer(), "kurir.apk"), m = r.metadata as Record<string, any>;
  const cfg = m.decryptedConfig as {algorithm: string; via: string; keySource: string; plaintext: string}[];
  assert.equal(cfg?.length, 1, JSON.stringify(m.cryptoScan)); assert.equal(cfg[0].algorithm, "aes-cbc"); assert.equal(cfg[0].plaintext, plain);
  assert.equal(cfg[0].keySource, `string "Kh3r…" (16)`); assert.ok(!JSON.stringify(r).includes(key), "full key leaked");
  const ep = (m.endpoints as {kind: string; source: string; host: string; via?: string}[]).find(e => e.host === "kurir-paket.duckdns.org");
  assert.equal(ep?.source, "deobfuscated:aes-cbc"); assert.equal(ep?.via, "com.evil.kurir.Cfg.d");
  const b = (m.behaviors as {id: string; severity: string}[]).find(x => x.id === "encrypted_config"); assert.equal(b?.severity, "high");
  assert.ok((m.campaign.hosts as string[]).includes("kurir-paket.duckdns.org"));
});
