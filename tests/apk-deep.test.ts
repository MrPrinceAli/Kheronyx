import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import AdmZip from "adm-zip";
import { extractFile } from "../lib/extract";
import { parseDex, type CodeOptions } from "../lib/dex";
import { parseElf } from "../lib/elf";
import { trackedRef, trackedString } from "../lib/behaviors";
import { apkSigning } from "../lib/apk-signing";
import { readZip, zipDirectory } from "../lib/zip";

// ---- DEX builder with real class_data / code_items (hand-assembled Dalvik bytecode) ----
const uleb = (n: number) => {const out: number[] = []; do {let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; out.push(b);} while (n); return out;};
type Method = {name: string; code: number[]; regs?: number};
class Dex {
  strings: string[] = []; types: number[] = []; methods: [number, number][] = []; fields: [number, number][] = []; classes: {cls: number; sup: number; methods: [number, Method][]}[] = [];
  s(x: string) {let i = this.strings.indexOf(x); if (i < 0) i = this.strings.push(x) - 1; return i;}
  t(x: string) {const si = this.s(x); let i = this.types.indexOf(si); if (i < 0) i = this.types.push(si) - 1; return i;}
  m(c: string, n: string) {const k: [number, number] = [this.t(c), this.s(n)]; let i = this.methods.findIndex(x => x[0] === k[0] && x[1] === k[1]); if (i < 0) i = this.methods.push(k) - 1; return i;}
  f(c: string, n: string) {const k: [number, number] = [this.t(c), this.s(n)]; let i = this.fields.findIndex(x => x[0] === k[0] && x[1] === k[1]); if (i < 0) i = this.fields.push(k) - 1; return i;}
  cls(name: string, sup: string, methods: Method[] = []) {const cls = this.t(name), s = this.t(sup); this.classes.push({cls, sup: s, methods: methods.map(x => [this.m(name, x.name), x] as [number, Method])}); return this;}
  build() {
    const oStr = 0x70, oType = oStr + this.strings.length * 4, oField = oType + this.types.length * 4, oMethod = oField + this.fields.length * 8, oClass = oMethod + this.methods.length * 8, oData = oClass + this.classes.length * 32;
    const data: number[] = [], strOff: number[] = [];
    const pad = () => {while ((oData + data.length) % 4) data.push(0);};
    for (const s of this.strings) {strOff.push(oData + data.length); const u = Buffer.from(s, "utf8"); data.push(...uleb(s.length), ...u, 0);}
    const codeOff = new Map<Method, number>();
    for (const c of this.classes) for (const [, m] of c.methods) {
      pad(); codeOff.set(m, oData + data.length); const h = Buffer.alloc(16); h.writeUInt16LE(m.regs ?? 16, 0); h.writeUInt32LE(m.code.length, 12); data.push(...h);
      for (const u of m.code) data.push(u & 0xff, u >> 8 & 0xff);
    }
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
// Instruction encoders (16-bit code units).
const I = {
  const4: (r: number, v: number) => [(v & 15) << 12 | r << 8 | 0x12], const16: (r: number, v: number) => [r << 8 | 0x13, v & 0xffff],
  str: (r: number, s: number) => [r << 8 | 0x1a, s], strJumbo: (r: number, s: number) => [r << 8 | 0x1b, s & 0xffff, s >>> 16],
  newInstance: (r: number, t: number) => [r << 8 | 0x22, t], newArray: (r: number, size: number, t: number) => [(size << 4 | r) << 8 | 0x23, t],
  fill: (r: number, off: number) => [r << 8 | 0x26, off & 0xffff, off >>> 16 & 0xffff], aputByte: (v: number, arr: number, i: number) => [v << 8 | 0x4f, i << 8 | arr],
  invoke: (op: number, m: number, regs: number[]) => [(regs.length << 4 | (regs[4] ?? 0)) << 8 | op, m, (regs[0] ?? 0) | (regs[1] ?? 0) << 4 | (regs[2] ?? 0) << 8 | (regs[3] ?? 0) << 12],
  range: (op: number, m: number, first: number, count: number) => [count << 8 | op, m, first], result: (r: number) => [r << 8 | 0x0c],
  xor8: (d: number, s: number, lit: number) => [d << 8 | 0xdf, (lit & 0xff) << 8 | s], sget: (r: number, f: number) => [r << 8 | 0x62, f],
  wide: (r: number) => [r << 8 | 0x18, 1, 2, 3, 4], polymorphic: (m: number) => [0x20fa, m, 0x0010, 0x0001], custom: (cs: number) => [0x10fc, cs, 0x0000],
  ret: () => [0x0e], nop: () => [0x0000],
  packed: (targets: number[]) => [0x0100, targets.length, 0, 0, ...targets.flatMap(t => [t & 0xffff, t >>> 16])],
  sparse: (pairs: [number, number][]) => [0x0200, pairs.length, ...pairs.flatMap(([k]) => [k & 0xffff, k >>> 16]), ...pairs.flatMap(([, t]) => [t & 0xffff, t >>> 16])],
  array: (width: number, values: number[]) => {const bytes = Buffer.alloc(Math.ceil(values.length * width / 2) * 2); values.forEach((v, i) => width === 1 ? bytes[i] = v & 0xff : bytes.writeUInt16LE(v & 0xffff, i * 2)); const u: number[] = []; for (let i = 0; i < bytes.length; i += 2) u.push(bytes.readUInt16LE(i)); return [0x0300, width, values.length & 0xffff, values.length >>> 16, ...u];},
};
const OPTS: CodeOptions = {deadline: Date.now() + 60000, ref: trackedRef, string: trackedString};
const opts = () => ({code: {...OPTS, deadline: Date.now() + 10000}});
// Minimal binary AndroidManifest (same layout as tests/analysis.test.ts).
function manifest(elements: [string, Record<string, string>][]) {
  const strings: string[] = []; const idx = (s: string) => {let i = strings.indexOf(s); if (i < 0) i = strings.push(s) - 1; return i;};
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
const launcher: [string, Record<string, string>][] = [["activity", {name: "id.app.Main"}], ["action", {name: "android.intent.action.MAIN"}], ["category", {name: "android.intent.category.LAUNCHER"}]];
type Behavior = {id: string; severity: string; evidence: string[]};
const behaviorsOf = (r: {metadata: Record<string, unknown>}) => r.metadata.behaviors as Behavior[];
const TOKEN = "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw";

// SMS stealer whose receiver is registered at runtime and inherits BroadcastReceiver indirectly; a library class calls
// MediaProjection. A packed-switch payload hides bytes that would decode as invoke-static Runtime.exec if not skipped.
function stealerDex() {
  const d = new Dex(), R = "Lid/undangan/digital/SmsReceiver;", B = "Lid/undangan/digital/BaseReceiver;";
  const pdu = d.m("Landroid/telephony/SmsMessage;", "createFromPdu"), body = d.m("Landroid/telephony/SmsMessage;", "getMessageBody"), open = d.m("Ljava/net/URL;", "openConnection");
  const exec = d.m("Ljava/lang/Runtime;", "exec"), proj = d.m("Landroid/media/projection/MediaProjectionManager;", "createScreenCaptureIntent");
  const url = d.s(`https://api.telegram.org/bot123456789:${TOKEN}/sendMessage`), big = d.s("Undangan pernikahan digital");
  d.cls(B, "Landroid/content/BroadcastReceiver;");
  d.cls(R, B, [{name: "onReceive", code: [
    ...I.wide(4), ...I.invoke(0x71, pdu, [1]), ...I.result(2), ...I.polymorphic(open), ...I.custom(0),
    ...I.packed([0x0071 | 0, exec, 0]), // payload data looks like "invoke-static {}, Runtime.exec"
    ...I.invoke(0x6e, body, [2]), ...I.result(3), ...I.str(5, url), ...I.strJumbo(6, big), ...I.range(0x74, open, 5, 1),
    ...I.sparse([[1, 0x71], [2, exec]]), ...I.nop(), ...I.array(1, [0x71, 0, exec & 0xff, exec >> 8]), ...I.ret(),
  ]}]);
  d.cls("Landroidx/core/app/ScreenHelper;", "Ljava/lang/Object;", [{name: "start", code: [...I.invoke(0x6e, proj, [0]), ...I.ret()]}]);
  d.cls("Lid/undangan/digital/Main;", "Landroid/app/Activity;", [{name: "onCreate", code: [...I.ret()]}]);
  return {dex: d.build(), exec};
}
test("bytecode: invoke-* call sites are attributed to app vs library code, payload pseudo-instructions are skipped", () => {
  const {dex} = stealerDex(), d = parseDex(dex, Infinity, opts()), code = d.code!;
  assert.equal(code.complete, true); assert.equal(code.methods, 3);
  const site = (ref: string) => code.sites.find(s => s.ref === ref);
  assert.deepEqual(site("Landroid/telephony/SmsMessage;->createFromPdu")?.app, ["Lid/undangan/digital/SmsReceiver;->onReceive"]);
  assert.deepEqual(site("Landroid/telephony/SmsMessage;->getMessageBody")?.app, ["Lid/undangan/digital/SmsReceiver;->onReceive"]);
  assert.deepEqual(site("Ljava/net/URL;->openConnection")?.app, ["Lid/undangan/digital/SmsReceiver;->onReceive"], "invoke/range decoded");
  assert.deepEqual(site("Landroid/media/projection/MediaProjectionManager;->createScreenCaptureIntent")?.lib, ["Landroidx/core/app/ScreenHelper;->start"]);
  assert.equal(site("Ljava/lang/Runtime;->exec"), undefined, "payload data must not be decoded as instructions");
  assert.ok(code.strings.some(s => s.ref.startsWith("https://api.telegram.org") && s.app[0] === "Lid/undangan/digital/SmsReceiver;->onReceive"));
});
test("APK: call-site evidence, library-only downgrade, runtime SMS receiver via indirect subclass and SMS→network link", async () => {
  const zip = new AdmZip();
  zip.addFile("AndroidManifest.xml", manifest([["manifest", {package: "id.undangan.digital"}], ["uses-permission", {name: "android.permission.RECEIVE_SMS"}], ["uses-permission", {name: "android.permission.INTERNET"}], ["application", {name: "id.undangan.digital.App"}], ["activity", {name: "id.undangan.digital.Main"}], ["action", {name: "android.intent.action.MAIN"}], ["category", {name: "android.intent.category.LAUNCHER"}]]));
  zip.addFile("classes.dex", stealerDex().dex);
  const r = await extractFile(zip.toBuffer(), "undangan.apk"), b = behaviorsOf(r), by = (id: string) => b.find(x => x.id === id);
  assert.equal(r.incomplete, false);
  const sms = by("sms_read")!; assert.equal(sms.severity, "high");
  assert.ok(sms.evidence.some(e => e.includes("dipanggil oleh: id.undangan.digital.SmsReceiver.onReceive")), sms.evidence.join(" | "));
  assert.ok(sms.evidence.some(e => e.includes("receiver SMS di kode: id.undangan.digital.SmsReceiver (tidak ada di manifest")), "indirect BroadcastReceiver subclass");
  const screen = by("screen_capture")!; assert.equal(screen.severity, "low"); assert.ok(r.indicators.some(i => i.name === "Merekam atau menyiarkan layar (tidak dipanggil kode aplikasi)"));
  assert.ok(screen.evidence.some(e => e.includes("androidx.core.app.ScreenHelper.start")));
  // Runtime.exec is only referenced (its bytes hide inside switch/array payloads), never invoked.
  const exec = by("shell_exec"); assert.equal(exec?.severity, "low"); assert.ok(exec?.evidence.some(e => e.includes("Runtime.exec ← tidak ada pemanggilan langsung")));
  const stealer = by("sms_stealer")!; assert.equal(stealer.severity, "critical");
  assert.ok(stealer.evidence.some(e => e.startsWith("rantai kode: id.undangan.digital.SmsReceiver membaca SMS dan memakai")), stealer.evidence.join(" | "));
  const sites = r.metadata.callSites as {api: string; app: string[]; libraryOnly?: boolean}[];
  assert.ok(sites.some(s => s.api === "SmsMessage.createFromPdu" && s.app[0] === "id.undangan.digital.SmsReceiver.onReceive"));
  assert.ok(sites.some(s => s.api === "MediaProjectionManager.createScreenCaptureIntent" && s.libraryOnly));
  assert.equal((r.metadata.dexScan as {code: {complete: boolean}}).code.complete, true);
  assert.ok(!JSON.stringify(r).includes(TOKEN));
});
test("class hierarchy: indirect framework subclasses resolve across DEX files with a depth cap and cycle safety", async () => {
  const d1 = new Dex().cls("Lcom/x/Svc;", "Lcom/x/Base;").cls("Lcom/x/Ime;", "Lcom/x/KeyboardBase;").cls("Lcom/c/A;", "Lcom/c/B;").cls("Lcom/c/B;", "Lcom/c/A;");
  let deep = "Landroid/service/notification/NotificationListenerService;"; for (let i = 0; i < 30; i++) {d1.cls(`Lcom/deep/L${i};`, deep); deep = `Lcom/deep/L${i};`;}
  const d2 = new Dex().cls("Lcom/x/Base;", "Lcom/lib/Mid;").cls("Lcom/lib/Mid;", "Landroid/accessibilityservice/AccessibilityService;").cls("Lcom/x/KeyboardBase;", "Landroid/inputmethodservice/InputMethodService;");
  const zip = new AdmZip(); zip.addFile("AndroidManifest.xml", manifest([["manifest", {package: "com.x"}], ...launcher])); zip.addFile("classes.dex", d1.build()); zip.addFile("classes2.dex", d2.build());
  const started = Date.now(), r = await extractFile(zip.toBuffer(), "x.apk"), b = behaviorsOf(r); assert.ok(Date.now() - started < 3000);
  const a11y = b.find(x => x.id === "accessibility")!; assert.ok(a11y.evidence[0].includes("com.x.Svc (turunan tidak langsung via com.x.Base)"), a11y.evidence[0]);
  assert.ok(b.find(x => x.id === "keyboard")?.evidence[0].includes("com.x.Ime (turunan tidak langsung via com.x.KeyboardBase)"));
  // The 30-level chain exceeds the depth cap: only the first levels count as listeners.
  const notif = b.find(x => x.id === "notification_listener")!; assert.ok(notif.evidence[0].includes("com.deep.L0")); assert.ok(!JSON.stringify(notif).includes("com.deep.L29"));
});
test("string deobfuscation: base64, hex, reversed, char/byte arrays, single-byte XOR and StringBuilder chains", async () => {
  const d = new Dex(), C = "Lid/kurir/Config;", rev = `https://api.telegram.org/bot987654321:${TOKEN}/sendMessage`;
  const strInit = d.m("Ljava/lang/String;", "<init>"), sb = d.t("Ljava/lang/StringBuilder;"), sbInit = d.m("Ljava/lang/StringBuilder;", "<init>"), append = d.m("Ljava/lang/StringBuilder;", "append"), toString = d.m("Ljava/lang/StringBuilder;", "toString");
  const tStr = d.t("Ljava/lang/String;"), tB = d.t("[B"), tC = d.t("[C");
  d.s(Buffer.from("wss://45.77.10.20:8443/ws").toString("base64")); d.s(Buffer.from("http://103.20.30.40/upload.php").toString("hex")); d.s([...rev].reverse().join(""));
  const chars = [..."https://c2-panel.xyz/gate.php"].map(c => c.charCodeAt(0)), xorKey = 0x5a, xored = [..."https://discord.com/api/webhooks/42/abcdef"].map(c => c.charCodeAt(0) ^ xorKey);
  const bytes = [..."http://8.8.4.4/x.php"].map(c => c.charCodeAt(0)), parts = ["https://", "hooks.slack", ".com/services/", "T0/B0/zz"];
  const charMethod = [...I.const16(0, chars.length), ...I.newArray(1, 0, tC), ...I.fill(1, 0), ...I.newInstance(2, tStr), ...I.invoke(0x70, strInit, [2, 1]), ...I.ret()];
  const charCode = [...charMethod, ...I.nop(), ...I.array(2, chars)];
  const xorCode0 = [...I.const16(0, xored.length), ...I.newArray(1, 0, tB), ...I.fill(1, 0), ...I.xor8(3, 3, xorKey), ...I.newInstance(2, tStr), ...I.invoke(0x70, strInit, [2, 1]), ...I.ret()];
  const xorCode = [...xorCode0, ...I.array(1, xored)];
  const byteCode = [...I.const16(0, bytes.length), ...I.newArray(1, 0, tB), ...bytes.flatMap((v, i) => [...I.const16(3, i), ...I.const16(4, v), ...I.aputByte(4, 1, 3)]), ...I.newInstance(2, tStr), ...I.invoke(0x70, strInit, [2, 1]), ...I.ret()];
  const sbCode = [...I.newInstance(0, sb), ...I.invoke(0x70, sbInit, [0]), ...parts.flatMap(p => [...I.str(1, d.s(p)), ...I.invoke(0x6e, append, [0, 1]), ...I.result(0)]), ...I.invoke(0x6e, toString, [0]), ...I.result(2), ...I.ret()];
  d.cls(C, "Ljava/lang/Object;", [{name: "chars", code: fixPayload(charCode)}, {name: "xor", code: fixPayload(xorCode)}, {name: "bytes", code: byteCode}, {name: "sb", code: sbCode}]);
  const zip = new AdmZip(); zip.addFile("AndroidManifest.xml", manifest([["manifest", {package: "id.kurir"}], ...launcher])); zip.addFile("classes.dex", d.build());
  const r = await extractFile(zip.toBuffer(), "kurir.apk"), found = r.metadata.deobfuscated as {value: string; technique: string; where?: string}[];
  const tech = (t: RegExp) => found.find(x => t.test(x.technique));
  assert.equal(tech(/^base64$/)?.value, "wss://45.77.10.20:8443/ws"); assert.equal(tech(/^hex$/)?.value, "http://103.20.30.40/upload.php");
  assert.equal(tech(/dibalik/)?.value, `https://api.telegram.org/bot987654321:…Dsaw/sendMessage`);
  assert.equal(tech(/array char/)?.value, "https://c2-panel.xyz/gate.php"); assert.equal(tech(/array char/)?.where, "id.kurir.Config.chars");
  assert.equal(tech(/array byte \(aput\)/)?.value, "http://8.8.4.4/x.php");
  assert.equal(tech(/^XOR 0x5a$/)?.value, "https://discord.com/api/webhooks/42/…");
  assert.equal(tech(/StringBuilder/)?.value, "https://hooks.slack.com/services/T0/B0/…");
  const b = behaviorsOf(r), obf = b.find(x => x.id === "obfuscated_strings")!; assert.equal(obf.severity, "high");
  assert.ok(b.find(x => x.id === "exfil_telegram")?.evidence.some(e => e.includes("(disamarkan: teks dibalik)")));
  assert.ok(b.some(x => x.id === "exfil_webhook") && b.some(x => x.id === "exfil_ip") && b.some(x => x.id === "exfil_panel"));
  assert.ok(r.indicators.some(i => i.name === "String disamarkan berisi alamat/rahasia" && i.evidence.includes("(disamarkan: XOR 0x5a)")));
  assert.ok(!JSON.stringify(r).includes(TOKEN));
});
// fill-array-data payloads must start on an even (4-byte aligned) code unit; re-point the fill instruction.
function fixPayload(code: number[]) {
  const at = code.indexOf(0x0300), fill = code.findIndex((u, i) => (u & 0xff) === 0x26 && i < at);
  if (at % 2) {code.splice(at, 0, 0x0000);}
  const target = code.indexOf(0x0300); code[fill + 1] = target - fill & 0xffff; code[fill + 2] = target - fill >>> 16; return code;
}
// ---- ELF builder: null, .dynsym, .dynstr, .dynamic, .rodata, .shstrtab ----
function buildElf(is64: boolean, opts: {rodata: string; imports: string[]; exports: string[]; needed: string[]}) {
  const dynstr: string[] = [""], sIdx = (s: string) => {const off = Buffer.from(dynstr.join("\0") + "\0").length; dynstr.push(s); return off;};
  const syms = [[0, 0, 0], ...opts.imports.map(n => [sIdx(n), 0x12, 0]), ...opts.exports.map(n => [sIdx(n), 0x12, 4])];
  const needed = opts.needed.map(sIdx), dynstrBuf = Buffer.from(dynstr.join("\0") + "\0");
  const symSize = is64 ? 24 : 16, symtab = Buffer.alloc(syms.length * symSize);
  syms.forEach(([name, info, shndx], i) => {const q = i * symSize; symtab.writeUInt32LE(name, q); if (is64) {symtab[q + 4] = info; symtab.writeUInt16LE(shndx, q + 6);} else {symtab[q + 12] = info; symtab.writeUInt16LE(shndx, q + 14);}});
  const dynSize = is64 ? 16 : 8, dynamic = Buffer.alloc((needed.length + 1) * dynSize);
  needed.forEach((v, i) => {if (is64) {dynamic.writeBigUInt64LE(1n, i * 16); dynamic.writeBigUInt64LE(BigInt(v), i * 16 + 8);} else {dynamic.writeUInt32LE(1, i * 8); dynamic.writeUInt32LE(v, i * 8 + 4);}});
  const rodata = Buffer.from(opts.rodata, "latin1"), names = ["", ".dynsym", ".dynstr", ".dynamic", ".rodata", ".shstrtab"], shstr = Buffer.from(names.join("\0") + "\0");
  const nameOff = names.map(n => n ? shstr.indexOf(Buffer.from(`\0${n}\0`)) + 1 : 0);
  const head = is64 ? 64 : 52, bodies = [Buffer.alloc(0), symtab, dynstrBuf, dynamic, rodata, shstr], offsets: number[] = []; let p = head;
  for (const body of bodies) {offsets.push(p); p += body.length; p += (8 - p % 8) % 8;}
  const shentsize = is64 ? 64 : 40, shoff = p, out = Buffer.alloc(shoff + shentsize * bodies.length);
  out.writeUInt32BE(0x7f454c46, 0); out[4] = is64 ? 2 : 1; out[5] = 1; out[6] = 1; out.writeUInt16LE(3, 16); out.writeUInt16LE(is64 ? 183 : 40, 18);
  if (is64) {out.writeBigUInt64LE(BigInt(shoff), 0x28); out.writeUInt16LE(64, 0x34); out.writeUInt16LE(shentsize, 0x3a); out.writeUInt16LE(bodies.length, 0x3c); out.writeUInt16LE(5, 0x3e);}
  else {out.writeUInt32LE(shoff, 0x20); out.writeUInt16LE(52, 0x28); out.writeUInt16LE(shentsize, 0x2e); out.writeUInt16LE(bodies.length, 0x30); out.writeUInt16LE(5, 0x32);}
  const types = [0, 11, 3, 6, 1, 3], links = [0, 2, 0, 2, 0, 0], flags = [0, 2, 2, 3, 2, 0];
  bodies.forEach((body, i) => {
    body.copy(out, offsets[i]); const q = shoff + i * shentsize; if (!i) return;
    out.writeUInt32LE(nameOff[i], q); out.writeUInt32LE(types[i], q + 4);
    if (is64) {out.writeBigUInt64LE(BigInt(flags[i]), q + 8); out.writeBigUInt64LE(BigInt(offsets[i]), q + 24); out.writeBigUInt64LE(BigInt(body.length), q + 32); out.writeUInt32LE(links[i], q + 40); out.writeBigUInt64LE(BigInt(i === 1 ? 24 : 0), q + 56);}
    else {out.writeUInt32LE(flags[i], q + 8); out.writeUInt32LE(offsets[i], q + 16); out.writeUInt32LE(body.length, q + 20); out.writeUInt32LE(links[i], q + 24); out.writeUInt32LE(i === 1 ? 16 : 0, q + 36);}
  });
  return out;
}
const elfSpec = {rodata: `\0init\0https://api.telegram.org/bot123456789:${TOKEN}/sendMessage?chat_id=-1001234567890\0TracerPid\0frida-server\0${Buffer.from("http://45.77.1.2/gate.php").toString("base64")}\0`, imports: ["ptrace", "strlen", "execve"], exports: ["Java_id_x_Native_send", "JNI_OnLoad"], needed: ["liblog.so", "libc.so"]};
test("ELF64/ELF32: dynsym imports/exports, DT_NEEDED, .rodata strings and hidden base64", () => {
  for (const is64 of [true, false]) {
    const e = parseElf(buildElf(is64, elfSpec), {deadline: Date.now() + 5000, keep: s => trackedString(s) || /\/\//.test(s)});
    assert.equal(e.bits, is64 ? 64 : 32); assert.equal(e.machine, is64 ? "arm64" : "arm"); assert.deepEqual(e.needed, ["liblog.so", "libc.so"]);
    assert.deepEqual(e.imports.sort(), ["execve", "ptrace"]); assert.deepEqual(e.jni, ["Java_id_x_Native_send"]); assert.equal(e.onLoad, true); assert.equal(e.exports, 2);
    assert.ok(e.strings.some(s => s.startsWith("https://api.telegram.org/bot123456789:"))); assert.ok(e.antiDebug.includes("TracerPid") && e.antiDebug.includes("frida-server"));
    assert.equal(e.hidden[0]?.value, "http://45.77.1.2/gate.php");
  }
});
test("APK native libraries: one scan per unique name (arm64 preferred), findings feed exfil rules with redaction", async () => {
  const zip = new AdmZip(); zip.addFile("AndroidManifest.xml", manifest([["manifest", {package: "id.x"}], ["uses-permission", {name: "android.permission.INTERNET"}], ...launcher]));
  zip.addFile("classes.dex", new Dex().cls("Lid/x/Native;", "Ljava/lang/Object;").build());
  zip.addFile("lib/armeabi-v7a/libnative.so", buildElf(false, {...elfSpec, needed: ["libarm32.so"]})); zip.addFile("lib/arm64-v8a/libnative.so", buildElf(true, elfSpec));
  zip.addFile("lib/arm64-v8a/libflutter.so", Buffer.alloc(1000)); zip.addFile("lib/arm64-v8a/libbroken.so", Buffer.from("\x7fELF\x02\x01\x01garbage"));
  const r = await extractFile(zip.toBuffer(), "x.apk"), libs = r.metadata.nativeLibraries as {name: string; abi: string; needed?: string[]; symbols?: string[]; jni?: string[]; skipped?: string; findings?: string[]}[];
  const lib = libs.find(l => l.name === "libnative.so")!; assert.equal(lib.abi, "arm64-v8a"); assert.deepEqual(lib.needed, ["liblog.so", "libc.so"]);
  assert.ok(lib.symbols?.includes("ptrace") && lib.jni?.includes("Java_id_x_Native_send")); assert.ok(lib.findings?.[0].includes("123456789:…Dsaw"));
  assert.equal(libs.filter(l => l.name === "libnative.so").length, 1); assert.equal(libs.find(l => l.name === "libflutter.so")?.skipped, "library framework/runtime");
  assert.match(libs.find(l => l.name === "libbroken.so")?.skipped || "", /gagal dibaca/);
  const b = behaviorsOf(r); assert.ok(b.find(x => x.id === "exfil_telegram")?.evidence.some(e => e.includes("native libnative.so:")));
  assert.ok(b.some(x => x.id === "native_anti_analysis")); assert.ok(b.find(x => x.id === "exfil_panel")?.evidence.some(e => e.includes("disamarkan: base64")));
  assert.deepEqual((r.metadata.campaign as {chatIds: string[]}).chatIds, ["-1001234567890"]); assert.ok(!JSON.stringify(r).includes(TOKEN)); assert.equal(r.incomplete, false);
});
test("packer detection: known stub (Jiagu) and unknown stub-only DEX next to an encrypted blob", async () => {
  const comps = ["Login", "Otp", "Home", "Upload", "Sync"].map(n => ["activity", {name: `id.bank.palsu.${n}`}] as [string, Record<string, string>]);
  const noise = Buffer.alloc(200000); for (let i = 0; i < noise.length; i++) noise[i] = (i * 2654435761 >>> 13) ^ (i * 40503 >>> 7) & 0xff;
  const make = (application: string, files: [string, Buffer][], stub: Dex) => {const z = new AdmZip(); z.addFile("AndroidManifest.xml", manifest([["manifest", {package: "id.bank.palsu"}], ["application", {name: application}], ...comps])); z.addFile("classes.dex", stub.build()); for (const [n, b] of files) z.addFile(n, b); return z.toBuffer();};
  const jiagu = await extractFile(make("com.stub.StubApp", [["lib/arm64-v8a/libjiagu_a64.so", Buffer.from("\x7fELFnot-really")], ["assets/libjiagu.so", noise]], new Dex().cls("Lcom/stub/StubApp;", "Landroid/app/Application;")), "bank.apk");
  const ind = jiagu.indicators.find(i => i.name.startsWith("Aplikasi dibungkus pelindung/packer ("))!; assert.equal(ind.name, "Aplikasi dibungkus pelindung/packer (Jiagu (Qihoo 360))");
  assert.match(ind.evidence, /kelas stub com\.stub\.StubApp|application com\.stub\.StubApp/); assert.match(ind.evidence, /DEX hanya stub: 5\/5/);
  assert.ok(jiagu.limitations.some(l => l.startsWith("Aplikasi dibungkus packer/pelindung (Jiagu"))); assert.equal(jiagu.incomplete, false);
  assert.equal((jiagu.metadata.packer as {stubOnly: boolean}).stubOnly, true);
  const loader = new Dex(); loader.cls("Lid/bank/palsu/Loader;", "Landroid/app/Application;", [{name: "attachBaseContext", code: [...I.invoke(0x70, loader.m("Ldalvik/system/DexClassLoader;", "<init>"), [0]), ...I.ret()]}]);
  const unknown = await extractFile(make("id.bank.palsu.Loader", [["assets/data.bin", noise]], loader), "bank2.apk");
  assert.ok(unknown.indicators.some(i => i.name === "Aplikasi dibungkus pelindung/packer (tidak dikenal)"));
  // A normal app whose components are all present is not flagged.
  const full = new Dex(); for (const n of ["Login", "Otp", "Home", "Upload", "Sync", "App"]) full.cls(`Lid/bank/palsu/${n};`, "Landroid/app/Activity;");
  const normal = await extractFile(make("id.bank.palsu.App", [], full), "bank3.apk"); assert.ok(!normal.indicators.some(i => i.name.startsWith("Aplikasi dibungkus")));
});
// ---- APK Signature Scheme v2/v3 builder (real signatures over a real content digest) ----
const lp = (...parts: Buffer[]) => {const body = Buffer.concat(parts), h = Buffer.alloc(4); h.writeUInt32LE(body.length); return Buffer.concat([h, body]);};
const u32 = (n: number) => {const b = Buffer.alloc(4); b.writeUInt32LE(n); return b;};
function derLen(n: number) {return n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]);}
const der = (tag: number, ...parts: Buffer[]) => {const body = Buffer.concat(parts); return Buffer.concat([Buffer.from([tag]), derLen(body.length), body]);};
function selfSigned(pub: KeyObject, priv: KeyObject, ec: boolean) {
  const oid = (hex: string) => der(0x06, Buffer.from(hex, "hex")), alg = ec ? der(0x30, oid("2a8648ce3d040302")) : der(0x30, oid("2a864886f70d01010b"), der(0x05));
  const name = der(0x30, der(0x31, der(0x30, oid("550403"), der(0x0c, Buffer.from("Kheronyx Test")))));
  const tbs = der(0x30, der(0xa0, der(0x02, Buffer.from([2]))), der(0x02, Buffer.from([1])), alg, name, der(0x30, der(0x17, Buffer.from("250101000000Z")), der(0x17, Buffer.from("350101000000Z"))), name, pub.export({type: "spki", format: "der"}));
  return der(0x30, tbs, alg, der(0x03, Buffer.concat([Buffer.from([0]), sign("sha256", tbs, priv)])));
}
// Independent implementation of the v2 chunked SHA-256 digest (sections 1, 3, 4; EOCD CD offset = signing block offset).
function chunked(zip: Buffer) {
  const {offset, end} = zipDirectory(zip), eocd = Buffer.from(zip.subarray(end)); eocd.writeUInt32LE(offset, 16);
  const digests: Buffer[] = [];
  for (const s of [zip.subarray(0, offset), zip.subarray(offset, end), eocd]) for (let p = 0; p < s.length; p += 1 << 20) {const c = s.subarray(p, p + (1 << 20)), h = Buffer.alloc(5); h[0] = 0xa5; h.writeUInt32LE(c.length, 1); digests.push(createHash("sha256").update(h).update(c).digest());}
  const h = Buffer.alloc(5); h[0] = 0x5a; h.writeUInt32LE(digests.length, 1); return createHash("sha256").update(h).update(Buffer.concat(digests)).digest();
}
function signApk(zip: Buffer, scheme: "v2" | "v3", ec: boolean) {
  const {publicKey, privateKey} = ec ? generateKeyPairSync("ec", {namedCurve: "P-256"}) : generateKeyPairSync("rsa", {modulusLength: 2048});
  const alg = ec ? 0x0201 : 0x0103, cert = selfSigned(publicKey, privateKey, ec), sdk = scheme === "v3" ? Buffer.concat([u32(24), u32(0x7fffffff)]) : Buffer.alloc(0);
  const signed = Buffer.concat([lp(lp(u32(alg), lp(chunked(zip)))), lp(lp(cert)), sdk, lp()]);
  const signer = lp(lp(signed), sdk, lp(lp(u32(alg), lp(sign("sha256", signed, privateKey)))), lp(publicKey.export({type: "spki", format: "der"})));
  const value = lp(signer), pair = Buffer.alloc(12); pair.writeBigUInt64LE(BigInt(value.length + 4)); pair.writeUInt32LE(scheme === "v2" ? 0x7109871a : 0xf05368c0, 8);
  const pairs = Buffer.concat([pair, value]), size = BigInt(pairs.length + 8 + 16), s1 = Buffer.alloc(8); s1.writeBigUInt64LE(size);
  const block = Buffer.concat([s1, pairs, s1, Buffer.from("APK Sig Block 42", "latin1")]), {offset, end} = zipDirectory(zip);
  const out = Buffer.concat([zip.subarray(0, offset), block, zip.subarray(offset)]); out.writeUInt32LE(offset + block.length, end + block.length + 16); return out;
}
function plainApk() {
  const z = new AdmZip(); z.addFile("AndroidManifest.xml", manifest([["manifest", {package: "id.sah"}], ...launcher])); z.addFile("classes.dex", new Dex().cls("Lid/app/Main;", "Landroid/app/Activity;", [{name: "a", code: I.ret()}]).build());
  z.addFile("assets/big.txt", Buffer.alloc(2_500_000, "kheronyx ")); return z.toBuffer();
}
test("APK Signature Scheme v2 (RSA) and v3 (ECDSA) verify; tampered content or signature fails", async () => {
  for (const [scheme, ec] of [["v2", false], ["v3", true]] as const) {
    const apk = signApk(plainApk(), scheme, ec), ok = apkSigning(apk, readZip(apk));
    assert.equal(ok.verified, true, ok.verification?.join("; ")); assert.deepEqual(ok.schemes, [scheme]);
    const r = await extractFile(apk, "sah.apk"); assert.equal((r.metadata.signing as {verified: boolean}).verified, true); assert.ok(!r.indicators.some(i => i.name.startsWith("Tanda tangan APK tidak valid")));
    const content = Buffer.from(apk); content[100] ^= 1; // inside the first local entry → content digest mismatch
    const bad = await extractFile(content, "ubah.apk"); assert.equal((bad.metadata.signing as {verified: boolean}).verified, false);
    const ind = bad.indicators.find(i => i.name === "Tanda tangan APK tidak valid (kemungkinan dimodifikasi/repackaged)")!; assert.match(ind.evidence, /digest isi APK TIDAK cocok/);
    const sigBroken = Buffer.from(apk), at = sigBroken.indexOf(Buffer.from("APK Sig Block 42")) - 40; sigBroken[at] ^= 0xff; // last bytes of the public key / signature area
    assert.equal(apkSigning(sigBroken, readZip(sigBroken)).verified, false);
  }
  // Time budget exceeded: digest skipped, no false "invalid" claim.
  const apk = signApk(plainApk(), "v2", false), late = apkSigning(apk, readZip(apk), Date.now() - 1);
  assert.equal(late.verified, null); assert.match(late.verification!.join(" "), /batas waktu/);
});
test("hostile bytecode and ELF never throw out of extractFile and stay fast", async () => {
  const {dex} = stealerDex(); let seed = 11; const rnd = () => (seed = seed * 1103515245 + 12345 & 0x7fffffff) / 0x7fffffff;
  const codeStart = dex.indexOf(Buffer.from([0x10, 0x00]), 0x70), started = Date.now();
  for (let i = 0; i < 300; i++) {
    const b = Buffer.from(dex); for (let k = 0; k < 6; k++) b[codeStart + Math.floor(rnd() * (b.length - codeStart))] = Math.floor(rnd() * 256);
    try {const d = parseDex(b, Date.now() + 2000, opts()); assert.ok(d.code);} catch (e) {assert.ok(e instanceof Error);}
  }
  // Amplification: every class_def points at one class_data whose methods all share a huge code item.
  const amp = new Dex(), big = Array.from({length: 60000}, () => 0x0000); amp.cls("La/A0;", "Ljava/lang/Object;", [{name: "m", code: big}]);
  for (let i = 1; i < 3000; i++) amp.cls(`La/A${i};`, "Ljava/lang/Object;");
  const ab = amp.build(), q0 = ab.readUInt32LE(0x64), data0 = ab.readUInt32LE(q0 + 24); for (let i = 1; i < 3000; i++) ab.writeUInt32LE(data0, q0 + i * 32 + 24);
  const t = Date.now(), ad = parseDex(ab, Date.now() + 5000, opts()); assert.ok(Date.now() - t < 2000); assert.equal(ad.code!.complete, false); assert.equal(ad.code!.reason, "batas instruksi");
  const elf = buildElf(true, elfSpec), zip = new AdmZip(); zip.addFile("AndroidManifest.xml", manifest([["manifest", {package: "id.x"}], ...launcher]));
  for (let i = 0; i < 40; i++) {const b = Buffer.from(elf); for (let k = 0; k < 8; k++) b[Math.floor(rnd() * (i % 2 ? 64 : b.length))] = Math.floor(rnd() * 256); zip.addFile(`lib/arm64-v8a/libx${i}.so`, b);}
  for (let i = 0; i < 20; i++) {const b = Buffer.from(dex); for (let k = 0; k < 10; k++) b[codeStart + Math.floor(rnd() * (b.length - codeStart))] = Math.floor(rnd() * 256); zip.addFile(i ? `classes${i + 1}.dex` : "classes.dex", b);}
  const r = await extractFile(zip.toBuffer(), "rusak.apk"); assert.ok(r.limitations.length); assert.ok(Date.now() - started < 15000, `${Date.now() - started} ms`);
});
test("large synthetic APK: many DEX files with real code and several .so stay within budget and AI evidence bound", async () => {
  const zip = new AdmZip(), sms = ["createFromPdu", "getMessageBody"], strings: string[] = [];
  for (let i = 0; i < 300; i++) strings.push(`https://api.telegram.org/bot${100000000 + i}:${TOKEN}/send${"x".repeat(80)}`, `Undangan pernikahan tagihan PLN kode OTP ${i} ${"y".repeat(100)}`);
  zip.addFile("AndroidManifest.xml", manifest([["manifest", {package: "id.besar"}], ["uses-permission", {name: "android.permission.RECEIVE_SMS"}], ...launcher, ...Array.from({length: 80}, (_, i) => ["receiver", {name: `id.besar.R${i}`, permission: "android.permission.BIND_DEVICE_ADMIN"}] as [string, Record<string, string>])]));
  for (let n = 0; n < 12; n++) {
    const d = new Dex(); strings.forEach(s => d.s(s));
    const refs = sms.map(m => d.m("Landroid/telephony/SmsMessage;", m)).concat(d.m("Ljava/net/URL;", "openConnection"), d.m("Ldalvik/system/DexClassLoader;", "<init>"), d.m("Ljava/lang/Runtime;", "exec"));
    for (let c = 0; c < 400; c++) d.cls(`L${c % 3 ? "id/besar" : "androidx/lib"}/C${n}_${c};`, c % 50 ? "Ljava/lang/Object;" : "Landroid/accessibilityservice/AccessibilityService;", Array.from({length: 10}, (_, k) => ({name: `m${k}`, code: [...I.const16(0, k), ...I.str(1, (c * 10 + k) % 600), ...I.invoke(0x71, refs[(c + k) % refs.length], [0, 1]), ...I.result(2), ...I.xor8(3, 3, 7), ...Array.from({length: 40}, () => 0x0001 | k << 8), ...I.ret()]})));
    zip.addFile(n ? `classes${n + 1}.dex` : "classes.dex", d.build());
  }
  for (let i = 0; i < 4; i++) zip.addFile(`lib/arm64-v8a/libbig${i}.so`, buildElf(true, {...elfSpec, rodata: elfSpec.rodata + "z".repeat(3_000_000)}));
  const started = Date.now(), r = await extractFile(zip.toBuffer(), "besar.apk"), ms = Date.now() - started, scan = r.metadata.dexScan as {code: {methods: number; complete: boolean}};
  assert.equal(scan.code.methods, 12 * 4000); assert.equal(scan.code.complete, true); assert.ok(ms < 20000, `${ms} ms`);
  assert.ok(JSON.stringify({...r, strings: r.strings.slice(0, 180), urls: r.urls.slice(0, 40)}).length < 110000);
  assert.ok(!JSON.stringify(r).includes(TOKEN));
});
test("mangled Telegram bot ids never leak the token secret (DEX strings, deobfuscated values, native .rodata)", async () => {
  const mangled = [`https://api.telegram.org/bot12345:${TOKEN}/send`, `bot:${TOKEN}`, `x9a8b7:${TOKEN}`];
  const d = new Dex(); mangled.forEach(s => d.s(s)); d.s([...mangled[0]].reverse().join("")); d.s(Buffer.from(mangled[1]).toString("base64"));
  d.cls("Lid/x/A;", "Ljava/lang/Object;", [{name: "a", code: I.ret()}]);
  const zip = new AdmZip(); zip.addFile("AndroidManifest.xml", manifest([["manifest", {package: "id.x"}], ...launcher])); zip.addFile("classes.dex", d.build());
  zip.addFile("lib/arm64-v8a/libz.so", buildElf(true, {...elfSpec, rodata: `\0${mangled.join("\0")}\0`})); zip.addFile("assets/raw.txt", Buffer.from(mangled.join("\n")));
  const r = await extractFile(zip.toBuffer(), "bocor.apk"); assert.ok(!JSON.stringify(r).includes(TOKEN.slice(2)), "secret leaked");
});
