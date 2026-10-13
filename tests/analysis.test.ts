import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { deflateSync } from "node:zlib";
import AdmZip from "adm-zip";
import { extractFile } from "../lib/extract";
import { parseDex } from "../lib/dex";
import { pkcs7, certInfo } from "../lib/certs";
import { signingBlock, signingIndicators } from "../lib/apk-signing";
import { redactSecrets } from "../lib/behaviors";
import { zipDirectory } from "../lib/zip";

// ---- fixture builders (hand-built binary formats, no external tools) ----
function mutf8(s: string) {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {const c = s.charCodeAt(i); if (c && c < 0x80) out.push(c); else if (c < 0x800) out.push(0xc0 | c >> 6, 0x80 | c & 0x3f); else out.push(0xe0 | c >> 12, 0x80 | c >> 6 & 0x3f, 0x80 | c & 0x3f);}
  return out;
}
const uleb = (n: number) => {const out: number[] = []; do {let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; out.push(b);} while (n); return out;};
type DexSpec = {strings?: string[]; methods?: [string, string][]; fields?: [string, string][]; classes?: [string, string][]};
function buildDex(spec: DexSpec) {
  const types = [...new Set([...(spec.methods || []), ...(spec.fields || [])].map(([c]) => c).concat((spec.classes || []).flat()))];
  const strings = [...new Set([...(spec.strings || []), ...types, ...(spec.methods || []).map(([, n]) => n), ...(spec.fields || []).map(([, n]) => n)])];
  const si = (s: string) => strings.indexOf(s), ti = (t: string) => types.indexOf(t);
  const nm = spec.methods?.length || 0, nf = spec.fields?.length || 0, nc = spec.classes?.length || 0;
  const oStr = 0x70, oType = oStr + strings.length * 4, oField = oType + types.length * 4, oMethod = oField + nf * 8, oClass = oMethod + nm * 8, oData = oClass + nc * 32;
  const data: number[] = [], offsets: number[] = [];
  for (const s of strings) {offsets.push(oData + data.length); data.push(...uleb(s.length), ...mutf8(s), 0);}
  const b = Buffer.alloc(oData + data.length);
  b.write("dex\n035\0", 0, "latin1"); b.writeUInt32LE(b.length, 0x20); b.writeUInt32LE(0x70, 0x24); b.writeUInt32LE(0x12345678, 0x28);
  b.writeUInt32LE(strings.length, 0x38); b.writeUInt32LE(oStr, 0x3c); b.writeUInt32LE(types.length, 0x40); b.writeUInt32LE(oType, 0x44);
  b.writeUInt32LE(nf, 0x50); b.writeUInt32LE(oField, 0x54); b.writeUInt32LE(nm, 0x58); b.writeUInt32LE(oMethod, 0x5c); b.writeUInt32LE(nc, 0x60); b.writeUInt32LE(oClass, 0x64);
  offsets.forEach((o, i) => b.writeUInt32LE(o, oStr + i * 4)); types.forEach((t, i) => b.writeUInt32LE(si(t), oType + i * 4));
  (spec.fields || []).forEach(([c, n], i) => {b.writeUInt16LE(ti(c), oField + i * 8); b.writeUInt32LE(si(n), oField + i * 8 + 4);});
  (spec.methods || []).forEach(([c, n], i) => {b.writeUInt16LE(ti(c), oMethod + i * 8); b.writeUInt32LE(si(n), oMethod + i * 8 + 4);});
  (spec.classes || []).forEach(([c, s], i) => {const q = oClass + i * 32; b.writeUInt32LE(ti(c), q); b.writeUInt32LE(ti(s), q + 8); b.writeUInt32LE(0xffffffff, q + 12); b.writeUInt32LE(0xffffffff, q + 16);});
  Buffer.from(data).copy(b, oData); return b;
}
// Minimal Android binary XML (UTF-8 string pool + start-element chunks with raw string attribute values).
function buildManifest(elements: [string, Record<string, string>][]) {
  const strings: string[] = []; const idx = (s: string) => {let i = strings.indexOf(s); if (i < 0) {strings.push(s); i = strings.length - 1;} return i;};
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
const lp = (...parts: Buffer[]) => {const body = Buffer.concat(parts), h = Buffer.alloc(4); h.writeUInt32LE(body.length); return Buffer.concat([h, body]);};
// Inserts an APK Signing Block (v2 pair with one signer/certificate) before the central directory.
function withV2Block(zip: Buffer, cert: Buffer) {
  const signer = lp(lp(lp(), lp(lp(cert)), lp()), lp(), lp()), value = lp(signer);
  const pair = Buffer.alloc(12); pair.writeBigUInt64LE(BigInt(value.length + 4)); pair.writeUInt32LE(0x7109871a, 8);
  const pairs = Buffer.concat([pair, value]), size = BigInt(pairs.length + 8 + 16), s1 = Buffer.alloc(8), s2 = Buffer.alloc(8); s1.writeBigUInt64LE(size); s2.writeBigUInt64LE(size);
  const block = Buffer.concat([s1, pairs, s2, Buffer.from("APK Sig Block 42", "latin1")]), {offset, end} = zipDirectory(zip);
  const out = Buffer.concat([zip.subarray(0, offset), block, zip.subarray(offset)]); out.writeUInt32LE(offset + block.length, end + block.length + 16); return out;
}
const debugCert = readFileSync(new URL("./fixtures/android-debug-cert.der", import.meta.url));
const TOKEN = "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw";
function stealerApk() {
  const zip = new AdmZip();
  zip.addFile("AndroidManifest.xml", buildManifest([
    ["manifest", {package: "id.undangan.digital"}],
    ["uses-permission", {name: "android.permission.RECEIVE_SMS"}], ["uses-permission", {name: "android.permission.READ_SMS"}],
    ["uses-permission", {name: "android.permission.SEND_SMS"}], ["uses-permission", {name: "android.permission.INTERNET"}],
    ["application", {name: "id.undangan.digital.App"}], ["activity", {name: "id.undangan.digital.Main"}],
    ["receiver", {name: "id.undangan.digital.SmsReceiver", permission: "android.permission.BROADCAST_SMS", exported: "true"}],
    ["intent-filter", {}], ["action", {name: "android.provider.Telephony.SMS_RECEIVED"}],
  ]));
  zip.addFile("classes.dex", buildDex({
    strings: [`https://api.telegram.org/bot123456789:${TOKEN}/sendMessage?chat_id=-1001234567890&text=`, "Undangan Pernikahan Digital", "Masukkan kode OTP anda untuk melanjutkan"],
    methods: [["Landroid/telephony/SmsMessage;", "createFromPdu"], ["Landroid/telephony/SmsMessage;", "getMessageBody"], ["Landroid/content/pm/PackageManager;", "setComponentEnabledSetting"]],
    classes: [["Lid/undangan/digital/SmsReceiver;", "Landroid/content/BroadcastReceiver;"]],
  }));
  // Second DEX proves classesN.dex beyond the first files is parsed too.
  zip.addFile("classes2.dex", buildDex({methods: [["Landroid/telephony/SmsManager;", "sendTextMessage"]]}));
  return withV2Block(zip.toBuffer(), debugCert);
}

// ---- tests ----
test("DEX tables: strings (incl. MUTF-8), types, field/method refs and class hierarchy", () => {
  const dex = parseDex(buildDex({strings: ["héllo wörld", "emoji 💍 ok", "\u0000nul"], methods: [["Landroid/telephony/SmsManager;", "sendTextMessage"]], fields: [["Landroid/provider/Telephony$Sms;", "CONTENT_URI"]], classes: [["Lcom/x/A11y;", "Landroid/accessibilityservice/AccessibilityService;"]]}));
  assert.ok(dex.strings.includes("héllo wörld") && dex.strings.includes("emoji 💍 ok") && dex.strings.includes("\u0000nul"));
  assert.deepEqual(dex.methods, ["Landroid/telephony/SmsManager;->sendTextMessage"]);
  assert.deepEqual(dex.fields, ["Landroid/provider/Telephony$Sms;->CONTENT_URI"]);
  assert.deepEqual(dex.classes, [{name: "Lcom/x/A11y;", superclass: "Landroid/accessibilityservice/AccessibilityService;"}]);
});
test("DEX parser rejects hostile headers quickly and survives random corruption", () => {
  const good = buildDex({strings: ["a string", "another"], methods: [["La/B;", "c"]], classes: [["La/B;", "Ljava/lang/Object;"]]});
  for (const [at, value] of [[0x38, 0xffffffff], [0x3c, 0x7ffffff0], [0x58, 70000], [0x20, 0xfffffff0]] as const) {const b = Buffer.from(good); b.writeUInt32LE(value, at); assert.throws(() => parseDex(b));}
  assert.throws(() => parseDex(good.subarray(0, 0x60))); assert.throws(() => parseDex(Buffer.from("not a dex file at all, definitely not")));
  // One string offset pointing at an endless uleb128 / out of bounds.
  const bad = Buffer.from(good); bad.writeUInt32LE(bad.length - 1, 0x70); bad[bad.length - 1] = 0xff; assert.throws(() => parseDex(bad));
  let seed = 7; const rnd = () => (seed = seed * 1103515245 + 12345 & 0x7fffffff) / 0x7fffffff; const started = Date.now();
  for (let i = 0; i < 400; i++) {const b = Buffer.from(good); for (let k = 0; k < 4; k++) b[Math.floor(rnd() * b.length)] = Math.floor(rnd() * 256); try {parseDex(b);} catch {}}
  assert.ok(Date.now() - started < 3000);
});
test("SMS stealer APK: behaviors, combo indicator, Telegram token redaction, all DEX files and v2 certificate", async () => {
  const result = await extractFile(stealerApk(), "undangan-pernikahan.apk"), json = JSON.stringify(result);
  const behaviors = result.metadata.behaviors as {id: string; severity: string; evidence: string[]}[], by = (id: string) => behaviors.find(b => b.id === id);
  assert.equal(by("sms_read")?.severity, "high"); assert.equal(by("sms_send")?.severity, "high");
  assert.ok(by("exfil_telegram")); assert.ok(by("otp_intercept")); assert.ok(by("hidden_icon")); assert.ok(by("lure_keywords"));
  assert.equal(by("sms_stealer")?.severity, "critical"); assert.equal(behaviors[0].id, "sms_stealer");
  assert.ok(result.indicators.some(i => i.name.startsWith("Pola pencuri SMS") && i.evidence.includes("80123f99")));
  assert.ok(!json.includes(TOKEN), "bot token secret must never leave the extractor"); assert.ok(json.includes("123456789:…Dsaw"));
  assert.deepEqual((result.metadata.campaign as {chatIds: string[]}).chatIds, ["-1001234567890"]);
  assert.equal((result.metadata.dexFiles as unknown[]).length, 2);
  const signing = result.metadata.signing as {schemes: string[]; certificates: {sha256: string; subject: string}[]};
  assert.deepEqual(signing.schemes, ["v2"]); assert.match(signing.certificates[0].sha256, /^80123f991de211b5/); assert.match(signing.certificates[0].subject, /CN=Android Debug/);
  assert.ok(result.indicators.some(i => i.name === "Ditandatangani sertifikat debug Android"));
  assert.equal(result.incomplete, false); assert.ok(json.length < 120000);
});
test("fake ZIP encryption flags (anti-analysis) do not blind the analyzer", async () => {
  const apk = stealerApk(), {offset, count} = zipDirectory(apk);
  for (let i = 0, p = offset; i < count; i++) {apk.writeUInt16LE(apk.readUInt16LE(p + 8) | 1, p + 8); p += 46 + apk.readUInt16LE(p + 28) + apk.readUInt16LE(p + 30) + apk.readUInt16LE(p + 32);}
  const result = await extractFile(apk, "paket.apk");
  assert.equal(result.incomplete, false); assert.ok(result.indicators.some(i => i.name.startsWith("Header ZIP dimanipulasi")));
  assert.ok((result.metadata.behaviors as {id: string}[]).some(b => b.id === "sms_stealer"));
});
test("AI evidence stays bounded for a sample that trips nearly every rule", async () => {
  const methods: [string, string][] = [["Landroid/telephony/SmsManager;", "sendTextMessage"], ["Landroid/telephony/SmsMessage;", "createFromPdu"], ["Landroid/accessibilityservice/AccessibilityService;", "performGlobalAction"], ["Landroid/provider/Settings;", "canDrawOverlays"], ["Landroid/app/admin/DevicePolicyManager;", "lockNow"], ["Ldalvik/system/DexClassLoader;", "<init>"], ["Landroid/media/projection/MediaProjectionManager;", "createScreenCaptureIntent"], ["Landroid/telephony/TelephonyManager;", "getLine1Number"], ["Landroid/telephony/TelephonyManager;", "sendUssdRequest"], ["Ljava/lang/Runtime;", "exec"]];
  const strings = Array.from({length: 600}, (_, i) => `${["https://api.telegram.org/bot", "http://103.10.20.", "https://panel-", "Undangan pernikahan tagihan PLN BPJS kurir paket resi kode OTP "][i % 4]}${i}${"x".repeat(150)}${i % 4 === 2 ? ".ngrok.io/gate.php" : ""}`);
  const zip = new AdmZip(), perms = ["RECEIVE_SMS", "READ_SMS", "SEND_SMS", "INTERNET", "SYSTEM_ALERT_WINDOW", "READ_CONTACTS", "READ_CALL_LOG", "CALL_PHONE", "RECEIVE_BOOT_COMPLETED", "REQUEST_INSTALL_PACKAGES", "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION"];
  zip.addFile("AndroidManifest.xml", buildManifest([["manifest", {package: "x.y"}], ...perms.map(p => ["uses-permission", {name: `android.permission.${p}`}] as [string, Record<string, string>]), ...Array.from({length: 60}, (_, i) => ["receiver", {name: `x.y.R${i}${"z".repeat(100)}`, exported: "true", permission: "android.permission.BIND_DEVICE_ADMIN"}] as [string, Record<string, string>]), ["service", {name: "x.y.A", permission: "android.permission.BIND_ACCESSIBILITY_SERVICE"}]]));
  for (let i = 0; i < 50; i++) zip.addFile(i ? `classes${i + 1}.dex` : "classes.dex", buildDex({strings, methods, classes: [[`Lx/y/N${i};`, "Landroid/service/notification/NotificationListenerService;"]]}));
  const result = await extractFile(zip.toBuffer(), "semua.apk");
  assert.ok((result.metadata.behaviors as unknown[]).length >= 20);
  assert.ok(JSON.stringify({...result, strings: result.strings.slice(0, 180), urls: result.urls.slice(0, 40)}).length < 110000);
});
test("hidden DEX payloads in assets (raw and inside a JAR) are reported and scanned", async () => {
  const zip = new AdmZip(), jar = new AdmZip(), loader = buildDex({methods: [["Ldalvik/system/DexClassLoader;", "<init>"]]});
  jar.addFile("classes.dex", buildDex({methods: [["Landroid/telephony/SmsManager;", "sendTextMessage"]]}));
  zip.addFile("AndroidManifest.xml", buildManifest([["manifest", {package: "a.b"}], ["activity", {name: "a.b.Main"}], ["action", {name: "android.intent.action.MAIN"}], ["category", {name: "android.intent.category.LAUNCHER"}]]));
  zip.addFile("classes.dex", loader); zip.addFile("assets/update.bin", buildDex({strings: ["http://45.77.10.20/panel/gate.php"]})); zip.addFile("assets/core.jar", jar.toBuffer());
  const result = await extractFile(zip.toBuffer(), "kurir.apk"), payloads = result.metadata.hiddenPayloads as {name: string; kind: string; dex: number}[];
  assert.deepEqual(payloads.map(p => [p.name, p.dex]).sort(), [["assets/core.jar", 1], ["assets/update.bin", 1]]);
  const ids = (result.metadata.behaviors as {id: string; severity: string}[]).map(b => `${b.id}:${b.severity}`);
  for (const id of ["hidden_payload:high", "dynamic_code:high", "sms_send:medium", "exfil_ip:medium", "exfil_panel:medium"]) assert.ok(ids.includes(id), id);
  assert.ok(!ids.some(i => i.startsWith("hidden_icon")));
  assert.ok(result.indicators.some(i => i.name === "APK tidak bertanda tangan"));
});
test("PKCS#7 (v1 META-INF) certificates and signing heuristics", () => {
  const {certs} = pkcs7(readFileSync(new URL("./fixtures/android-debug-cert.p7b", import.meta.url)));
  const info = certInfo(certs[0]); assert.match(info.sha256, /^80123f99/); assert.equal(info.selfSigned, true); assert.equal(info.key, "rsa-2048");
  const names = signingIndicators({schemes: ["v1"], certificates: [info], errors: []}, Date.parse(info.validFrom) + 86400000).map(i => i.name);
  assert.deepEqual(names, ["Ditandatangani sertifikat debug Android", "Sertifikat penanda tangan sangat baru"]);
  assert.throws(() => pkcs7(Buffer.from([0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x06])));
  // A signing block whose size field lies must throw, never read out of bounds.
  const b = Buffer.alloc(64); b.write("APK Sig Block 42", 48, "latin1"); b.writeBigUInt64LE(10n ** 12n, 40); assert.throws(() => signingBlock(b, 64));
});
function buildPe(plus: boolean, imports: [string, string[]][]) {
  const optSize = plus ? 240 : 224, opt = 0x40 + 24, sec = opt + optSize, raw = 0x200, va = 0x1000, b = Buffer.alloc(0x600);
  b.write("MZ", 0, "latin1"); b.writeUInt32LE(0x40, 60); b.write("PE\0\0", 0x40, "latin1"); b.writeUInt16LE(plus ? 0x8664 : 0x14c, 0x44); b.writeUInt16LE(1, 0x46); b.writeUInt16LE(optSize, 0x54);
  b.writeUInt16LE(plus ? 0x20b : 0x10b, opt); b.writeUInt32LE(0x200, opt + 60); b.writeUInt32LE(16, opt + (plus ? 108 : 92));
  b.write(".idata", sec, "latin1"); b.writeUInt32LE(0x400, sec + 8); b.writeUInt32LE(va, sec + 12); b.writeUInt32LE(0x400, sec + 16); b.writeUInt32LE(raw, sec + 20); b.writeUInt32LE(0xc0000040, sec + 36);
  const width = plus ? 8 : 4; let cursor = (imports.length + 1) * 20; const rva = (o: number) => va + o, at = (o: number) => raw + o;
  imports.forEach(([dll, fns], i) => {
    const ilt = cursor; cursor += (fns.length + 1) * width; const name = cursor; b.write(`${dll}\0`, at(name), "latin1"); cursor += dll.length + 2;
    fns.forEach((f, j) => {
      const slot = at(ilt + j * width);
      if (f.startsWith("#")) {if (plus) {b.writeUInt32LE(Number(f.slice(1)), slot); b.writeUInt32LE(0x80000000, slot + 4);} else b.writeUInt32LE(0x80000000 + Number(f.slice(1)), slot);}
      else {b.writeUInt32LE(rva(cursor), slot); b.write(`\0\0${f}\0`, at(cursor), "latin1"); cursor += f.length + 4;}
    });
    b.writeUInt32LE(rva(ilt), at(i * 20)); b.writeUInt32LE(rva(name), at(i * 20 + 12)); b.writeUInt32LE(rva(ilt), at(i * 20 + 16));
  });
  b.writeUInt32LE(va, opt + (plus ? 112 : 96) + 8); b.writeUInt32LE((imports.length + 1) * 20, opt + (plus ? 112 : 96) + 12); return b;
}
test("PE32 and PE32+ import tables are parsed into functions and suspicious API groups", async () => {
  for (const plus of [false, true]) {
    const result = await extractFile(buildPe(plus, [["KERNEL32.dll", ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "#5"]], ["USER32.dll", ["SetWindowsHookExA", "GetAsyncKeyState"]]]), "tool.exe");
    assert.equal(result.incomplete, false);
    assert.deepEqual(result.metadata.importedLibraries, ["kernel32.dll", "user32.dll"]); assert.equal(result.metadata.importCount, 6);
    const k32 = (result.metadata.imports as {dll: string; functions: string[]}[])[0]; assert.deepEqual([...k32.functions].sort(), ["#5", "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"]);
    const names = result.indicators.map(i => i.name); assert.ok(names.includes("Injeksi kode ke proses lain")); assert.ok(names.includes("Perekaman ketikan (keylogger)"));
    assert.ok(result.indicators.find(i => i.name === "Injeksi kode ke proses lain")!.evidence.includes("kernel32.dll!VirtualAllocEx"));
  }
});
test("malformed and truncated inputs never throw out of extractFile", async () => {
  const pe = buildPe(false, [["KERNEL32.dll", ["ExitProcess"]]]);
  const loop = Buffer.from(pe); loop.writeUInt32LE(0x1000, 0x200); // ILT pointing back into the descriptor table
  const zip = new AdmZip(); zip.addFile("AndroidManifest.xml", Buffer.from("x")); zip.addFile("classes.dex", Buffer.concat([Buffer.from("dex\n035\0"), Buffer.alloc(200, 0xff)])); zip.addFile("classes3.dex", Buffer.alloc(10)); zip.addFile("assets/a.jar", Buffer.from("PK\x03\x04broken"));
  for (const [buffer, name] of [[pe.subarray(0, 0x300), "cut.exe"], [loop, "loop.exe"], [zip.toBuffer(), "broken.apk"], [Buffer.concat([Buffer.from("PK\x03\x04"), Buffer.alloc(100)]), "junk.apk"], [Buffer.from("%PDF-1.4\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >> endobj\n%%EOF"), "x.pdf"]] as [Buffer, string][]) {
    const result = await extractFile(buffer, name); assert.ok(result.limitations.length);
  }
  const broken = await extractFile(zip.toBuffer(), "broken.apk"); assert.equal(broken.incomplete, true); assert.ok(broken.limitations.some(l => l.includes("classes.dex")));
});
test("PDF actions are reported with object context, including inside compressed object streams", async () => {
  const hidden = deflateSync(Buffer.from("7 0 << /Type /Action /S /Launch /F (cmd.exe) /P (/c calc) >>"));
  const body = `%PDF-1.5\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert('x')) >> >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n5 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length ${hidden.length} >>\nstream\n`;
  const result = await extractFile(Buffer.concat([Buffer.from(body, "latin1"), hidden, Buffer.from("\nendstream\nendobj\n%%EOF")]), "tagihan.pdf");
  const launch = result.indicators.find(i => i.name.startsWith("Tindakan launch")); assert.ok(launch); assert.match(launch.evidence, /ObjStm obj 5 0.*cmd\.exe/);
  assert.ok(result.indicators.some(i => i.name === "JavaScript dijalankan saat dokumen dibuka" && i.evidence.includes("obj 1 0")));
});
test("secret redaction covers Telegram tokens and webhooks", () => {
  assert.equal(redactSecrets(`bot987654321:${TOKEN}/send`), "bot987654321:…Dsaw/send");
  assert.equal(redactSecrets("https://discord.com/api/webhooks/123/abcDEF-secret"), "https://discord.com/api/webhooks/123/…");
});
