import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { extractFile } from "../lib/extract";
import { linkRisk } from "../lib/pdf-behaviors";

// ---- hand-built PE images (nothing is executed) ----
type Sec = {name: string; data: Buffer; flags: number};
const align = (n: number, a: number) => Math.ceil(n / a) * a;
const OPT = 0x40 + 24, DIRS = OPT + 96;
function image(sections: Sec[], overlay = Buffer.alloc(0), dirs: Record<number, [number, number]> = {}, patch?: (h: Buffer) => void) {
  const headers = 0x400, h = Buffer.alloc(headers); h.write("MZ", 0, "latin1"); h.writeUInt32LE(0x40, 60); h.write("PE\0\0", 0x40, "latin1"); h.writeUInt16LE(0x14c, 0x44);
  h.writeUInt16LE(sections.length, 0x46); h.writeUInt16LE(224, 0x54); h.writeUInt16LE(0x102, 0x56); h.writeUInt16LE(0x10b, OPT); h.writeUInt32LE(headers, OPT + 60); h.writeUInt32LE(16, OPT + 92);
  let raw = headers, va = 0x1000; const bodies: Buffer[] = [];
  sections.forEach((s, i) => {
    const size = align(s.data.length, 0x200), q = OPT + 224 + i * 40; h.write(s.name, q, "latin1"); h.writeUInt32LE(Math.max(s.data.length, 0x1000), q + 8); h.writeUInt32LE(va, q + 12); h.writeUInt32LE(size, q + 16); h.writeUInt32LE(raw, q + 20); h.writeUInt32LE(s.flags, q + 36);
    const body = Buffer.alloc(size); s.data.copy(body); bodies.push(body); raw += size; va += align(Math.max(s.data.length, 1), 0x1000);
  });
  for (const [k, [off, len]] of Object.entries(dirs)) {h.writeUInt32LE(off, DIRS + Number(k) * 8); h.writeUInt32LE(len, DIRS + Number(k) * 8 + 4);}
  patch?.(h);
  return Buffer.concat([h, ...bodies, overlay]);
}
// Deterministic near-random bytes (xorshift32): entropy ~8 bits/byte, like an encrypted payload.
function noise(n: number, seed = 0x9e3779b9) {const b = Buffer.alloc(n); let x = seed >>> 0; for (let i = 0; i < n; i++) {x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; b[i] = x & 0xff;} return b;}
const code = (n = 0x2000) => Buffer.alloc(n, 0x90);
const goLike = (extra: Sec[] = []) => [{name: ".text", data: code(), flags: 0x60000020}, {name: ".data", data: noise(1024 * 1024), flags: 0xc0000040}, ...extra];
const behavior = (a: Awaited<ReturnType<typeof extractFile>>, id: string) => (a.metadata.behaviors as {id: string; severity: string; evidence: string[]}[] | undefined)?.find(b => b.id === id);
// Minimal DER + Authenticode SignedData (SpcIndirectDataContent with a SHA-256 image digest and one certificate).
const der = (tag: number, ...parts: Buffer[]) => {const body = Buffer.concat(parts), n = body.length; const len = n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]); return Buffer.concat([Buffer.from([tag]), len, body]);};
const oid = (hex: string) => der(6, Buffer.from(hex, "hex"));
function certTable(digest: Buffer, cert: Buffer) {
  const spc = der(0x30, der(0x30, oid("2b06010401823702010f")), der(0x30, der(0x30, oid("608648016503040201"), Buffer.from([5, 0])), der(4, digest)));
  const signed = der(0x30, der(2, Buffer.from([1])), der(0x31, der(0x30, oid("608648016503040201"))), der(0x30, oid("2b060104018237020104"), der(0xa0, spc)), der(0xa0, cert));
  const p7 = der(0x30, oid("2a864886f70d010702"), der(0xa0, signed)), t = Buffer.alloc(align(8 + p7.length, 8));
  t.writeUInt32LE(8 + p7.length, 0); t.writeUInt16LE(0x200, 4); t.writeUInt16LE(2, 6); p7.copy(t, 8); return t;
}
function signedImage(sections: Sec[], tamper = false) {
  const cert = readFileSync(new URL("./fixtures/authenticode-test-leaf.der", import.meta.url)), at = image(sections).length, size = certTable(Buffer.alloc(32), cert).length;
  const base = image(sections, Buffer.alloc(0), {4: [at, size]}), sum = OPT + 64, entry = DIRS + 32;
  const digest = createHash("sha256").update(base.subarray(0, sum)).update(base.subarray(sum + 4, entry)).update(base.subarray(entry + 8)).digest();
  if (tamper) digest[0] ^= 0xff;
  return Buffer.concat([base, certTable(digest, cert)]);
}

test("crypter: Go-like program with a multi-MB near-random writable .data is a high encrypted payload", async () => {
  const a = await extractFile(image(goLike()), "loader.exe"), b = behavior(a, "encrypted_payload");
  assert.equal(a.incomplete, false); assert.equal(b?.severity, "high"); assert.match(b!.evidence[0], /section \.data \(data writable\): 1\.0 MB/);
  assert.ok(a.indicators.some(i => i.name.startsWith("Payload terenkripsi tersembunyi")));
  // Compressed DWARF (Go/MinGW long section names resolving to .zdebug_*) is debug info, not a payload.
  const strtab = Buffer.concat([Buffer.from([0, 0, 0, 0]), Buffer.from(".zdebug_info\0")]); strtab.writeUInt32LE(strtab.length, 0);
  const debug = image([{name: ".text", data: code(), flags: 0x60000020}, {name: "/4", data: noise(1024 * 1024), flags: 0x42100040}, {name: ".symtab", data: strtab, flags: 0x42000000}], Buffer.alloc(0), {}, h => {h.writeUInt32LE(0x400 + 0x2000 + 1024 * 1024, 0x40 + 12);});
  assert.equal(behavior(await extractFile(debug, "debug.exe"), "encrypted_payload"), undefined);
});
test("crypter exceptions: installers, known packers and a CA-signed file with a matching image hash do not reach high", async () => {
  assert.equal(behavior(await extractFile(image(goLike([{name: ".ndata", data: Buffer.alloc(0x200), flags: 0xc0000080}])), "setup.exe"), "encrypted_payload"), undefined);
  const upx = await extractFile(image([{name: "UPX0", data: code(), flags: 0xe0000080}, {name: "UPX1", data: noise(1024 * 1024), flags: 0xe0000040}]), "upx.exe");
  assert.equal(behavior(upx, "encrypted_payload"), undefined); assert.equal(behavior(upx, "packed")?.severity, "medium");
  const signed = await extractFile(signedImage(goLike()), "signed.exe"), auth = signed.metadata.authenticode as {imageHashMatches: boolean; selfSigned: boolean};
  assert.equal(auth.imageHashMatches, true); assert.equal(auth.selfSigned, false);
  assert.equal(behavior(signed, "encrypted_payload")?.severity, "low"); assert.equal(behavior(signed, "signature_mismatch"), undefined);
  // A copied signature (hash mismatch) is flagged and gives no exception.
  const cloned = await extractFile(signedImage(goLike(), true), "cloned.exe");
  assert.equal((cloned.metadata.authenticode as {imageHashMatches: boolean}).imageHashMatches, false);
  assert.equal(behavior(cloned, "signature_mismatch")?.severity, "medium"); assert.equal(behavior(cloned, "encrypted_payload")?.severity, "high");
});
test("crypter: .NET code section near-random, packer-style RWX section and hex-encoded overlay", async () => {
  const net = image([{name: ".text", data: noise(300 * 1024), flags: 0x60000020}], Buffer.alloc(0), {14: [0x1000, 72]});
  assert.equal(behavior(await extractFile(net, "net.exe"), "encrypted_payload")?.severity, "high");
  const dll = image([{name: ".text", data: noise(300 * 1024), flags: 0x60000020}], Buffer.alloc(0), {14: [0x1000, 72]}, h => h.writeUInt16LE(0x2102, 0x56));
  assert.equal(behavior(await extractFile(dll, "lib.dll.exe"), "encrypted_payload")?.severity, "medium");
  const rwx = image([{name: ".text", data: code(), flags: 0x60000020}, {name: "x7Gq2", data: noise(700 * 1024), flags: 0xe0000040}]);
  assert.equal(behavior(await extractFile(rwx, "rwx.exe"), "encrypted_payload")?.severity, "high");
  const hex = image([{name: ".text", data: code(), flags: 0x60000020}], Buffer.from(noise(150 * 1024).toString("hex").toUpperCase(), "latin1"));
  const b = behavior(await extractFile(hex, "hex.exe"), "encrypted_payload"); assert.equal(b?.severity, "high"); assert.match(b!.evidence[0], /teks hex/);
  // Ordinary low-entropy data and a small dense blob stay quiet.
  assert.equal(behavior(await extractFile(image([{name: ".text", data: code(), flags: 0x60000020}, {name: ".data", data: Buffer.alloc(1024 * 1024, 7), flags: 0xc0000040}]), "plain.exe"), "encrypted_payload"), undefined);
  assert.equal(behavior(await extractFile(image([{name: ".text", data: code(), flags: 0x60000020}, {name: ".rdata", data: noise(64 * 1024), flags: 0x40000040}]), "small.exe"), "encrypted_payload"), undefined);
});
test("zero-import program resolving APIs by hand; DLLs and .NET are exempt", async () => {
  const gui = (dll = false) => (h: Buffer) => {h.writeUInt16LE(2, OPT + 68); h.writeUInt32LE(0x1000, OPT + 16); if (dll) h.writeUInt16LE(0x2102, 0x56);};
  const a = await extractFile(image([{name: ".text", data: code(), flags: 0x60000020}], Buffer.alloc(0), {}, gui()), "noimp.exe");
  assert.equal(behavior(a, "no_imports")?.severity, "high"); assert.match(behavior(a, "no_imports")!.evidence.join(" "), /0 fungsi import/);
  assert.equal(behavior(await extractFile(image([{name: ".text", data: code(), flags: 0x60000020}], Buffer.alloc(0), {}, gui(true)), "res.dll.exe"), "no_imports"), undefined);
  assert.equal(behavior(await extractFile(image([{name: ".text", data: code(), flags: 0x60000020}], Buffer.alloc(0), {14: [0x1000, 72]}, gui()), "net.exe"), "no_imports"), undefined);
});

// ---- hand-built PDFs ----
const esc = (s: string) => s.replace(/[\\()]/g, m => `\\${m}`);
function pdf(opts: {text?: string[]; catalog?: string; annots?: string[]; extra?: string[]}) {
  const lines = (opts.text || []).map((t, i) => `BT /F1 10 Tf 20 ${760 - i * 14} Td (${esc(t)}) Tj ET`).join("\n"), n = 5, annots = opts.annots || [];
  const objects = [`<< /Type /Catalog /Pages 2 0 R ${opts.catalog || ""} >>`, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R${annots.length ? ` /Annots [${annots.map((_, i) => `${n + 1 + i} 0 R`).join(" ")}]` : ""} >>`,
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", `<< /Length ${lines.length} >>\nstream\n${lines}\nendstream`, ...annots, ...opts.extra || []];
  let text = "%PDF-1.4\n"; const offsets: number[] = [];
  objects.forEach((o, i) => {offsets.push(Buffer.byteLength(text, "latin1")); text += `${i + 1} 0 obj\n${o}\nendobj\n`;});
  const xref = Buffer.byteLength(text, "latin1");
  text += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.map(o => `${String(o).padStart(10, "0")} 00000 n \n`).join("")}trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return Buffer.from(text, "latin1");
}
const link = (url: string, rect = "[200 400 400 440]") => `<< /Type /Annot /Subtype /Link /Rect ${rect} /Border [0 0 0] /A << /S /URI /URI (${esc(url)}) >> >>`;
const levels = (a: Awaited<ReturnType<typeof extractFile>>) => (a.metadata.behaviors as {id: string; severity: string}[] | undefined ?? []).map(b => `${b.id}:${b.severity}`);

test("PDF: JavaScript run on open and /Launch actions are high, even when pdf.js cannot parse the file", async () => {
  const js = await extractFile(pdf({catalog: "/OpenAction << /S /JavaScript /JS (app.alert\\('Buka di browser'\\); app.launchURL\\('https://x.example.net'\\);) >>", text: ["Invoice"]}), "inv.pdf");
  assert.equal(js.incomplete, false); assert.equal(behavior(js, "pdf_autorun_js")?.severity, "high"); assert.match(behavior(js, "pdf_autorun_js")!.evidence.join(" "), /launchURL|app\.alert/);
  const launch = await extractFile(pdf({catalog: "/OpenAction << /S /Launch /F (cmd.exe) /P (/c calc) >>", text: ["Dokumen"]}), "launch.pdf");
  assert.equal(behavior(launch, "pdf_launch")?.severity, "high");
  const broken = await extractFile(Buffer.from("%PDF-1.4\n1 0 obj << /OpenAction << /S /Launch /Win << /F (cmd.exe) >> >> >> endobj\n%%EOF"), "broken.pdf");
  assert.equal(broken.incomplete, true); assert.equal(behavior(broken, "pdf_launch")?.severity, "high");
});
test("PDF: program attachment is high; form posting to an outside server is medium", async () => {
  const mz = "MZ\x90\0this program cannot be run in DOS mode";
  const att = await extractFile(pdf({catalog: "/Names << /EmbeddedFiles << /Names [(tagihan.pdf.exe) 6 0 R] >> >>", text: ["Lihat lampiran"], extra: [`<< /Type /Filespec /F (tagihan.pdf.exe) /UF (tagihan.pdf.exe) /EF << /F 7 0 R >> >>`, `<< /Type /EmbeddedFile /Length ${mz.length} >>\nstream\n${mz}\nendstream`]}), "att.pdf");
  const b = behavior(att, "pdf_embedded_exe"); assert.equal(b?.severity, "high"); assert.match(b!.evidence[0], /tagihan\.pdf\.exe/);
  const form = await extractFile(pdf({text: ["Formulir pendaftaran peserta seminar nasional tahun ini, isi data diri dengan lengkap dan benar sebelum menekan tombol kirim di bawah ini."], annots: ["<< /Type /Annot /Subtype /Widget /FT /Btn /Rect [20 20 120 60] /A << /S /SubmitForm /F << /FS /URL /F (https://collect.formdata-panel.xyz/save.php) >> >> >>"]}), "form.pdf");
  assert.equal(behavior(form, "pdf_submit_form")?.severity, "medium");
});
test("PDF phishing: lure text plus a shortener link is high and the host is queued for threat intel", async () => {
  const a = await extractFile(pdf({text: ["Microsoft 365", "Your account has been suspended due to unusual sign-in activity.", "Verify your account within 24 hours to keep access."], annots: [link("https://bit.ly/3Fake365")]}), "notice.pdf");
  const b = behavior(a, "pdf_phishing"); assert.equal(b?.severity, "high"); assert.match(b!.evidence.join(" "), /penyingkat URL/);
  assert.ok((a.metadata.campaign as {hosts: string[]}).hosts.includes("bit.ly"));
  // Indonesian lure, page-sized link to free hosting: phishing high + "one big button".
  const id = await extractFile(pdf({text: ["Tagihan pembayaran BCA"], annots: [link("https://bca-verifikasi.vercel.app/login", "[0 0 595 842]")]}), "tagihan.pdf");
  assert.deepEqual(["pdf_phishing:high", "pdf_link_only:medium"].filter(x => levels(id).includes(x)).length, 2);
  assert.match(behavior(id, "pdf_link_only")!.evidence.join(" "), /100% halaman/);
  assert.equal(linkRisk("http://45.77.10.20/inv").strong, "alamat IP langsung"); assert.equal(linkRisk("https://www.ui.ac.id/").strong, undefined);
});
test("PDF: an ordinary text document with normal links stays below medium", async () => {
  const text = ["Laporan Tahunan Koperasi Sejahtera 2026", "Ringkasan kegiatan, jadwal pembayaran iuran anggota, dan rencana kerja tahun depan.", "Rapat anggota tahunan diadakan di aula kantor desa pada bulan Desember.", "Invoice dan bukti pembayaran tersedia di sekretariat untuk diperiksa anggota.", "Informasi lengkap dapat dibaca di situs resmi koperasi dan portal pemerintah daerah."];
  const a = await extractFile(pdf({text, annots: [link("https://koperasi-sejahtera.co.id/laporan-2026"), link("https://www.jogjaprov.go.id/")]}), "laporan.pdf");
  assert.equal(a.incomplete, false); assert.ok(levels(a).every(x => !/:(?:medium|high|critical)$/.test(x)), levels(a).join(","));
});
