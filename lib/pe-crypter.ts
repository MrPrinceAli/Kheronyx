// Crypter/loader heuristics for PE files: encrypted or encoded payloads parked in data sections, packer-style RWX
// sections, the overlay or a .NET code section, plus programs without any import table. Only bounded 64 KB windows are
// measured (≤ 768 per file), nothing is decrypted or executed. Installers, script bundlers and known packers are
// explained elsewhere (pe-packers.ts) and skipped; content covered by an intact-looking Authenticode digest is only "low".
import type { Behavior, Severity } from "./behaviors";
import type { Overlay } from "./pe-packers";
import { entropy } from "./apk-payloads";
import { MB } from "./limits";
export type PeSection = {name: string; size: number; entropy: number; flags: number; offset: number};
// none: no Authenticode; valid: CA-issued signer and the signed image hash matches the file; self: self-signed;
// mismatch: the signed hash does not match (signature copied from another file or file modified after signing).
export type Signature = "none" | "valid" | "self" | "mismatch";
export type CrypterFacts = {sections: PeSection[]; overlay?: Overlay; installer?: string; script?: string; packers: string[]; dotnet: boolean; imports: number; dll: boolean; subsystem: number; entry: number; signature: Signature};
const W = 65536, MAX_WINDOWS = 256, BUDGET = 768, DENSE = 7.9, HIGH = 512 * 1024, MIN = 128 * 1024;
const RANK: Record<Severity, number> = {low: 0, medium: 1, high: 2, critical: 3};
const size = (n: number) => n >= MB ? `${(n / MB).toFixed(1)} MB` : `${Math.round(n / 1024)} KB`;
const CODE = 0x20, EXEC = 0x20000000, WRITE = 0x80000000;
// COFF long section names ("/19" -> ".zdebug_line"): Go/MinGW keep (compressed) DWARF debug info in such sections.
export function longName(b: Buffer, pe: number, name: string) {
  if (!/^\/\d{1,7}$/.test(name) || pe + 20 > b.length) return name;
  const table = b.readUInt32LE(pe + 12), symbols = b.readUInt32LE(pe + 16), at = table + symbols * 18 + Number(name.slice(1));
  if (!table || symbols > 1e7 || at >= b.length) return name;
  const end = b.indexOf(0, at), s = b.toString("latin1", at, Math.min(end < 0 ? b.length : end, at + 64));
  return /^[\x21-\x7e]+$/.test(s) ? s : name;
}
// Share of 64 KB windows at ≥7.9 bits/byte (sampled evenly when a region has more than MAX_WINDOWS windows).
function dense(b: Buffer, start: number, length: number, budget: {left: number}) {
  const n = Math.floor(Math.min(length, b.length - start) / W), count = Math.min(n, MAX_WINDOWS, budget.left); if (count <= 0) return {bytes: 0, ratio: 0};
  let hit = 0; budget.left -= count;
  for (let i = 0; i < count; i++) {const at = start + Math.floor(i * n / count) * W; if (entropy(b.subarray(at, at + W)) >= DENSE) hit++;}
  return {bytes: Math.round(hit / count * n) * W, ratio: hit / count};
}
// Hex or base64 text: payloads stored as encoded text (entropy ~4-6) to slip past "high entropy" checks.
function encoded(h: Buffer) {
  if (h.length < 4096) return "";
  const text = h.toString("latin1"), body = text.replace(/[\r\n]/g, "");
  if (body.length >= h.length * 0.97 && /^[0-9A-Fa-f]+$/.test(body)) return "hex";
  return body.length >= h.length * 0.97 && /^[A-Za-z0-9+/]+=*$/.test(body) ? "base64" : "";
}
export function crypterBehaviors(b: Buffer, pe: number, f: CrypterFacts): Behavior[] {
  const out: Behavior[] = [], hits: {severity: Severity; text: string}[] = [], budget = {left: BUDGET};
  const hit = (severity: Severity, text: string) => hits.push({severity: f.signature === "valid" ? "low" : severity, text});
  // Sections: writable data (Go/MSVC .data), packer-style writable+executable sections and read-only data. Resources,
  // debug info and ordinary code are skipped; known packers/installers are reported by the "packed"/installer logic.
  if (!f.packers.length && !f.installer) for (const s of f.sections) {
    const name = longName(b, pe, s.name).replace(/[^\x21-\x7e]/g, "?"), exec = Boolean(s.flags & EXEC || s.flags & CODE), rwx = Boolean(s.flags & EXEC && s.flags & WRITE);
    if (s.size < MIN || s.entropy < 6.5 || /^\.rsrc$|^\.z?debug_/i.test(name) || exec && !rwx) continue;
    const d = dense(b, s.offset, s.size, budget); if (d.bytes < MIN) continue;
    const whole = s.entropy >= DENSE && s.size >= HIGH, writable = Boolean(s.flags & WRITE) && d.bytes >= HIGH;
    hit(whole || writable ? "high" : "medium", `section ${name}${/^\/\d/.test(s.name) && name !== s.name ? ` (${s.name})` : ""}${rwx ? " (writable+executable)" : writable ? " (data writable)" : ""}: ${size(d.bytes)} dari ${size(s.size)} nyaris acak (entropi section ${s.entropy})`);
  }
  // .NET: IL and metadata are far from random, so a large near-random code section means encrypted resources/IL.
  const text = f.dotnet ? f.sections.find(s => s.flags & CODE) : undefined;
  // Libraries sometimes embed compressed data (code pages, models), so only a program (EXE) reaches high.
  if (text && text.size >= 256 * 1024 && text.entropy >= 7.5) hit(text.entropy >= 7.7 && !f.dll ? "high" : "medium", `${f.dll ? "DLL" : "program"} .NET dengan section kode ${text.name} ${size(text.size)} berentropi ${text.entropy} (IL/metadata biasa jauh di bawah 7; kemungkinan resource/IL terenkripsi)`);
  // Overlay (bytes after the last section, before the Authenticode table).
  const ov = f.overlay, region = ov ? ov.size - (ov.certificateBytes || 0) - (ov.afterCertificate || 0) : 0;
  if (ov && region >= MIN && !f.installer && !f.script && /tidak dikenal|entropi tinggi/.test(ov.type)) {
    const enc = encoded(b.subarray(ov.offset, ov.offset + Math.min(region, W))), d = enc ? {bytes: 0, ratio: 0} : dense(b, ov.offset, region, budget);
    if (enc) hit(region >= 256 * 1024 ? "high" : "medium", `overlay ${size(region)} berisi teks ${enc} panjang (payload ter-encode yang ditempel setelah program)`);
    else if (d.bytes >= MIN) hit(d.bytes >= HIGH && d.ratio >= 0.75 ? "high" : "medium", `overlay ${size(region)} di offset ${ov.offset}: ${size(d.bytes)} nyaris acak, tanpa format installer/arsip yang dikenal`);
    else if (region >= HIGH && f.signature === "none") hit("medium", `overlay ${size(region)} berisi data tak dikenal tanpa tanda tangan maupun format installer`);
  }
  if (hits.length) {
    const severity = hits.reduce<Severity>((m, h) => RANK[h.severity] > RANK[m] ? h.severity : m, "low");
    out.push({id: "encrypted_payload", name: "Payload terenkripsi tersembunyi di dalam program (pola crypter/loader)", severity, evidence: [...hits.sort((x, y) => RANK[y.severity] - RANK[x.severity]).slice(0, 4).map(h => h.text),
      f.signature === "valid" ? "bagian ini tercakup tanda tangan Authenticode yang hash-nya cocok, jadi kemungkinan data aplikasi resmi yang terkompresi" : "bukan installer/arsip yang dikenal: program biasa tidak menyimpan data acak/ter-encode sebesar ini; crypter membuka payload seperti ini di memori saat dijalankan"]});
  }
  // No import table at all: a normal Windows program imports at least kernel32; resolving APIs by hand hides intent.
  const code = f.sections.filter(s => s.flags & (CODE | EXEC) && s.size >= 4096);
  if (!f.dotnet && !f.imports && !f.dll && f.entry && (f.subsystem === 2 || f.subsystem === 3) && code.length) {
    const small = b.length < MB, packedLook = f.sections.some(s => s.size >= 4096 && s.entropy >= 7.2);
    out.push({id: "no_imports", name: "Program tanpa tabel import (memanggil fungsi secara tersembunyi)", severity: f.signature === "valid" ? "low" : small || packedLook ? "high" : "medium", evidence: [
      "0 fungsi import: alamat API Windows dicari sendiri saat berjalan (PEB walking/hash API), teknik umum shellcode, loader dan stealer", small ? `ukuran program kecil (${size(b.length)})` : "", packedLook ? "ada section berentropi tinggi (kode dikemas/terenkripsi)" : ""].filter(Boolean)});
  }
  return out;
}
