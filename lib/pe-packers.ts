// Packer/protector, installer and compiler identification plus overlay classification for PE files. Only bounded windows
// (file head, overlay head, file tail) are searched, so a 250 MB installer costs a few milliseconds.
import { entropy } from "./apk-payloads";
import { sniff } from "./pe-resources";
import { MB } from "./limits";
export type Section = {name: string; size: number; entropy: number; offset: number};
export type Overlay = {offset: number; size: number; type: string; entropy?: number; certificateBytes?: number; afterCertificate?: number};
export type Identity = {packer: string[]; installer?: string; compiler: string[]; script?: string};
const SECTIONS: [RegExp, string][] = [
  [/^\.?UPX\d?$|^UPX!$/i, "UPX"], [/^\.aspack$|^\.adata$/i, "ASPack"], [/^\.MPRESS[12]$/i, "MPRESS"], [/^\.themida$|^\.winlice$/i, "Themida/WinLicense"], [/^\.vmp\d$/i, "VMProtect"],
  [/^\.enigma[12]$/i, "Enigma Protector"], [/^PEC2(?:TO|MO)?$|^pec[12]$|^PECompact2?$/i, "PECompact"], [/^\.petite$/i, "Petite"], [/^\.nsp[012]$/i, "NsPack"], [/^\.?MEW$/i, "MEW"],
  [/^\.y(?:P|0da)$/i, "Yoda's Crypter"], [/^\.packed$/i, "packer tidak dikenal (.packed)"], [/^\.perplex$/i, "Perplex"], [/^\.spack$/i, "Simple Pack"], [/^\.svkp$/i, "SVKP"], [/^\.ccg$/i, "CCG"],
];
const ascii = (s: string) => Buffer.from(s, "latin1"), wide = (s: string) => Buffer.from(s, "utf16le");
export function identify(b: Buffer, sections: Section[], overlayStart: number, peOffset: number, dotnet: boolean, obfuscators: string[] = []): Identity {
  const head = b.subarray(0, Math.min(b.length, 8 * MB)), ov = overlayStart < b.length ? b.subarray(overlayStart, Math.min(b.length, overlayStart + MB)) : Buffer.alloc(0), tail = b.subarray(Math.max(0, b.length - MB));
  const has = (s: string, where: Buffer[] = [head, ov]) => where.some(w => w.includes(ascii(s)) || s.length >= 6 && w.includes(wide(s)));
  const names = sections.map(s => s.name), packer = new Set<string>(), compiler: string[] = []; let installer: string | undefined, script: string | undefined;
  for (const n of names) for (const [re, label] of SECTIONS) if (re.test(n)) packer.add(label);
  if (b.subarray(0, 4096).includes(ascii("UPX!")) || has("$Info: This file is packed with the UPX")) packer.add("UPX");
  if (names.includes(".ndata") || ov.subarray(0, 64).includes(ascii("NullsoftInst")) || has("Nullsoft Install System")) installer = "NSIS";
  else if (names.includes(".wixburn")) installer = "WiX Burn";
  else if (has("Inno Setup Setup Data") || has("InnoSetupLdrWindow") || has("This installation was built with Inno Setup")) installer = "Inno Setup";
  else if (has("InstallShield")) installer = "InstallShield";
  else if (has("SquirrelSetup") || has("Squirrel.Windows") || has("squirrel-install")) installer = "Squirrel";
  else if (has("Advanced Installer")) installer = "Advanced Installer";
  else if (ov.subarray(0, 8).toString("latin1").startsWith("7z\xbc\xaf\x27\x1c") || has("7zS.sfx") || has("7-Zip SFX")) installer = "7-Zip SFX";
  else if (ov.subarray(0, 8).toString("latin1").startsWith("Rar!\x1a\x07") || has("WinRAR SFX")) installer = "WinRAR SFX";
  if (tail.includes(Buffer.from("MEI\x0c\x0b\x0a\x0b\x0e", "latin1")) || has("_MEIPASS") || has("pyi-runtime-tmpdir") || has("PyInstaller")) {compiler.push("Python (PyInstaller)"); script = "PyInstaller (skrip Python dan pustaka terbundel)";}
  else if (has("NUITKA_ONEFILE_PARENT") || has("Nuitka")) {compiler.push("Python (Nuitka)"); script = "Nuitka (Python terkompilasi)";}
  else if (has("py2exe")) {compiler.push("Python (py2exe)"); script = "py2exe (skrip Python)";}
  if (has("AU3!EA06") || has("AU3!EA05") || has(">>>AUTOIT SCRIPT<<<")) {compiler.push("AutoIt"); script = "AutoIt (skrip terkompilasi)";}
  const go = b.indexOf("\xff Go buildinf:", 0, "latin1");
  if (go >= 0 && go < 128 * MB) {const flags = b[go + 15], n = b[go + 32]; const v = flags & 2 && n < 40 ? b.toString("latin1", go + 33, go + 33 + n) : head.toString("latin1").match(/go1\.\d{1,2}(?:\.\d{1,2})?/)?.[0]; compiler.push(`Go${v && /^go1\.[\d.]+$/.test(v) ? ` ${v}` : ""}`);}
  else if (has("Go build ID: \"")) compiler.push("Go");
  if (has("/rustc/") || has("\\rustc\\") || has("RUST_BACKTRACE")) compiler.push("Rust");
  if (has("ELECTRON_RUN_AS_NODE") || has("electron.asar")) compiler.push("Electron (aplikasi JavaScript/Node.js)");
  if (dotnet) compiler.push(".NET (CLR)");
  if (names.includes(".itext") || names.includes("CODE") && names.includes("DATA") || has("Embarcadero Delphi") || has("Borland Delphi")) compiler.push("Delphi");
  if (has("GCC: (") || has("Mingw-w64 runtime failure")) compiler.push("GCC/MinGW");
  if (peOffset > 0x80 && b.subarray(0x80, Math.min(peOffset, 0x400)).includes(ascii("Rich"))) compiler.push("MSVC (Rich header)");
  for (const o of obfuscators) if (!/^nama|^Suppress/.test(o)) packer.add(`${o} (obfuscator .NET)`);
  return {packer: [...packer], ...installer ? {installer} : {}, compiler: compiler.slice(0, 6), ...script ? {script} : {}};
}
// Overlay = bytes after the last section's raw data. The Authenticode blob normally lives there; anything else is classified.
export function overlay(b: Buffer, start: number, cert: {offset: number; size: number}): Overlay | undefined {
  if (start >= b.length) return;
  const size = b.length - start, certIn = cert.size > 0 && cert.offset >= start && cert.offset + cert.size <= b.length;
  const before = certIn ? cert.offset - start : size, after = certIn ? b.length - cert.offset - cert.size : 0;
  const out: Overlay = {offset: start, size, type: "data tidak dikenal", ...certIn ? {certificateBytes: cert.size} : {}, ...after > 16 ? {afterCertificate: after} : {}};
  const region = before > 16 ? b.subarray(start, start + before) : after > 16 ? b.subarray(cert.offset + cert.size) : undefined;
  if (!region) {out.type = certIn ? "sertifikat Authenticode saja" : "padding kecil"; return out;}
  const h = region.subarray(0, 65536), m = h.toString("latin1", 0, 32);
  const hit = sniff(h.length >= 16 ? h : Buffer.concat([h, Buffer.alloc(16 - h.length)]), true);
  if (hit) out.type = hit.kind;
  else if (m.slice(4, 20).startsWith("\xef\xbe\xad\xdeNullsoftInst") || h.subarray(0, 64).includes(ascii("NullsoftInst"))) out.type = "data installer NSIS";
  else if (/^(?:zlb\x1a|idska32|rDlPtS)/.test(m) || h.includes(ascii("Inno Setup Setup Data"))) out.type = "data installer Inno Setup";
  else if (b.subarray(Math.max(start, b.length - 4096)).includes(Buffer.from("MEI\x0c\x0b\x0a\x0b\x0e", "latin1"))) out.type = "arsip PyInstaller";
  else {
    // Sample up to 8 windows across the region: all-zero means size inflation, otherwise measure density.
    const count = Math.min(8, Math.ceil(region.length / 65536)), windows = Array.from({length: count}, (_, i) => {const at = Math.floor(region.length / count * i); return region.subarray(at, at + 65536);});
    const zero = windows.every(w => w.every(x => x === w[0])), ent = Math.round(windows.reduce((n, w) => n + entropy(w), 0) / windows.length * 100) / 100;
    out.type = zero ? "data berulang/kosong (padding)" : ent > 7.5 ? "data berentropi tinggi (terkompresi/terenkripsi)" : "data tidak dikenal"; if (!zero) out.entropy = ent;
  }
  return out;
}
