// Bounded PE resource-directory walker (type/name/language, depth 3, cycle-safe) with VS_VERSIONINFO, manifest and
// embedded-payload sniffing, plus brand-impersonation checks (version info vs. Authenticode signer). Nothing is executed.
import type { ToOffset } from "./pe-imports";
import type { Behavior, Severity } from "./behaviors";
import { entropy } from "./apk-payloads";
export type ResourcePayload = {path: string; kind: string; group: string; size: number; entropy?: number};
export type PeResources = {count: number; types: Record<string, number>; version?: Record<string, string>; manifest?: {executionLevel?: string; uiAccess?: boolean; autoElevate?: boolean}; icons: number; payloads: ResourcePayload[]; errors: number; truncated?: boolean};
const TYPES: Record<number, string> = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE", 19: "PLUGPLAY", 20: "VXD", 21: "ANICURSOR", 22: "ANIICON", 23: "HTML", 24: "MANIFEST"};
// Types whose content is structured UI/metadata: never sniffed for scripts or entropy (an MZ/archive header still counts).
const STRUCTURED = new Set([1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 14, 16, 17, 21, 22, 23, 24]);
const MAX_ENTRIES = 20000, MAX_LEAVES = 3000, ENTROPY_BUDGET = 16 * 1024 * 1024, BLOB_MIN = 32 * 1024;
export const VERSION_KEYS = ["CompanyName", "FileDescription", "ProductName", "OriginalFilename", "InternalName", "FileVersion", "ProductVersion", "LegalCopyright", "Comments"];
const clean = (s: string, max = 200) => s.replace(/[\x00-\x1f\x7f​-‏‪-‮⁦-⁩﻿]/g, "").trim().slice(0, max);
const SCRIPTS: [string, RegExp][] = [
  ["PowerShell", /powershell(?:\.exe)?\s+-|Invoke-Expression|\bIEX\s*\(|New-Object\s+(?:System\.)?Net\.WebClient|\[(?:System\.)?Convert\]::FromBase64String|-EncodedCommand|Invoke-WebRequest|(?:Add|Set)-MpPreference|\.DownloadString\(/i],
  ["VBScript", /CreateObject\s*\(\s*"(?:WScript\.Shell|Scripting\.FileSystemObject|MSXML2\.XMLHTTP|ADODB\.Stream|Shell\.Application)"|On Error Resume Next|\bWScript\.Sleep\b/i],
  ["JScript", /new\s+ActiveXObject\s*\(|WScript\.CreateObject\s*\(|GetObject\s*\(\s*["']winmgmts/i],
  ["batch", /^\s*@echo\s+off\b|%~dp0|\bschtasks(?:\.exe)?\s+\/create\b|\breg(?:\.exe)?\s+add\s+HK|\battrib\s+\+[sh]\s|\bdel\s+\/[fqs]\s+\/[fqs]/im],
];
// Real media/document containers that are legitimately dense (never reported as encrypted blobs).
const MEDIA = (h: Buffer) => h.readUInt32BE(0) === 0x89504e47 || h[0] === 0xff && h[1] === 0xd8 || /^(?:GIF8|RIFF|OTTO|true|wOFF|wOF2|OggS|fLaC|ID3|%PDF|TPF0|<\?xm|\x00\x00\x01\x00|\x00\x00\x02\x00)/.test(h.toString("latin1", 0, 4)) || h.readUInt32BE(0) === 0x00010000 || h.toString("latin1", 0, 2) === "BM";
// Classifies a resource (also used for the overlay) by magic bytes; scripts/blobs only for non-structured resources.
export function sniff(d: Buffer, structured = false): {kind: string; group: string; entropy?: number} | undefined {
  if (d.length < 16) return;
  const m = d.toString("latin1", 0, 8);
  if (m.startsWith("MZ") && d.length >= 64) {const e = d.readUInt32LE(60); if (e >= 4 && e + 24 <= d.length && d.readUInt32LE(e) === 0x4550) return {kind: d.readUInt16LE(e + 22) & 0x2000 ? "DLL Windows (PE)" : "program Windows (PE)", group: "program Windows"};}
  if (m.startsWith("PK\x03\x04")) return {kind: "arsip ZIP", group: "arsip"};
  if (m.startsWith("7z\xbc\xaf\x27\x1c")) return {kind: "arsip 7z", group: "arsip"};
  if (m.startsWith("Rar!\x1a\x07")) return {kind: "arsip RAR", group: "arsip"};
  if (m.startsWith("MSCF\0\0\0\0")) return {kind: "arsip CAB", group: "arsip"};
  if (d[0] === 0x1f && d[1] === 0x8b && d[2] === 8) return {kind: "arsip GZIP", group: "arsip"};
  if (d.subarray(0, 64).includes("AU3!EA0")) return {kind: "skrip AutoIt terkompilasi", group: "skrip"};
  if (structured) return;
  const wide = d[1] === 0 && d[3] === 0 || d[0] === 0xff && d[1] === 0xfe;
  const text = wide ? d.toString("utf16le", 0, Math.min(d.length, 16384) & ~1) : d.toString("latin1", 0, Math.min(d.length, 8192));
  if ((text.match(/[\t\n\r\x20-\x7e]/g) || []).length >= text.length * 0.85) {for (const [name, re] of SCRIPTS) if (re.test(text)) return {kind: `skrip ${name}`, group: "skrip"}; return;}
  if (d.length < BLOB_MIN || MEDIA(d)) return;
  const ent = entropy(d.subarray(0, 65536));
  return ent > 7.6 ? {kind: "blob terenkripsi/terkompresi (mirip shellcode atau payload terenkripsi)", group: "blob terenkripsi", entropy: ent} : undefined;
}
// VS_VERSIONINFO: nested {wLength, wValueLength, wType, szKey, pad, Value, pad, Children}. Offsets are relative to the resource.
function versionInfo(v: Buffer) {
  const out: Record<string, string> = {}; let blocks = 0;
  const align = (n: number) => n + 3 & ~3;
  const walk = (p: number, end: number, depth: number) => {
    while (p + 6 <= end && blocks++ < 400) {
      const len = v.readUInt16LE(p), valueLen = v.readUInt16LE(p + 2), type = v.readUInt16LE(p + 4), stop = Math.min(end, p + len); if (len < 6) return;
      let q = p + 6, key = ""; while (q + 2 <= stop && key.length < 64) {const c = v.readUInt16LE(q); q += 2; if (!c) break; key += String.fromCharCode(c);}
      q = align(q);
      if (depth === 3 && VERSION_KEYS.includes(key) && valueLen && !(key in out)) {
        let s = ""; for (let r = q; r + 2 <= stop && s.length < 300; r += 2) {const c = v.readUInt16LE(r); if (!c) break; s += String.fromCharCode(c);}
        if (clean(s)) out[key] = clean(s);
      }
      const children = depth === 0 ? align(q + valueLen) : depth === 3 ? stop : type === 1 ? align(q + valueLen * 2) : align(q + valueLen);
      if (depth === 0 && key === "VS_VERSION_INFO" || depth === 1 && key === "StringFileInfo" || depth === 2) walk(children, stop, depth + 1);
      if (depth === 0) return; p = align(p + len);
    }
  };
  walk(0, v.length, 0);
  return out;
}
function manifest(d: Buffer) {
  const text = d[0] === 0xff && d[1] === 0xfe ? d.toString("utf16le", 2, Math.min(d.length, 65536) & ~1) : d.toString("utf8", 0, Math.min(d.length, 65536));
  const level = text.match(/requestedExecutionLevel\b[^>]{0,200}?\blevel\s*=\s*["']\s*(\w{1,40})/i)?.[1];
  const ui = /requestedExecutionLevel\b[^>]{0,200}?\buiAccess\s*=\s*["']\s*true/i.test(text), elevate = /<(?:\w+:)?autoElevate>\s*true/i.test(text);
  return {...level ? {executionLevel: level} : {}, ...ui ? {uiAccess: true} : {}, ...elevate ? {autoElevate: true} : {}};
}
export function readResources(b: Buffer, toOffset: ToOffset, rva: number, deadline: number): PeResources {
  if (toOffset(rva, 16) < 0) throw new Error("Direktori resource di luar file.");
  const seen = new Set<number>(), leaves: {path: string; type: number | string; offset: number; size: number}[] = []; let entries = 0, errors = 0, truncated = false;
  const label = (key: number | string, depth: number) => typeof key === "string" ? key : depth === 0 ? TYPES[key] || `#${key}` : String(key);
  const name = (off: number) => {const p = toOffset(rva + off, 2); if (p < 0) return "?"; const n = Math.min(b.readUInt16LE(p), 64), q = toOffset(rva + off + 2, n * 2); return q < 0 ? "?" : clean(b.toString("utf16le", q, q + n * 2), 64) || "?";};
  const walk = (off: number, depth: number, path: string[], type: number | string) => {
    if (seen.has(off)) {errors++; return;} seen.add(off);
    const p = toOffset(rva + off, 16); if (p < 0) {errors++; return;}
    const n = b.readUInt16LE(p + 12) + b.readUInt16LE(p + 14);
    for (let i = 0; i < n; i++) {
      if (++entries > MAX_ENTRIES || leaves.length >= MAX_LEAVES || Date.now() > deadline) {truncated = true; return;}
      const e = toOffset(rva + off + 16 + i * 8, 8); if (e < 0) {errors++; return;}
      const id = b.readUInt32LE(e), target = b.readUInt32LE(e + 4), key = id & 0x80000000 ? name(id & 0x7fffffff) : id, here = [...path, label(key, depth)], t = depth ? type : key;
      if (target & 0x80000000) {if (depth < 2) walk(target & 0x7fffffff, depth + 1, here, t); else errors++; continue;}
      const d = toOffset(rva + target, 16); if (d < 0) {errors++; continue;}
      const size = b.readUInt32LE(d + 4), q = size ? toOffset(b.readUInt32LE(d), Math.min(size, 16)) : -1;
      if (q < 0) {errors++; continue;}
      leaves.push({path: here.join("/").slice(0, 120), type: t, offset: q, size});
    }
  };
  walk(0, 0, [], 0);
  const out: PeResources = {count: leaves.length, types: {}, icons: 0, payloads: [], errors, ...truncated ? {truncated} : {}};
  let budget = ENTROPY_BUDGET;
  for (const l of leaves) {
    const tl = typeof l.type === "string" ? l.type.slice(0, 40) : TYPES[l.type] || `#${l.type}`; out.types[tl] = (out.types[tl] || 0) + 1;
    const data = b.subarray(l.offset, Math.min(b.length, l.offset + l.size));
    try {
      if (l.type === 16 && !out.version) {const v = versionInfo(data.subarray(0, 65536)); if (Object.keys(v).length) out.version = v;}
      else if (l.type === 24 && !out.manifest) out.manifest = manifest(data);
      if (l.type === 3 || l.type === 14) out.icons++;
      if (out.payloads.length >= 40 || Date.now() > deadline) continue;
      const structured = typeof l.type === "number" && STRUCTURED.has(l.type), dense = !structured && data.length >= BLOB_MIN && budget > 0;
      const hit = sniff(structured || dense ? data : data.subarray(0, Math.min(data.length, BLOB_MIN - 1)), structured); if (dense) budget -= 65536;
      if (hit) out.payloads.push({path: l.path, kind: hit.kind, group: hit.group, size: l.size, ...hit.entropy ? {entropy: hit.entropy} : {}});
    } catch {out.errors++;}
  }
  return out;
}
const SEVERITY: Record<string, Severity> = {"program Windows": "high", skrip: "high", arsip: "medium", "blob terenkripsi": "low"};
export function resourceBehaviors(r: PeResources, installer = false): Behavior[] {
  const groups = new Map<string, ResourcePayload[]>(); for (const p of r.payloads) groups.set(p.group, [...groups.get(p.group) || [], p]);
  const out: Behavior[] = [...groups].map(([group, list]) => {
    // Installers/SFX legitimately carry archives (and sometimes their own helper programs) in resources.
    let severity = SEVERITY[group] || "medium"; if (installer && severity !== "low") severity = group === "skrip" ? "medium" : "low";
    if (group === "skrip" && list.every(p => !/PowerShell|AutoIt/.test(p.kind)) && severity === "high") severity = "medium";
    return {id: `resource_${group.replace(/\W+/g, "_")}`, name: `File tersembunyi di dalam resource (${group})`, severity, evidence: list.slice(0, 5).map(p => `${p.path}: ${p.kind}, ${p.size} byte${p.entropy ? `, entropi ${p.entropy}` : ""}`)};
  });
  const m = r.manifest;
  if (m?.executionLevel && /^requireAdministrator$/i.test(m.executionLevel) || m?.uiAccess) out.push({id: "requires_admin", name: "Meminta hak administrator", severity: m.uiAccess ? "medium" : "low", evidence: [`manifest: requestedExecutionLevel=${m.executionLevel || "?"}${m.uiAccess ? ", uiAccess=true (dapat mengendalikan jendela aplikasi lain yang lebih tinggi haknya)" : ""}${m.autoElevate ? ", autoElevate=true" : ""}`]});
  return out;
}
// [brand label, claim pattern, expected signer subject]. Short acronyms only count in upper case.
const BRANDS: [string, RegExp, RegExp][] = [
  ["Microsoft", /\bMicrosoft\b/i, /\bMicrosoft\b/i], ["Google", /\bGoogle\b/i, /\bGoogle\b/i], ["Adobe", /\bAdobe\b/i, /\bAdobe\b/i],
  ["WhatsApp", /\bWhatsApp\b/i, /WhatsApp|Meta Platforms|Facebook/i], ["Meta/Facebook", /\b(?:Facebook|Meta Platforms)\b/i, /Meta Platforms|Facebook/i],
  ["Telegram", /\bTelegram\b/i, /\bTelegram\b/i], ["Zoom", /\bZoom Video\b|^Zoom\b/i, /\bZoom\b/i], ["Mozilla", /\bMozilla\b|\bFirefox\b/i, /\bMozilla\b/i],
  ["Apple", /\bApple Inc\b|\biTunes\b/i, /\bApple\b/i], ["Oracle/Java", /\bOracle\b|\bJava\(TM\)/i, /\bOracle\b/i], ["NVIDIA", /\bNVIDIA\b/i, /\bNVIDIA\b/i],
  ["Intel", /\bIntel(?:\(R\)| Corporation)/i, /\bIntel\b/i], ["Discord", /\bDiscord\b/i, /\bDiscord\b/i], ["Steam/Valve", /\bValve\b|\bSteam\b/, /\bValve\b/i],
  ["AnyDesk", /\bAnyDesk\b/i, /\bAnyDesk\b/i], ["TeamViewer", /\bTeamViewer\b/i, /\bTeamViewer\b/i], ["Opera", /\bOpera (?:Norway|Software|Browser)\b/i, /\bOpera\b/i],
  ["BCA", /\bBank Central Asia\b|\bBCA\b|\bKlikBCA\b/, /Bank Central Asia|\bBCA\b/i], ["BRI", /\bBank Rakyat Indonesia\b|\bBRI\b|\bBRImo\b/, /Bank Rakyat Indonesia|\bBRI\b/i],
  ["Bank Mandiri", /\bBank Mandiri\b|\bLivin'? by Mandiri\b|^Mandiri\b/i, /\bMandiri\b/i], ["BNI", /\bBank Negara Indonesia\b|\bBNI\b/, /Bank Negara Indonesia|\bBNI\b/i],
  ["BSI", /\bBank Syariah Indonesia\b/i, /Bank Syariah Indonesia/i], ["DANA", /\bDANA\b/, /\bDANA\b/i], ["OVO", /\bOVO\b/, /\bOVO\b|Visionet/i],
  ["GoPay/Gojek", /\b(?:GoPay|Gojek|GoTo Gojek)\b/i, /\bGoTo\b|\bGojek\b|Aplikasi Karya Anak Bangsa/i], ["ShopeePay/Shopee", /\bShopee(?:Pay)?\b/i, /\bShopee\b|\bSea\b/i],
  ["Tokopedia", /\bTokopedia\b/i, /\bTokopedia\b/i], ["Kominfo/Komdigi", /\bKominfo\b|\bKomdigi\b|Kementerian Komunikasi/i, /Kementerian Komunikasi|Kominfo|Komdigi/i],
  ["DJP (Pajak)", /Direktorat Jenderal Pajak|\bDJP Online\b|\be-?Faktur\b/i, /Direktorat Jenderal Pajak/i], ["BPJS", /\bBPJS\b/, /\bBPJS\b/i], ["PLN", /\bPT PLN\b|\bPLN \(Persero\)/, /\bPLN\b/],
];
export type SignerInfo = {signer?: {subject?: string}; selfSigned?: boolean};
export function impersonation(version: Record<string, string> | undefined, auth: SignerInfo | undefined): Behavior[] {
  if (!version) return [];
  const subject = auth?.signer?.subject || "", out: Behavior[] = [];
  // Dotted identifiers ("Microsoft.PowerShell.Foo") are .NET assembly-name defaults, not a publisher claim.
  version = Object.fromEntries(Object.entries(version).filter(([, v]) => !/^[A-Za-z_]\w*(?:\.\w+)+$/.test(v)));
  for (const [brand, claim, signer] of BRANDS) {
    const strong = ["CompanyName", "LegalCopyright"].filter(k => version[k] && claim.test(version[k]));
    // Product/description fields only count when the brand leads the text ("Google Chrome Setup", not "Plugin for Adobe X").
    const weak = ["ProductName", "FileDescription", "InternalName", "OriginalFilename"].filter(k => version[k] && claim.test(version[k]) && version[k].search(claim) <= 2);
    if (!strong.length && !weak.length) continue;
    if (subject && signer.test(subject) && !auth?.selfSigned) continue;
    const why = !subject ? "file tidak memiliki tanda tangan Authenticode" : auth?.selfSigned ? `ditandatangani sertifikat swa-tanda-tangan "${subject.slice(0, 120)}"` : `ditandatangani oleh "${subject.slice(0, 120)}", bukan ${brand}`;
    const unsignedMs = !subject && brand === "Microsoft";
    out.push({id: "brand_impersonation", name: `Identitas file meniru ${brand}`, severity: strong.length && !unsignedMs ? "high" : "medium", evidence: [`version info ${[...strong, ...weak].slice(0, 3).map(k => `${k}="${version[k].slice(0, 80)}"`).join(", ")}`, why, unsignedMs ? "catatan: file bawaan Windows bisa ditandatangani lewat katalog sistem (tidak tersimpan di file), tetapi file unduhan yang mengaku Microsoft seharusnya bertanda tangan" : ""].filter(Boolean)});
    if (out.length >= 2) break;
  }
  return out;
}
