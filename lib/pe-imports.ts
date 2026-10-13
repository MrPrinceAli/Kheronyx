// Bounded PE import-table reader (IMAGE_IMPORT_DESCRIPTOR + delay-load descriptors) and API-group heuristics.
export type PeImport = {dll: string; functions: string[]; count: number; delay?: boolean};
export type ToOffset = (rva: number, length?: number) => number;
const MAX_DLLS = 128, MAX_FUNCTIONS = 4000;
const cstr = (b: Buffer, off: number, max = 256) => {if (off < 0 || off >= b.length) return ""; const end = b.indexOf(0, off), s = b.toString("latin1", off, Math.min(end < 0 ? b.length : end, off + max)); return /^[\x21-\x7e]+$/.test(s) ? s : "";};
export function readImports(b: Buffer, toOffset: ToOffset, plus: boolean, importRva: number, delayRva = 0): PeImport[] {
  const out: PeImport[] = []; let total = 0; const width = plus ? 8 : 4;
  const thunks = (rva: number) => {
    const names: string[] = []; let count = 0, t = toOffset(rva);
    for (; t >= 0 && t + width <= b.length && total < MAX_FUNCTIONS; t += width) {
      const lo = b.readUInt32LE(t), hi = plus ? b.readUInt32LE(t + 4) : 0; if (!lo && !hi) break;
      const ordinal = plus ? hi & 0x80000000 : lo & 0x80000000; count++; total++;
      const hint = ordinal ? -1 : toOffset(lo & 0x7fffffff, 3), name = ordinal ? `#${lo & 0xffff}` : hint < 0 ? "" : cstr(b, hint + 2);
      if (name && names.length < 400) names.push(name);
    }
    return {names, count};
  };
  const walk = (rva: number, size: number, delay: boolean) => {
    let q = rva ? toOffset(rva, size) : -1;
    for (let i = 0; q >= 0 && q + size <= b.length && i < MAX_DLLS && out.length < MAX_DLLS && total < MAX_FUNCTIONS; i++, q += size) {
      // Delay descriptors: attrs, name, hmod, IAT, INT. Only RVA-based (attrs & 1) descriptors are meaningful.
      const nameRva = b.readUInt32LE(q + (delay ? 4 : 12)), lookup = delay ? b.readUInt32LE(q + 16) : b.readUInt32LE(q) || b.readUInt32LE(q + 16);
      if (!nameRva && !lookup) break; if (delay && !(b.readUInt32LE(q) & 1)) continue;
      const dll = cstr(b, toOffset(nameRva, 1), 200).toLowerCase(); if (!dll) continue;
      const {names, count} = thunks(lookup); out.push({dll, functions: names, count, ...delay ? {delay} : {}});
    }
  };
  walk(importRva, 20, false); if (delayRva) walk(delayRva, 32, true);
  return out;
}
type Group = {id: string; name: string; severity: "low" | "medium" | "high"; match: RegExp; when?: (hit: Set<string>) => boolean};
const GROUPS: Group[] = [
  {id: "injection", name: "Injeksi kode ke proses lain", severity: "high", match: /^(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread(?:Ex)?|NtUnmapViewOfSection|ZwUnmapViewOfSection|QueueUserAPC|SetThreadContext|Wow64SetThreadContext|NtWriteVirtualMemory|RtlCreateUserThread|NtCreateThreadEx)$/, when: h => h.size >= 2},
  {id: "keylogger", name: "Perekaman ketikan (keylogger)", severity: "high", match: /^(?:SetWindowsHookEx[AW]?|GetAsyncKeyState|GetRawInputData)$/, when: h => [...h].some(f => /Hook|Async/.test(f))},
  {id: "credential_theft", name: "Akses kredensial/data browser", severity: "high", match: /^(?:CryptUnprotectData|CredEnumerate[AW]|CredRead[AW]|LsaRetrievePrivateData|VaultEnumerateItems|VaultGetItem)$/},
  {id: "download_execute", name: "Mengunduh lalu menjalankan program", severity: "medium", match: /^(?:URLDownloadToFile[AW]?|URLDownloadToCacheFile[AW]|InternetOpenUrl[AW]|InternetReadFile|WinHttpOpen|WinHttpSendRequest|WinHttpReadData|ShellExecute(?:Ex)?[AW]?|WinExec|CreateProcess[AW]|CreateProcessAsUser[AW]|CreateProcessWithLogonW)$/, when: h => [...h].some(f => /URLDownload/.test(f)) || [...h].some(f => /Internet|WinHttp/.test(f)) && [...h].some(f => /Exec|CreateProcess/.test(f))},
  {id: "anti_analysis", name: "Teknik anti-debug/anti-analisis", severity: "low", match: /^(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|ZwQueryInformationProcess|NtSetInformationThread|OutputDebugString[AW])$/, when: h => [...h].filter(f => f !== "IsDebuggerPresent").length >= 1 && h.size >= 2},
  {id: "persistence", name: "Persistensi lewat registry/layanan", severity: "medium", match: /^(?:RegSetValueEx[AW]|RegCreateKeyEx[AW]|CreateService[AW]|ChangeServiceConfig2?[AW])$/, when: h => [...h].some(f => /Service/.test(f)) || h.size >= 2},
  {id: "screen_clipboard", name: "Tangkapan layar/clipboard", severity: "low", match: /^(?:BitBlt|GetDC|GetWindowDC|CreateCompatibleBitmap|GetClipboardData|SetClipboardData)$/, when: h => h.has("GetClipboardData") || h.has("BitBlt") && (h.has("GetDC") || h.has("GetWindowDC")) && h.has("CreateCompatibleBitmap")},
  {id: "file_encryption", name: "Enkripsi file massal (mirip ransomware)", severity: "medium", match: /^(?:CryptEncrypt|BCryptEncrypt|CryptGenKey|CryptImportKey|FindFirstFile(?:Ex)?[AW]|FindNextFile[AW]|MoveFileEx[AW])$/, when: h => [...h].some(f => /Encrypt/.test(f)) && [...h].some(f => /FindFirstFile/.test(f))},
];
export function importBehaviors(imports: PeImport[]) {
  const all = new Set<string>(), where = new Map<string, string>();
  for (const i of imports) for (const f of i.functions) {all.add(f); if (!where.has(f)) where.set(f, i.dll);}
  return GROUPS.flatMap(g => {
    const hit = new Set([...all].filter(f => g.match.test(f))); if (!hit.size || g.when && !g.when(hit)) return [];
    return [{id: g.id, name: g.name, severity: g.severity, evidence: [...hit].slice(0, 8).map(f => `${where.get(f)}!${f}`)}];
  });
}
