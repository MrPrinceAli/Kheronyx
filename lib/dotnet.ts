// Bounded ECMA-335 metadata reader (CLI header -> metadata root -> #~/#- tables, #Strings, #US, #GUID, #Blob) and
// heuristics for .NET stealers, RATs and loaders. Only names/strings are read; IL is never decompiled or executed.
import type { ToOffset } from "./pe-imports";
import type { Behavior, Severity } from "./behaviors";
import { redactSecrets } from "./behaviors";
export type DotnetMeta = {
  runtimeVersion: string; clrFlags: string[]; assemblyName?: string; mvid?: string; assemblyRefs: string[]; moduleRefs: string[];
  types: number; methods: number; memberRefs: number; userStrings: number; namespaces: string[]; notableTypes: string[];
  notableMemberRefs: string[]; pinvoke: string[]; resources: string[]; userStringsSample: string[]; obfuscator?: string[]; truncated?: boolean;
};
export type Dotnet = {meta: DotnetMeta; behaviors: Behavior[]; obfuscators: string[]; strings: string[]; names: string[]};
const MAX_ROWS = 150000, MAX_US = 20000, MAX_US_BYTES = 16 * 1024 * 1024;
// Coded index -> member tables (-1 = unused tag).
const CODED: Record<string, number[]> = {
  TDR: [2, 1, 0x1b], HC: [4, 8, 0x17], HCA: [6, 4, 1, 2, 8, 9, 10, 0, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b],
  HFM: [4, 8], HDS: [2, 6, 0x20], MRP: [2, 1, 0x1a, 6, 0x1b], HS: [0x14, 0x17], MDR: [6, 0x0a], MF: [4, 6], IMPL: [0x26, 0x23, 0x27], CAT: [-1, -1, 6, 0x0a, -1], RS: [0, 0x1a, 0x23, 1], TOMD: [2, 6],
};
// Column layout of tables 0x00..0x2C: 1/2/4 fixed bytes, S/G/B heap indexes, Txx simple table index, else coded index.
const SCHEMA = ["2 S G G G", "RS S S", "4 S S TDR T04 T06", "T04", "2 S B", "T06", "4 2 2 S B T08", "T08", "2 2 S", "T02 TDR", "MRP S B", "2 HC B", "HCA CAT B", "HFM B", "2 HDS B", "2 4 T02", "4 T04", "B", "T02 T14", "T14", "2 S TDR", "T02 T17", "T17", "2 S B", "2 T06 HS", "T02 MDR MDR", "S", "B", "2 MF S T1A", "4 T04", "4 4", "4", "4 2 2 2 2 4 B S S", "4", "4 4 4", "2 2 2 2 4 B S S B", "4 T23", "4 4 4 T23", "4 S B", "4 4 S S IMPL", "4 4 S IMPL", "T02 T02", "2 2 TOMD S", "MDR B", "T2A TDR"].map(s => s.split(" "));
const T = {Module: 0, TypeRef: 1, TypeDef: 2, MethodDef: 6, MemberRef: 0x0a, ModuleRef: 0x1a, ImplMap: 0x1c, Assembly: 0x20, AssemblyRef: 0x23, ManifestResource: 0x28};
const printable = (s: string, max = 200) => s.replace(/[\x00-\x1f\x7f]/g, "").slice(0, max);
function compressed(b: Buffer, p: number): [number, number] {
  if (p >= b.length) return [-1, 0]; const x = b[p];
  if (!(x & 0x80)) return [x, 1]; if ((x & 0xc0) === 0x80) return p + 2 <= b.length ? [(x & 0x3f) << 8 | b[p + 1], 2] : [-1, 0];
  if ((x & 0xe0) === 0xc0) return p + 4 <= b.length ? [((x & 0x1f) << 24 | b[p + 1] << 16 | b[p + 2] << 8 | b[p + 3]) >>> 0, 4] : [-1, 0]; return [-1, 0];
}
export function readMetadata(b: Buffer, toOffset: ToOffset, cliRva: number, deadline: number) {
  const cli = toOffset(cliRva, 72); if (cli < 0 || b.readUInt32LE(cli) < 72) throw new Error("Header CLI .NET tidak valid.");
  const flagsValue = b.readUInt32LE(cli + 16), mdRva = b.readUInt32LE(cli + 8), mdSize = Math.min(b.readUInt32LE(cli + 12), 256 * 1024 * 1024), m = toOffset(mdRva, Math.min(mdSize, 32));
  if (m < 0 || mdSize < 32 || b.readUInt32LE(m) !== 0x424a5342) throw new Error("Metadata root .NET tidak valid.");
  const md = b.subarray(m, Math.min(b.length, m + mdSize)), verLen = md.readUInt32LE(12); if (verLen > 256 || 16 + verLen + 4 > md.length) throw new Error("Versi metadata tidak valid.");
  const runtimeVersion = printable(md.toString("latin1", 16, 16 + verLen).split("\0")[0], 40);
  let p = 16 + verLen + 2; const streamCount = Math.min(md.readUInt16LE(p), 16); p += 2;
  const streams = new Map<string, Buffer>();
  for (let i = 0; i < streamCount; i++) {
    if (p + 9 > md.length) throw new Error("Header stream metadata terpotong.");
    const off = md.readUInt32LE(p), size = md.readUInt32LE(p + 4), end = md.indexOf(0, p + 8); if (end < 0 || end - p - 8 > 32) throw new Error("Nama stream metadata tidak valid.");
    const name = md.toString("latin1", p + 8, end); p = p + 8 + (end - p - 8 + 4 & ~3);
    // Obfuscators add decoy duplicate streams; like the CLR loader (and dnlib), the last one wins.
    if (off <= md.length) streams.set(name, md.subarray(off, Math.min(md.length, off + size)));
  }
  const tables = streams.get("#~") || streams.get("#-"), strings = streams.get("#Strings") || Buffer.alloc(0), us = streams.get("#US") || Buffer.alloc(0), guids = streams.get("#GUID") || Buffer.alloc(0), blobs = streams.get("#Blob") || Buffer.alloc(0);
  if (!tables || tables.length < 24) throw new Error("Stream tabel metadata tidak ada.");
  const heap = tables[6], valid = tables.readBigUInt64LE(8), rows: number[] = new Array(64).fill(0); p = 24;
  for (let i = 0; i < 64; i++) if (valid >> BigInt(i) & 1n) {if (p + 4 > tables.length) throw new Error("Jumlah baris tabel terpotong."); rows[i] = tables.readUInt32LE(p); p += 4; if (rows[i] > 0xffffff) throw new Error("Jumlah baris tabel tidak wajar.");}
  if (heap & 0x40) p += 4;
  const strSize = heap & 1 ? 4 : 2, guidSize = heap & 2 ? 4 : 2, blobSize = heap & 4 ? 4 : 2;
  const colSize = (c: string) => c === "S" ? strSize : c === "G" ? guidSize : c === "B" ? blobSize : /^\d$/.test(c) ? Number(c) : /^T[0-9A-F]{2}$/.test(c) ? rows[parseInt(c.slice(1), 16)] < 65536 ? 2 : 4
    : (() => {const list = CODED[c], bits = Math.ceil(Math.log2(list.length)); return Math.max(...list.map(t => t < 0 ? 0 : rows[t])) < 1 << 16 - bits ? 2 : 4;})();
  const layout: {offset: number; rowSize: number; cols: number[]; sizes: number[]}[] = [];
  for (let t = 0; t < SCHEMA.length; t++) {
    const sizes = SCHEMA[t].map(colSize), cols: number[] = []; let o = 0; for (const s of sizes) {cols.push(o); o += s;}
    layout.push({offset: p, rowSize: o, cols, sizes}); p += rows[t] * o;
    if (p > tables.length) throw new Error("Tabel metadata terpotong.");
  }
  const cell = (t: number, r: number, c: number) => {const l = layout[t], q = l.offset + r * l.rowSize + l.cols[c]; return l.sizes[c] === 4 ? tables.readUInt32LE(q) : l.sizes[c] === 2 ? tables.readUInt16LE(q) : tables[q];};
  const str = (i: number) => {if (!i || i >= strings.length) return ""; const e = strings.indexOf(0, i); return printable(strings.toString("utf8", i, e < 0 ? Math.min(strings.length, i + 512) : Math.min(e, i + 512)));};
  const blob = (i: number) => {const [n, k] = compressed(blobs, i); return n < 0 || i + k + n > blobs.length ? Buffer.alloc(0) : blobs.subarray(i + k, i + k + Math.min(n, 4096));};
  const guid = (i: number) => {if (!i || i * 16 > guids.length) return ""; const g = guids.subarray((i - 1) * 16, i * 16); return `${g.readUInt32LE(0).toString(16).padStart(8, "0")}-${g.readUInt16LE(4).toString(16).padStart(4, "0")}-${g.readUInt16LE(6).toString(16).padStart(4, "0")}-${g.toString("hex", 8, 10)}-${g.toString("hex", 10, 16)}`;};
  let truncated = false;
  const each = <X>(t: number, f: (r: number) => X): X[] => {const out: X[] = [], n = Math.min(rows[t], MAX_ROWS); if (rows[t] > MAX_ROWS) truncated = true; for (let r = 0; r < n; r++) {if ((r & 1023) === 1023 && Date.now() > deadline) {truncated = true; break;} out.push(f(r));} return out;};
  const full = (ns: string, name: string) => ns ? `${ns}.${name}` : name;
  const typeRefs = each(T.TypeRef, r => full(str(cell(T.TypeRef, r, 2)), str(cell(T.TypeRef, r, 1))));
  const typeDefs = each(T.TypeDef, r => full(str(cell(T.TypeDef, r, 2)), str(cell(T.TypeDef, r, 1))));
  const methods = each(T.MethodDef, r => str(cell(T.MethodDef, r, 3)));
  const moduleRefs = each(T.ModuleRef, r => str(cell(T.ModuleRef, r, 0)));
  const parent = (v: number) => {const tag = v & 7, i = (v >> 3) - 1; return tag === 1 ? typeRefs[i] : tag === 0 ? typeDefs[i] : tag === 2 ? moduleRefs[i] : tag === 3 ? methods[i] : "?";};
  const memberRefs = each(T.MemberRef, r => ({name: `${parent(cell(T.MemberRef, r, 0)) || "?"}::${str(cell(T.MemberRef, r, 1))}`, sig: cell(T.MemberRef, r, 2)}));
  const pinvoke = each(T.ImplMap, r => {const f = cell(T.ImplMap, r, 1), target = f & 1 ? methods[(f >> 1) - 1] : ""; return `${(moduleRefs[cell(T.ImplMap, r, 3) - 1] || "?").toLowerCase()}!${str(cell(T.ImplMap, r, 2)) || target || "?"}`;});
  const assembly = rows[T.Assembly] ? `${str(cell(T.Assembly, 0, 7))} v${[1, 2, 3, 4].map(c => cell(T.Assembly, 0, c)).join(".")}` : undefined;
  const assemblyRefs = each(T.AssemblyRef, r => `${str(cell(T.AssemblyRef, r, 6))} v${[0, 1, 2, 3].map(c => cell(T.AssemblyRef, r, c)).join(".")}`);
  const resources = each(T.ManifestResource, r => str(cell(T.ManifestResource, r, 2)));
  const mvid = rows[T.Module] ? guid(cell(T.Module, 0, 2)) : "";
  // #US: compressed length + UTF-16LE + 1 terminal flag byte.
  const userStrings: string[] = [];
  for (let q = 1, budget = Math.min(us.length, MAX_US_BYTES); q < budget && userStrings.length < MAX_US;) {
    const [n, k] = compressed(us, q); if (n < 0 || q + k + n > us.length) break; q += k;
    if (n > 1) {const s = us.toString("utf16le", q, q + (n - 1 & ~1)); if (s.length >= 4) userStrings.push(s.length > 2000 ? s.slice(0, 2000) : s);}
    q += n; if ((userStrings.length & 1023) === 1023 && Date.now() > deadline) {truncated = true; break;}
  }
  const loadBytes = memberRefs.filter(x => /^System\.(?:Reflection\.Assembly|AppDomain)::Load$/.test(x.name) && blob(x.sig).subarray(2).includes(Buffer.from([0x1d, 0x05]))).length > 0;
  const flags = [[1, "ILONLY"], [2, "32BITREQUIRED"], [8, "STRONGNAMESIGNED"], [0x10, "NATIVE_ENTRYPOINT"], [0x20000, "32BITPREFERRED"]].filter(([f]) => flagsValue & (f as number)).map(([, n]) => n as string);
  return {runtimeVersion, flags, assembly, mvid, typeRefs, typeDefs, methods, memberRefs: memberRefs.map(x => x.name), pinvoke, moduleRefs, assemblyRefs, resources, userStrings, loadBytes, truncated, rowsTotal: {types: rows[T.TypeDef], methods: rows[T.MethodDef], memberRefs: rows[T.MemberRef]}};
}
type Raw = ReturnType<typeof readMetadata>;
const OBFUSCATORS: [string, RegExp][] = [
  ["ConfuserEx", /ConfusedByAttribute|\bConfuser(?:Ex)?\b/], [".NET Reactor", /Eziriz|\.NET Reactor/], ["SmartAssembly", /\bSmartAssembly\b|PoweredByAttribute/], ["Eazfuscator.NET", /Eazfuscator/i],
  ["Babel", /BabelObfuscatorAttribute|BabelAttribute|Babel\.NET/], ["Dotfuscator", /DotfuscatorAttribute/], ["Agile.NET", /ObfuscatedByAgileDotNet|AgileDotNet|CliSecure/], ["Crypto Obfuscator", /CryptoObfuscator/],
  ["Goliath", /ObfuscatedByGoliath/], ["DeepSea", /DeepSeaObfuscator/], ["NETGuard", /\bNETGuard\b/], ["KoiVM", /\bKoiVM\b/], ["Xenocode", /Xenocode/], ["Obfuscar", /\bObfuscar\b/],
];
// Heuristic family markers (strings/type names seen in public reports). Phrased as "mirip": shared code and false positives exist.
const FAMILIES: [string, RegExp][] = [
  ["RedLine", /\bRedLine\b|\bScannedBrowser\b|\bScanningArgs\b|\bScannedCookie\b|tempuri\.org\/Entity\/Id\d+/], ["AgentTesla", /AgentTesla|%startupfolder%|%insfolder%|%insname%|<br>(?:PCName|OSFullName|UserName)\s*:/i],
  ["AsyncRAT", /\bAsyncRAT\b|\bAsyncClient\b|\bServersignature\b|\bAnti_Analysis\b|\bDetectManufacturer\b/], ["Quasar RAT", /Quasar\.Client|Quasar\.Common|\bQuasarRAT\b|\bxRAT\b/], ["njRAT", /\bnjRAT\b|\|'\|'\||netsh firewall add allowedprogram/i],
  ["DCRat", /\bDCRat\b|DarkCrystal/i], ["XWorm", /\bXWorm\b|<Xwormmm>/i], ["StormKitty", /StormKitty/], ["Snake Keylogger", /SnakeKeylogger|\$%TelegramDv\$|Snake Tracker/i], ["Stealerium", /\bStealerium\b/],
  ["Lumma", /LummaC2|\bLumma ?Stealer\b|TeslaBrowser\/5\.5/], ["Vidar", /\bVidar\b(?! ?Holen)/], ["Raccoon", /RaccoonStealer|Raccoon Stealer|recordbreaker/i], ["Remcos", /\bRemcos\b|Breaking-Security\.Net/i], ["NanoCore", /\bNanoCore\b/], ["LokiBot", /fuckav\.ru|\bLokiBot\b/i],
];
const BROWSER = /\\(?:Login Data|Web Data|Local State|Cookies)\b|^(?:Login Data|Web Data|Local State|logins\.json|key[34]\.db|cookies\.sqlite|signons\.sqlite)$|logins\.json|key4\.db|signons\.sqlite|encrypted_key|password_value|SELECT\s+(?:origin_url|action_url|host_key|name_on_card)|moz_cookies|\\(?:Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave-Browser|Opera Software|Yandex\\YandexBrowser|Mozilla\\Firefox)\\/i;
const SESSIONS = /Telegram Desktop\\tdata|\\tdata\b|discord(?:canary|ptb)?\\Local Storage|Local Storage\\leveldb|dQw4w9WgXcQ|\[\\w-\]\{2[46]\}\\\.|mfa\\\.\[|FileZilla\\(?:recentservers|sitemanager)\.xml|Steam\\(?:config|ssfn)|\bssfn\*|\\NordVPN\\|OpenVPN Connect\\profiles|Pidgin\\accounts\.xml|Foxmail|\\\.minecraft\\|Authy Desktop/i;
const WALLETS = /wallet\.dat|\\(?:Exodus|Electrum|Atomic|Armory|Bytecoin|Coinomi|Jaxx|Guarda|Zcash|Monero|Ethereum\\keystore)\b|exodus\.wallet|nkbihfbeogaeaoehlefnkodbefgpgknn|ibnejdfjmmkpcnlpebklmnkoeoihofec|fhbohimaelbohpjbbldcngcnapndodjp|hnfanknocfeofbddgcijnmhnfnkdnaad|bfnaelmomeimhlpmgjnjophhpkkoljpa|egjidjbpglichdcondbcbdnbeeppgdph|\bMetaMask\b/i;
const ADDRESS_RE = /\(bc1\||\[13\]\[a-km-zA-HJ-NP-Z1-9\]|0x\[a-fA-F0-9\]\{40\}|\^T\[A-Za-z1-9\]\{33\}|\^\(?:?bc1|\^4\[0-9AB\]/;
const ANTI = /\b(?:vmware|virtualbox|vbox(?:service|tray|mouse|guest)|vmtoolsd|qemu|SbieDll\.dll|sandboxie|cuckoo|wine_get_unix_file_name|Win32_(?:ComputerSystem|VideoController|PortConnector)|dnspy|de4dot|processhacker|wireshark|fiddler|x64dbg|ollydbg|ida64|HTTPDebugger|vboxmrxnp)\b/i;
const PERSIST = /Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?\b|schtasks(?:\.exe)?["']?\s*\/create|\/create\s+\/(?:sc|tn)\b|Start Menu\\Programs\\Startup|\\Winlogon\b/i;
const EVASION = /(?:Add|Set)-MpPreference|DisableRealtimeMonitoring|ExclusionPath|netsh\s+(?:advfirewall|firewall)|vssadmin\s+delete|bcdedit.{0,40}recoveryenabled|DisableAntiSpyware/i;
const INJECT = /^(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread(?:Ex)?|NtUnmapViewOfSection|ZwUnmapViewOfSection|SetThreadContext|Wow64SetThreadContext|NtWriteVirtualMemory|QueueUserAPC|NtCreateThreadEx|RtlCreateUserThread)$/;
export function familyMarkers(texts: Iterable<string>): Behavior[] {
  const hits = new Map<string, Set<string>>(); let n = 0;
  for (const s of texts) {
    if (++n > 60000) break; const t = s.length > 600 ? s.slice(0, 600) : s;
    for (const [family, re] of FAMILIES) if (re.test(t)) {let set = hits.get(family); if (!set) hits.set(family, set = new Set()); if (set.size < 3) set.add(redactSecrets(t).slice(0, 120));}
  }
  return [...hits].slice(0, 3).map(([family, set]) => ({id: "family_marker", name: `Mirip keluarga malware ${family} (penanda string)`, severity: "high" as Severity, evidence: [...set].map(x => `"${x}"`)}));
}
export function dotnetAnalysis(x: Raw): Dotnet {
  const refs = x.memberRefs, names = [...x.typeDefs, ...x.typeRefs], out: Behavior[] = [], used = new Set<string>(), usedStrings = new Set<string>();
  const mr = (re: RegExp) => {const hit = [...new Set(refs.filter(r => re.test(r)))].slice(0, 6); hit.forEach(h => used.add(h)); return hit;};
  const pi = (re: RegExp) => [...new Set(x.pinvoke.filter(f => re.test(f.split("!").pop() || "")))].slice(0, 8);
  const us = (re: RegExp, n = 4) => {const hit: string[] = []; for (const s of x.userStrings) if (re.test(s)) {hit.push(redactSecrets(s).slice(0, 120)); usedStrings.add(s); if (hit.length >= n) break;} return hit;};
  const add = (id: string, name: string, severity: Severity, evidence: string[]) => {const e = evidence.filter(Boolean); if (e.length) out.push({id, name, severity, evidence: e.slice(0, 6)}); return e.length > 0;};
  const list = (label: string, xs: string[]) => xs.length ? `${label}: ${xs.join(", ").slice(0, 260)}` : "";
  const has = (id: string) => out.some(b => b.id === id);
  const unprotect = [...mr(/Cryptography\.ProtectedData::Unprotect$/), ...pi(/^(?:CryptUnprotectData|BCryptDecrypt)$/)];
  const browser = us(BROWSER), sessions = us(SESSIONS), wallets = us(WALLETS);
  if (browser.length || sessions.length) add("net_credential_theft", "Mencuri data browser, kredensial, atau sesi aplikasi (.NET)", browser.length + sessions.length >= 2 || unprotect.length && browser.length ? "high" : "medium", [list("string", [...browser, ...sessions].slice(0, 5)), list("API dekripsi", unprotect)]);
  if (wallets.length) add("net_wallet_theft", "Mencuri dompet kripto (.NET)", wallets.length >= 2 ? "high" : "medium", [list("string", wallets)]);
  const clip = [...mr(/Windows\.Forms\.Clipboard::(?:GetText|SetText|GetDataObject|SetDataObject|ContainsText)$|Windows\.Clipboard::(?:GetText|SetText)$/), ...pi(/^(?:GetClipboardData|SetClipboardData|OpenClipboard|AddClipboardFormatListener)$/)], addr = us(ADDRESS_RE, 3);
  if (clip.length && addr.length) add("net_clipper", "Pola clipper (mengganti alamat dompet kripto di clipboard)", "high", [list("API", clip), list("pola alamat", addr)]);
  else if (clip.length) add("net_clipboard", "Mengakses clipboard", "low", [list("API", clip)]);
  const keys = pi(/^(?:SetWindowsHookEx[AW]?|GetAsyncKeyState|GetKeyboardState|GetKeyState|MapVirtualKey(?:Ex)?[AW]?|ToUnicode(?:Ex)?|GetRawInputData)$/), keyStr = us(/^\[(?:ENTER|BACKSPACE|TAB|CAPSLOCK|ESC|SPACE|DEL)\]$|keylog/i, 2);
  if (keys.some(k => /Hook|Async|RawInput/.test(k))) add("net_keylogger", "Perekaman ketikan (keylogger)", keys.length >= 2 || keyStr.length ? "high" : "medium", [list("P/Invoke", keys), list("string", keyStr)]);
  const screen = [...mr(/Drawing\.Graphics::CopyFromScreen$/), ...pi(/^(?:BitBlt|PrintWindow)$/)];
  if (screen.length) add("net_screenshot", "Mengambil tangkapan layar", "low", [list("API", screen)]);
  const inject = pi(INJECT), injectStr = us(/^(?:VirtualAllocEx|WriteProcessMemory|NtUnmapViewOfSection|ZwUnmapViewOfSection|SetThreadContext|Wow64SetThreadContext|CreateRemoteThread|NtWriteVirtualMemory)$/, 6), dyn = mr(/InteropServices\.Marshal::GetDelegateForFunctionPointer$/);
  const injectAll = [...new Set([...inject.map(f => f.split("!").pop()!), ...dyn.length ? injectStr : []])];
  if (injectAll.length >= 2) add("net_injection", "Injeksi kode ke proses lain (P/Invoke)", "high", [list("P/Invoke", inject), dyn.length && injectStr.length ? list("API diresolusi dinamis (GetDelegateForFunctionPointer)", injectStr) : "", injectAll.some(f => /Unmap/.test(f)) && injectAll.some(f => /SetThreadContext/.test(f)) ? "pola process hollowing (RunPE)" : ""]);
  const load = mr(/^System\.(?:Reflection\.Assembly|AppDomain)::Load$/), invoke = mr(/Reflection\.(?:Assembly::get_EntryPoint|MethodBase::Invoke|MethodInfo::Invoke)$|^System\.Activator::CreateInstance$/), unpack = mr(/Cryptography\.\w+::CreateDecryptor$|^System\.Convert::FromBase64String$|Compression\.(?:GZipStream|DeflateStream)::\.ctor$|Resources\.ResourceManager::GetObject$|Assembly::GetManifestResourceStream$/);
  // Assembly.Load(string) is routine plugin loading; only the byte[] overload (code from memory) is reported.
  if (load.length && x.loadBytes) add("net_reflective_load", "Memuat assembly .NET dari memori (reflective loading)", invoke.length && unpack.length ? "high" : "medium", [list("API", [...load, ...invoke].slice(0, 5)), "Assembly.Load dipanggil dengan byte[] (kode dari memori, bukan file)", list("dekode/dekripsi", unpack)]);
  const anti = [...new Set([...us(ANTI, 6).map(s => s.match(ANTI)?.[0] || s), ...mr(/Diagnostics\.Debugger::get_IsAttached$/).map(() => "Debugger.IsAttached"), ...pi(/^(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|NtSetInformationThread)$/)])];
  if (anti.length >= 2) add("net_anti_analysis", "Teknik anti-VM/anti-debug (.NET)", anti.length >= 4 ? "medium" : "low", [list("penanda", anti.slice(0, 8))]);
  const persist = us(PERSIST, 3); if (persist.length) add("net_persistence", "Persistensi (Run key/tugas terjadwal/Startup)", "medium", [list("string", persist), list("API", mr(/Win32\.RegistryKey::SetValue$/))]);
  const evasion = us(EVASION, 3); if (evasion.length) add("net_defense_evasion", "Melemahkan Windows Defender/firewall/pemulihan", "high", [list("string", evasion)]);
  const download = mr(/Net\.WebClient::(?:DownloadData|DownloadFile|DownloadString|OpenRead)(?:Async|TaskAsync)?$|Net\.Http\.HttpClient::(?:GetByteArrayAsync|GetStreamAsync)$/), start = mr(/Diagnostics\.Process::Start$/);
  if (download.length && start.length) add("net_download_exec", "Mengunduh lalu menjalankan program (.NET)", "medium", [list("API", [...download, ...start])]);
  const exfilApi = mr(/Net\.Mail\.SmtpClient::Send(?:Async|MailAsync)?$|Net\.FtpWebRequest::|Net\.WebClient::Upload(?:Data|File|String|Values)(?:Async|TaskAsync)?$|Net\.Http\.HttpClient::PostAsync$/), exfilStr = us(/api\.telegram\.org|discord(?:app)?\.com\/api\/webhooks|smtp\.[a-z0-9-]+\.[a-z]{2,}|ftp:\/\//i, 3);
  if ((has("net_credential_theft") || has("net_wallet_theft")) && (exfilApi.length || exfilStr.length)) add("net_stealer", "Pola pencuri data .NET (stealer)", exfilStr.some(s => /telegram|discord/i.test(s)) ? "critical" : "high", [`kombinasi: ${["net_credential_theft", "net_wallet_theft", "net_keylogger", "net_screenshot", "net_clipper"].filter(has).join(" + ")}`, list("kanal", [...exfilStr, ...exfilApi].slice(0, 4))]);
  const net = mr(/Net\.Sockets\.(?:TcpClient::(?:Connect|\.ctor)|Socket::(?:Connect|BeginConnect|ConnectAsync))$|Net\.Security\.SslStream::\.ctor$/), shell = us(/^cmd(?:\.exe)?$|^\/c\s|^powershell(?:\.exe)?$/i, 2), webcam = pi(/^capCreateCaptureWindow[AW]?$/);
  const rat = [["net_keylogger", "keylogger"], ["net_screenshot", "tangkapan layar"], ["net_clipboard", "clipboard"], ["net_clipper", "clipper"], ["net_persistence", "persistensi"]].filter(([id]) => has(id)).map(([, l]) => l);
  if (shell.length && start.length) rat.push("shell jarak jauh"); if (webcam.length) rat.push("webcam");
  if (net.length && rat.length >= 2) add("net_rat", "Pola remote access trojan (RAT) .NET", "high", [list("koneksi", net.slice(0, 3)), `kemampuan: ${rat.join(", ")}`]);
  const obfuscators: string[] = [];
  for (const [label, re] of OBFUSCATORS) if (names.some(n => re.test(n)) || x.userStrings.slice(0, 5000).some(s => re.test(s))) obfuscators.push(label);
  const own = [...x.typeDefs, ...x.methods].filter(n => n && n !== "<Module>" && !/^[.<]/.test(n)).slice(0, 5000), mangled = own.filter(n => /[^\x20-\x7e]|^[^A-Za-z_]/.test(n) || /^[A-Za-z]{1,2}$/.test(n.split(".").pop() || n)).length;
  if (own.length >= 30 && mangled / own.length > 0.4) obfuscators.push(`nama tipe/metode teracak (${Math.round(mangled / own.length * 100)}%)`);
  if (names.some(n => /SuppressIldasmAttribute$/.test(n))) obfuscators.push("SuppressIldasm (anti-dekompilasi)");
  // Compact, AI-friendly summary.
  const NOTE_TYPE = /stealer|grabber|keylog|inject|runpe|hollow|clipper|miner|payload|antivm|anti_?(?:analysis|debug|vm)|sandbox|wallet|discord|telegram|cookie|screenshot|webcam|botnet|ransom|scannedbrowser|chromium|gecko/i;
  const NOTE_REF = /Reflection\.Assembly::Load|MethodBase::Invoke|Diagnostics\.Process::Start|Win32\.RegistryKey::(?:SetValue|CreateSubKey)|Net\.WebClient::|Net\.Sockets\.|Net\.Mail\.|Clipboard::|CopyFromScreen|Marshal::GetDelegateForFunctionPointer|ManagementObjectSearcher::|ProtectedData::Unprotect/;
  const namespaces = [...new Set(x.typeDefs.map(n => n.includes(".") ? n.slice(0, n.lastIndexOf(".")) : "").filter(Boolean))].slice(0, 8);
  const interesting = /https?:\/\/|\\|\.exe\b|\.dll\b|\.bat\b|\.ps1\b|\.vbs\b|powershell|cmd\b|HKEY_|Software\\|SELECT |@[a-z0-9-]+\.[a-z]{2,}|\bbot\d|chat_id|webhook|password|token/i;
  const sample = [...new Set([...usedStrings, ...x.userStrings.filter(s => interesting.test(s))])].slice(0, 15).map(s => redactSecrets(s).slice(0, 140));
  const meta: DotnetMeta = {runtimeVersion: x.runtimeVersion, clrFlags: x.flags, ...x.assembly ? {assemblyName: x.assembly.slice(0, 120)} : {}, ...x.mvid ? {mvid: x.mvid} : {},
    assemblyRefs: x.assemblyRefs.slice(0, 15).map(s => s.slice(0, 80)), moduleRefs: x.moduleRefs.slice(0, 10).map(s => s.slice(0, 60)), types: x.rowsTotal.types, methods: x.rowsTotal.methods, memberRefs: x.rowsTotal.memberRefs, userStrings: x.userStrings.length,
    namespaces: namespaces.map(s => s.slice(0, 80)), notableTypes: [...new Set(x.typeDefs.filter(n => NOTE_TYPE.test(n)))].slice(0, 12).map(s => s.slice(0, 80)),
    notableMemberRefs: [...new Set([...used, ...refs.filter(r => NOTE_REF.test(r))])].slice(0, 20).map(s => s.slice(0, 90)), pinvoke: [...new Set(x.pinvoke)].slice(0, 15).map(s => s.slice(0, 70)),
    resources: x.resources.slice(0, 10).map(s => s.slice(0, 80)), userStringsSample: sample, ...obfuscators.length ? {obfuscator: obfuscators} : {}, ...x.truncated ? {truncated: true} : {}};
  if (obfuscators.length) out.push({id: "net_obfuscator", name: "Proteksi/obfuscator .NET terdeteksi", severity: "medium", evidence: [obfuscators.join(", ")]});
  return {meta, behaviors: out, obfuscators, strings: x.userStrings.slice(0, 3000), names: [...x.typeDefs.slice(0, 5000), ...x.typeRefs.slice(0, 2000), ...x.resources]};
}
export function parseDotnet(b: Buffer, toOffset: ToOffset, cliRva: number, deadline: number): Dotnet {return dotnetAnalysis(readMetadata(b, toOffset, cliRva, deadline));}
