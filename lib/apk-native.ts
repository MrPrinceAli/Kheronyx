import { unzipEntry, type ZipEntry } from "./zip";
import { parseElf } from "./elf";
import { redactSecrets, revealable, trackedString, type Behavior, type Signals } from "./behaviors";
// Scans each native library once per unique name (preferring arm64-v8a), smallest app-specific libraries first,
// within a byte and time budget. Strings feed the normal URL/Telegram/webhook/lure rules via `sig`.
export type NativeLib = {name: string; abi: string; size: number; machine?: string; needed?: string[]; symbols?: string[]; jni?: string[]; jniCount?: number; jniOnLoad?: boolean; exports?: number; antiDebug?: string[]; findings?: string[]; skipped?: string};
const ABI = ["arm64-v8a", "armeabi-v7a", "armeabi", "x86_64", "x86"];
// Engine/runtime libraries whose strings say nothing about the app (Flutter's own code lives in libapp.so, still scanned).
const FRAMEWORK = /^lib(?:flutter|unity|il2cpp|monosgen-2\.0|mono-native|xamarin-app|reactnativejni|hermes|jsc|c\+\+_shared|fbjni|yoga|glog|folly[\w-]*|tensorflowlite[\w-]*|opencv[\w-]*|av(?:codec|format|util|filter|device)[\w-]*|sw(?:scale|resample)[\w-]*|crashlytics[\w-]*|sentry[\w-]*|bugly[\w-]*|gdx[\w-]*|realm-jni|sqlcipher|conceal|imagepipeline|native-imagetranscoder|static-webp|gifimage|j2v8|chromium_android_linker|ffmpeg[\w-]*|mediapipe[\w-]*|filament[\w-]*|skia[\w-]*)\.so$/i;
const LIB_MAX = 48 * 1024 * 1024, TOTAL = 192 * 1024 * 1024, MAX_LIBS = 24;
export function nativeScan(buffer: Buffer, entries: ZipEntry[], sig: Signals, deadline: number) {
  const byName = new Map<string, {e: ZipEntry; abi: string}>(), abis = new Set<string>();
  for (const e of entries) {
    const lib = e.name.match(/^lib\/([^/]+)\/([^/]+\.so)$/); if (!lib && !/^assets\/.+\.so$/i.test(e.name)) continue;
    const abi = lib ? lib[1] : "assets", name = lib ? lib[2] : e.name.split("/").pop()!; if (lib) abis.add(abi);
    const prev = byName.get(name), rank = (a: string) => (ABI.indexOf(a) + 1 || 9);
    if (!prev || rank(abi) < rank(prev.abi)) byName.set(name, {e, abi});
  }
  const list = [...byName].sort(([a, x], [b, y]) => Number(FRAMEWORK.test(a)) - Number(FRAMEWORK.test(b)) || x.e.size - y.e.size);
  const libs: NativeLib[] = [], anti: string[] = [], exec: string[] = []; let bytes = TOTAL, scanned = 0, skipped = 0;
  const keep = (s: string) => trackedString(s) || revealable(s);
  for (const [name, {e, abi}] of list) {
    const row: NativeLib = {name: name.slice(0, 80), abi: abi.slice(0, 20), size: e.size};
    const reason = FRAMEWORK.test(name) ? "library framework/runtime" : scanned >= MAX_LIBS ? "batas jumlah library" : e.size > LIB_MAX || e.size > bytes ? "terlalu besar" : Date.now() > deadline ? "batas waktu" : "";
    if (reason) {row.skipped = reason; if (!FRAMEWORK.test(name)) skipped++; if (libs.length < 20) libs.push(row); continue;}
    try {
      const data = unzipEntry(buffer, e, LIB_MAX); bytes -= data.length; scanned++;
      const elf = parseElf(data, {deadline, keep});
      sig.strings(elf.strings, `native ${row.name}: `);
      for (const h of elf.hidden) sig.reveal({...h, where: `native ${row.name}`});
      Object.assign(row, {machine: elf.machine, needed: elf.needed.slice(0, 10), symbols: elf.imports.slice(0, 12), jni: elf.jni.slice(0, 6), jniCount: elf.jni.length, jniOnLoad: elf.onLoad, exports: elf.exports,
        ...elf.antiDebug.length ? {antiDebug: elf.antiDebug.slice(0, 4)} : {}, ...elf.strings.length ? {findings: elf.strings.filter(trackedString).slice(0, 4).map(s => redactSecrets(s).slice(0, 160))} : {}});
      if (elf.antiDebug.length || elf.imports.includes("ptrace")) anti.push(`${row.name}: ${[elf.imports.includes("ptrace") ? "ptrace" : "", ...elf.antiDebug.slice(0, 2)].filter(Boolean).join(", ").slice(0, 140)}`);
      const runs = elf.imports.filter(f => /^(?:exec\w*|system|popen|fork|vfork)$/.test(f)); if (runs.length) exec.push(`${row.name}: ${runs.join(", ")}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : "ELF rusak";
      if (abi === "assets" && /Header ELF/.test(message)) row.skipped = "bukan ELF (kemungkinan terenkripsi)"; else {row.skipped = `gagal dibaca: ${message.slice(0, 80)}`; skipped++;}
    }
    if (libs.length < 20) libs.push(row);
  }
  const behaviors: Behavior[] = [];
  if (anti.length) behaviors.push({id: "native_anti_analysis", name: "Anti-debug/anti-analisis di library native", severity: "medium", evidence: [...anti.slice(0, 4), exec.length ? `eksekusi proses: ${exec.slice(0, 2).join("; ")}` : ""].filter(Boolean)});
  return {libs, count: byName.size, abis: [...abis].slice(0, 8), scanned, skipped, behaviors};
}
