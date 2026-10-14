import { decodeHidden, type Hidden } from "./deobfuscate";
// Bounded little-endian ELF32/ELF64 reader for Android native libraries: section headers, .dynsym/.dynstr
// (imported/exported symbols), DT_NEEDED (falls back to program headers when section headers are stripped) and
// printable strings from .rodata/.data*. Code is never disassembled or executed.
export type Elf = {bits: 32 | 64; machine: string; sections: number; needed: string[]; imports: string[]; exports: number; jni: string[]; onLoad: boolean; strings: string[]; hidden: Hidden[]; antiDebug: string[]; scannedBytes: number};
const MACHINES: Record<number, string> = {3: "x86", 8: "mips", 40: "arm", 62: "x86_64", 183: "arm64"};
// Imports worth surfacing: process control/exec, dynamic loading, memory protection, anti-debug primitives.
const NOTABLE = new Set(["ptrace", "fork", "vfork", "execve", "execv", "execl", "execlp", "execvp", "system", "popen", "dlopen", "dlsym", "android_dlopen_ext", "mprotect", "inotify_add_watch", "kill", "__system_property_get", "prctl", "syscall", "connect"]);
const ANTI = /TracerPid|frida|gum-js-loop|linjector|xposed|substrate|\bmagisk\b|gdbserver|android_server|\/sbin\/su\b|\/system\/x?bin\/su\b/i;
const fail = (message: string): never => {throw new Error(message);};
export function parseElf(b: Buffer, opts: {deadline: number; keep: (s: string) => boolean; maxScan?: number}): Elf {
  if (b.length < 52 || b.readUInt32BE(0) !== 0x7f454c46) fail("Header ELF tidak valid.");
  const is64 = b[4] === 2; if (b[4] !== 1 && !is64) fail("Kelas ELF tidak dikenal."); if (b[5] !== 1) fail("ELF big-endian tidak didukung.");
  if (is64 && b.length < 64) fail("Header ELF terpotong.");
  const word = (o: number) => {if (o + (is64 ? 8 : 4) > b.length) fail("ELF terpotong."); return is64 ? Number(b.readBigUInt64LE(o)) : b.readUInt32LE(o);};
  const cstr = (o: number, end: number, max = 200) => {if (o >= end || o >= b.length) return ""; const s = b.subarray(o, Math.min(end, b.length, o + max)), z = s.indexOf(0); return s.toString("latin1", 0, z < 0 ? s.length : z).replace(/[^\x20-\x7e]/g, "?");};
  const out: Elf = {bits: is64 ? 64 : 32, machine: MACHINES[b.readUInt16LE(18)] || `0x${b.readUInt16LE(18).toString(16)}`, sections: 0, needed: [], imports: [], exports: 0, jni: [], onLoad: false, strings: [], hidden: [], antiDebug: [], scannedBytes: 0};
  type Section = {name: string; type: number; flags: number; offset: number; size: number; link: number; entsize: number};
  const sections: Section[] = [];
  const shoff = word(is64 ? 0x28 : 0x20), shentsize = b.readUInt16LE(is64 ? 0x3a : 0x2e), shnum = b.readUInt16LE(is64 ? 0x3c : 0x30), shstrndx = b.readUInt16LE(is64 ? 0x3e : 0x32);
  if (shoff && shnum && shnum <= 4096 && shentsize >= (is64 ? 64 : 40) && shoff + shnum * shentsize <= b.length) {
    for (let i = 0; i < shnum; i++) {
      const q = shoff + i * shentsize;
      sections.push(is64 ? {name: "", type: b.readUInt32LE(q + 4), flags: Number(b.readBigUInt64LE(q + 8) & 0xffffn), offset: Number(b.readBigUInt64LE(q + 24)), size: Number(b.readBigUInt64LE(q + 32)), link: b.readUInt32LE(q + 40), entsize: Number(b.readBigUInt64LE(q + 56))}
        : {name: "", type: b.readUInt32LE(q + 4), flags: b.readUInt32LE(q + 8), offset: b.readUInt32LE(q + 16), size: b.readUInt32LE(q + 20), link: b.readUInt32LE(q + 24), entsize: b.readUInt32LE(q + 36)});
    }
    const valid = (s?: Section) => Boolean(s) && s!.type !== 8 && s!.offset <= b.length && s!.size <= b.length - s!.offset;
    const names = sections[shstrndx];
    if (valid(names)) sections.forEach((s, i) => {s.name = cstr(names.offset + b.readUInt32LE(shoff + i * shentsize), names.offset + names.size, 64);});
    for (let i = sections.length - 1; i >= 0; i--) if (!valid(sections[i])) sections.splice(i, 1, {...sections[i], type: 0, size: 0});
    out.sections = sections.length;
    const strtab = (link: number) => {const s = sections[link]; return s && s.type === 3 ? s : undefined;};
    // Dynamic symbols: undefined (shndx 0) = imported, defined global/weak = exported.
    const imports = new Set<string>();
    for (const s of sections) {
      if (s.type !== 11) continue; const st = strtab(s.link), size = is64 ? 24 : 16; if (!st) continue;
      const count = Math.min(Math.floor(s.size / size), 200000);
      for (let i = 1; i < count; i++) {
        const q = s.offset + i * size, nameAt = b.readUInt32LE(q), info = b[q + (is64 ? 4 : 12)], shndx = b.readUInt16LE(q + (is64 ? 6 : 14));
        if ((i & 4095) === 0 && Date.now() > opts.deadline) break;
        if (!nameAt) continue;
        const name = cstr(st.offset + nameAt, st.offset + st.size, 160); if (!name) continue;
        if (!shndx) {if (imports.size < 4000) imports.add(name);}
        else if (info >> 4 === 1 || info >> 4 === 2) {out.exports++; if (name.startsWith("Java_")) {if (out.jni.length < 40) out.jni.push(name);} else if (name === "JNI_OnLoad") out.onLoad = true;}
      }
    }
    out.imports = [...imports].filter(n => NOTABLE.has(n));
    for (const s of sections) {
      if (s.type !== 6) continue; const st = strtab(s.link); if (!st) continue; const size = is64 ? 16 : 8;
      for (let i = 0; i < Math.min(Math.floor(s.size / size), 4096); i++) {const tag = word(s.offset + i * size); if (!tag) break; if (tag === 1 && out.needed.length < 32) out.needed.push(cstr(st.offset + word(s.offset + i * size + (is64 ? 8 : 4)), st.offset + st.size, 120));}
    }
  }
  if (!out.needed.length) neededFromSegments(b, is64, word, cstr, out);
  // Strings: read-only/initialized data sections, or a bounded prefix of the file when section headers are unusable.
  const max = opts.maxScan ?? 16 * 1024 * 1024, regions = sections.filter(s => s.type === 1 && !(s.flags & 4) && /^\.(?:rodata|data)(?:\.|$)/.test(s.name) && s.size).map(s => [s.offset, s.offset + s.size]);
  if (!regions.length) regions.push([0, b.length]);
  let budget = max, matches = 0, stop = false; const kept = new Set<string>(), anti = new Set<string>(), hidden = new Map<string, Hidden>();
  for (const [start, end] of regions) {
    const to = Math.min(end, start + budget); if (to <= start || stop) break; budget -= to - start; out.scannedBytes += to - start;
    for (const m of b.toString("latin1", start, to).matchAll(/[\x20-\x7e]{6,400}/g)) {
      if ((++matches & 4095) === 0 && (Date.now() > opts.deadline || matches > 600000)) {stop = true; break;}
      const s = m[0];
      if (kept.size < 400 && opts.keep(s)) kept.add(s);
      if (anti.size < 8 && ANTI.test(s)) anti.add(s.slice(0, 120));
      if (hidden.size < 40 && s.length >= 12 && !/\s/.test(s)) {const h = decodeHidden(s); if (h && opts.keep(h.value)) hidden.set(h.value, h);}
    }
  }
  out.strings = [...kept]; out.antiDebug = [...anti]; out.hidden = [...hidden.values()];
  return out;
}
// DT_NEEDED via PT_DYNAMIC + PT_LOAD address mapping (packed/stripped libraries often corrupt section headers).
function neededFromSegments(b: Buffer, is64: boolean, word: (o: number) => number, cstr: (o: number, end: number, max?: number) => string, out: Elf) {
  const phoff = word(is64 ? 0x20 : 0x1c), phentsize = b.readUInt16LE(is64 ? 0x36 : 0x2a), phnum = b.readUInt16LE(is64 ? 0x38 : 0x2c);
  if (!phoff || !phnum || phnum > 512 || phentsize < (is64 ? 56 : 32) || phoff + phnum * phentsize > b.length) return;
  const loads: [number, number, number][] = []; let dyn: [number, number] | undefined;
  for (let i = 0; i < phnum; i++) {
    const q = phoff + i * phentsize, type = b.readUInt32LE(q), offset = word(q + (is64 ? 8 : 4)), vaddr = word(q + (is64 ? 16 : 8)), filesz = word(q + (is64 ? 32 : 16));
    if (offset > b.length || filesz > b.length - offset) continue;
    if (type === 1) loads.push([vaddr, offset, filesz]); else if (type === 2) dyn = [offset, filesz];
  }
  if (!dyn) return; const size = is64 ? 16 : 8, entries: [number, number][] = [];
  for (let i = 0; i < Math.min(Math.floor(dyn[1] / size), 4096); i++) {const tag = word(dyn[0] + i * size); if (!tag) break; entries.push([tag, word(dyn[0] + i * size + size / 2)]);}
  const strtab = entries.find(([t]) => t === 5)?.[1], strsz = entries.find(([t]) => t === 10)?.[1] || 65536; if (strtab === undefined) return;
  const seg = loads.find(([v, , s]) => strtab >= v && strtab < v + s); if (!seg) return; const base = seg[1] + strtab - seg[0];
  for (const [t, v] of entries) if (t === 1 && out.needed.length < 32) out.needed.push(cstr(base + v, Math.min(b.length, base + strsz), 120));
}
