import { readZip, unzipEntry, zipHead, type ZipEntry } from "./zip";
// Looks for code hidden outside classes*.dex (assets/, res/raw/, odd root files): raw DEX, nested APK/JAR with DEX,
// ELF outside lib/, and high-entropy blobs with payload-like or disguised names. Only bounded prefixes are sniffed;
// DEX found this way is handed to `onDex` so the behavior catalog also covers dropped payloads.
export type Payload = {name: string; kind: string; size: number; entropy?: number; dex?: number};
export type Budget = {deadline: number; bytes: number};
export function entropy(buffer: Buffer) {
  const counts = new Uint32Array(256); for (const b of buffer) counts[b]++;
  let n = 0; for (const c of counts) if (c) {const p = c / buffer.length; n -= p * Math.log2(p);} return Math.round(n * 100) / 100;
}
const SUSPECT = /\.(?:dex|jar|apk|odex|zip|bin|dat|data|enc|so|tmp|bak|db)$/i, DISGUISE = /\.(?:png|jpe?g|gif|webp|json|xml|txt|html?|js|css)$/i;
const MEDIA = /\.(?:mp3|ogg|wav|m4a|aac|mp4|webm|mkv|3gp|ttf|otf|woff2?|pak|obb|unity3d|bundle|assets|ress|resource|resS|bank|fsb|bnk|ktx|pvr|astc|pkm|etc2?|lz4|br|gz|xz|7z|mov|flac|opus|tflite|pb|onnx|bin\.gz)$/i;
// Any real image/font container (mislabelled extensions are common and harmless).
const KNOWN = (h: Buffer) => h.readUInt32BE(0) === 0x89504e47 || h[0] === 0xff && h[1] === 0xd8 || /^(?:GIF8|RIFF|OTTO|true|wOFF|wOF2)$/.test(h.toString("latin1", 0, 4)) || h.readUInt32BE(0) === 0x00010000;
const DEX_MAX = 64 * 1024 * 1024;
const candidate = (e: ZipEntry) => e.size >= 64 && !e.name.endsWith("/") && !/^(?:META-INF|lib)\//.test(e.name) && !/^classes\d*\.dex$/.test(e.name) && (/^(?:assets|res\/raw)\//.test(e.name) || !e.name.includes("/") && !/^(?:AndroidManifest\.xml|resources\.arsc)$/.test(e.name) || /\.(?:dex|jar|apk|odex)$/i.test(e.name));
const rank = (n: string) => SUSPECT.test(n) || !/\.[\w]{1,6}$/.test(n.split("/").pop() || "") ? 0 : DISGUISE.test(n) ? 1 : 2;
export function findPayloads(buffer: Buffer, entries: ZipEntry[], budget: Budget, onDex: (name: string, data: Buffer) => void): Payload[] {
  const found: Payload[] = [], list = entries.filter(candidate).sort((a, b) => rank(a.name) - rank(b.name)).slice(0, 800);
  const inflate = (from: Buffer, e: ZipEntry) => {if (e.size > DEX_MAX || e.size > budget.bytes) throw new Error("Payload melebihi batas analisis."); budget.bytes -= e.size; return unzipEntry(from, e, DEX_MAX);};
  const dex = (name: string, data: Buffer) => {try {onDex(name, data); return 1;} catch {return 0;}};
  for (const e of list) {
    if (Date.now() > budget.deadline || found.length >= 30) break;
    let head: Buffer; try {head = zipHead(buffer, e, 65536);} catch {continue;}
    if (head.length < 4) continue;
    const name = e.name.slice(0, 160), magic = head.toString("latin1", 0, 4);
    if (magic === "dex\n") {let n = 0; try {n = dex(name, inflate(buffer, e));} catch {} found.push({name, kind: "DEX tersembunyi", size: e.size, dex: n}); continue;}
    if (magic === "PK\x03\x04") {
      try {
        const inner = inflate(buffer, e), dexes = readZip(inner).filter(x => /(?:^|\/)classes\d*\.dex$/.test(x.name)).slice(0, 8);
        if (dexes.length) {let n = 0; for (const d of dexes) {try {n += dex(`${name}!${d.name.slice(0, 60)}`, inflate(inner, d));} catch {}} found.push({name, kind: "APK/JAR berisi DEX", size: e.size, dex: n});}
      } catch {if (/\.(?:apk|jar|dex)$/i.test(e.name)) found.push({name, kind: "Arsip kode tidak terbaca", size: e.size});}
      continue;
    }
    if (magic === "\x7fELF") {found.push({name, kind: "Kode native di luar lib/", size: e.size}); continue;}
    if (head.length < 4096 || e.size < 16384 || MEDIA.test(e.name) || KNOWN(head)) continue;
    const disguised = DISGUISE.test(e.name), ent = entropy(head);
    if (ent > 7.6 && (rank(e.name) === 0 || disguised)) found.push({name, kind: disguised ? "Blob terenkripsi menyamar sebagai file biasa" : "Blob terenkripsi/berentropi tinggi", size: e.size, entropy: ent});
  }
  return found;
}
