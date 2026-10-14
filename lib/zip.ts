import { constants, inflateRawSync } from "node:zlib";
export type ZipEntry = {name: string; compressedSize: number; size: number; method: number; offset: number; flags: number};
// Locates the end-of-central-directory record; `offset` is where the central directory (and an APK Signing Block before it) starts.
export function zipDirectory(buffer: Buffer) {
  let end = -1;
  for (let i = buffer.length - 22; i >= Math.max(0, buffer.length - 65557); i--) {
    if (buffer.readUInt32LE(i) === 0x06054b50 && i + 22 + buffer.readUInt16LE(i + 20) === buffer.length) {end = i; break;}
  }
  if (end < 0) throw new Error("Struktur ZIP/APK tidak valid.");
  if (buffer.readUInt16LE(end + 4) || buffer.readUInt16LE(end + 6)) throw new Error("Arsip multi-volume belum didukung.");
  const count = buffer.readUInt16LE(end + 10); let p = buffer.readUInt32LE(end + 16);
  // Large APKs (games, bundled assets) routinely exceed a few thousand entries. Only entries we inflate
  // are size-bounded (see unzipEntry), so the total expanded size of the archive no longer matters.
  if (count === 0xffff || count > 60000 || p === 0xffffffff) throw new Error("Arsip terlalu kompleks atau menggunakan ZIP64.");
  return {end, count, offset: p};
}
export function readZip(buffer: Buffer): ZipEntry[] {
  const {end, count, offset} = zipDirectory(buffer); let p = offset;
  const entries: ZipEntry[] = [];
  for (let i = 0; i < count; i++) {
    if (p + 46 > end || buffer.readUInt32LE(p) !== 0x02014b50) throw new Error("Direktori APK rusak.");
    const nameLength = buffer.readUInt16LE(p + 28), extraLength = buffer.readUInt16LE(p + 30), commentLength = buffer.readUInt16LE(p + 32);
    if (p + 46 + nameLength + extraLength + commentLength > end) throw new Error("Direktori APK terpotong.");
    const size = buffer.readUInt32LE(p + 24);
    if (size === 0xffffffff) throw new Error("Arsip menggunakan ZIP64 dan belum didukung.");
    entries.push({name: buffer.toString("utf8", p + 46, p + 46 + nameLength), size, compressedSize: buffer.readUInt32LE(p + 20), method: buffer.readUInt16LE(p + 10), flags: buffer.readUInt16LE(p + 8), offset: buffer.readUInt32LE(p + 42)});
    p += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}
// The ZIP "encrypted" bit is ignored here on purpose: Android ignores it too, and malware sets it on plain entries
// to break analysis tools. Truly encrypted data then fails the strict size/inflate checks below.
function entryData(buffer: Buffer, entry: ZipEntry) {
  const p = entry.offset;
  if (p + 30 > buffer.length || buffer.readUInt32LE(p) !== 0x04034b50) throw new Error("Header bagian APK tidak valid.");
  const start = p + 30 + buffer.readUInt16LE(p + 26) + buffer.readUInt16LE(p + 28);
  if (start + entry.compressedSize > buffer.length) throw new Error("Bagian APK terpotong.");
  return buffer.subarray(start, start + entry.compressedSize);
}
// BadPack-style manifests lie about their ZIP sizes and zero the AXML chunk type, yet Android still reads them.
// Looks for the real binary-XML header (header size 8 + a plausible total size) right around the entry's data and
// returns a repaired copy, or null when nothing credible is there.
export function salvageBinaryXml(buffer: Buffer, entry: ZipEntry, maxBytes: number) {
  const p = entry.offset; if (p + 30 > buffer.length || buffer.readUInt32LE(p) !== 0x04034b50) return null;
  const start = p + 30 + buffer.readUInt16LE(p + 26) + buffer.readUInt16LE(p + 28);
  for (let at = Math.max(p + 30, start - 8); at <= start + 8 && at + 8 <= buffer.length; at++) {
    const type = buffer.readUInt16LE(at), header = buffer.readUInt16LE(at + 2), size = buffer.readUInt32LE(at + 4);
    if ((type === 3 || type === 0) && header === 8 && size >= 64 && size <= maxBytes && at + size <= buffer.length && buffer.readUInt16LE(at + 8) === 1) {
      const copy = Buffer.from(buffer.subarray(at, at + size)); copy.writeUInt16LE(3, 0); return copy;
    }
  }
  return null;
}
// First bytes of an entry without inflating all of it (magic/entropy sniffing). Output is capped even for bomb-like streams.
export function zipHead(buffer: Buffer, entry: ZipEntry, bytes = 65536) {
  const data = entryData(buffer, entry);
  if (entry.method !== 8 && entry.compressedSize === entry.size) return data.subarray(0, bytes);
  if (entry.method !== 8) throw new Error("Metode kompresi bagian APK tidak didukung.");
  return inflateRawSync(data.subarray(0, Math.min(data.length, 8192)), {finishFlush: constants.Z_SYNC_FLUSH, maxOutputLength: 9 * 1024 * 1024}).subarray(0, bytes);
}
export function unzipEntry(buffer: Buffer, entry: ZipEntry, maxBytes: number) {
  if (entry.size > maxBytes) throw new Error("Bagian APK terlalu besar untuk dibedah.");
  const data = entryData(buffer, entry);
  // Android only distinguishes stored from deflated, so malware ("BadPack") writes junk method numbers to break
  // analysis tools: unknown methods with equal sizes are read as stored, otherwise as deflate.
  let output: Buffer | null = null;
  try {output = entry.method === 0 || entry.method !== 8 && entry.compressedSize === entry.size ? data : inflateRawSync(data, {maxOutputLength: maxBytes});} catch (error) {if (!(entry.flags & 1)) throw error;}
  if (!output || output.length !== entry.size || output.length > maxBytes) throw new Error(entry.flags & 1 ? "Bagian APK terenkripsi." : "Kompresi atau ukuran bagian APK tidak valid.");
  return output;
}
