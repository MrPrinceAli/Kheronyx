import { inflateRawSync } from "node:zlib";
export type ZipEntry = {name: string; compressedSize: number; size: number; method: number; offset: number; flags: number};
export function readZip(buffer: Buffer): ZipEntry[] {
  let end = -1;
  for (let i = buffer.length - 22; i >= Math.max(0, buffer.length - 65557); i--) {
    if (buffer.readUInt32LE(i) === 0x06054b50 && i + 22 + buffer.readUInt16LE(i + 20) === buffer.length) {end = i; break;}
  }
  if (end < 0) throw new Error("Struktur ZIP/APK tidak valid.");
  if (buffer.readUInt16LE(end + 4) || buffer.readUInt16LE(end + 6)) throw new Error("Arsip multi-volume belum didukung.");
  const count = buffer.readUInt16LE(end + 10); let p = buffer.readUInt32LE(end + 16);
  if (count > 4096 || p === 0xffffffff) throw new Error("Arsip terlalu kompleks atau menggunakan ZIP64.");
  const entries: ZipEntry[] = []; let expanded = 0;
  for (let i = 0; i < count; i++) {
    if (p + 46 > end || buffer.readUInt32LE(p) !== 0x02014b50) throw new Error("Direktori APK rusak.");
    const nameLength = buffer.readUInt16LE(p + 28), extraLength = buffer.readUInt16LE(p + 30), commentLength = buffer.readUInt16LE(p + 32);
    if (p + 46 + nameLength + extraLength + commentLength > end) throw new Error("Direktori APK terpotong.");
    const size = buffer.readUInt32LE(p + 24); expanded += size;
    if (expanded > 200 * 1024 * 1024 || size === 0xffffffff) throw new Error("Ukuran hasil dekompresi APK melewati batas.");
    entries.push({name: buffer.toString("utf8", p + 46, p + 46 + nameLength), size, compressedSize: buffer.readUInt32LE(p + 20), method: buffer.readUInt16LE(p + 10), flags: buffer.readUInt16LE(p + 8), offset: buffer.readUInt32LE(p + 42)});
    p += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}
export function unzipEntry(buffer: Buffer, entry: ZipEntry, maxBytes: number) {
  if (entry.flags & 1) throw new Error("Bagian APK terenkripsi.");
  if (entry.size > maxBytes) throw new Error("Bagian APK terlalu besar untuk dibedah.");
  const p = entry.offset;
  if (p + 30 > buffer.length || buffer.readUInt32LE(p) !== 0x04034b50) throw new Error("Header bagian APK tidak valid.");
  const start = p + 30 + buffer.readUInt16LE(p + 26) + buffer.readUInt16LE(p + 28);
  if (start + entry.compressedSize > buffer.length) throw new Error("Bagian APK terpotong.");
  const data = buffer.subarray(start, start + entry.compressedSize);
  const output = entry.method === 0 ? data : entry.method === 8 ? inflateRawSync(data, {maxOutputLength: maxBytes}) : null;
  if (!output || output.length !== entry.size || output.length > maxBytes) throw new Error("Kompresi atau ukuran bagian APK tidak valid.");
  return output;
}
