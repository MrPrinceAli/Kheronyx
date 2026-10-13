// Bounded Android binary XML reader. Returns manifest tags/attributes, never executes content.
export function androidManifest(buffer: Buffer): {tag: string; attributes: Record<string, string>}[] {
  if (buffer.toString("utf8", 0, 100).trimStart().startsWith("<")) {
    throw new Error("Manifest APK berupa XML teks; pemeriksaan manifest biner tidak tersedia.");
  }
  if (buffer.length < 8 || buffer.readUInt16LE(0) !== 3) throw new Error("Manifest Android biner tidak valid.");
  let strings: string[] = []; const tags: {tag: string; attributes: Record<string, string>}[] = [];
  for (let p = 8; p + 8 <= buffer.length;) {
    const type = buffer.readUInt16LE(p), header = buffer.readUInt16LE(p + 2), size = buffer.readUInt32LE(p + 4);
    if (size < 8 || p + size > buffer.length || header < 8) throw new Error("Chunk manifest Android tidak valid.");
    if (type === 1) strings = stringPool(buffer, p, header, size, 10000);
    if (type === 0x102) {
      if (size < 36) throw new Error("Tag manifest terpotong.");
      const tag = strings[buffer.readUInt32LE(p + 20)] || "unknown";
      const start = p + 16 + buffer.readUInt16LE(p + 24), step = buffer.readUInt16LE(p + 26), count = buffer.readUInt16LE(p + 28);
      if (step < 20 || count > 300 || start + count * step > p + size) throw new Error("Atribut manifest rusak.");
      const attributes: Record<string, string> = Object.create(null);
      for (let i = 0; i < count; i++) {
        const a = start + i * step, name = strings[buffer.readUInt32LE(a + 4)] || "unknown", raw = buffer.readUInt32LE(a + 8), kind = buffer[a + 15], value = buffer.readUInt32LE(a + 16);
        attributes[name] = raw !== 0xffffffff ? (strings[raw] || "") : kind === 3 ? (strings[value] || "") : kind === 0x12 ? String(value !== 0) : String(value);
      }
      tags.push({tag, attributes}); if (tags.length > 2000) throw new Error("Manifest terlalu kompleks.");
    }
    p += size;
  }
  if (!tags.some(t => t.tag === "manifest")) throw new Error("Tag utama manifest tidak ditemukan.");
  return tags;
}
// Decodes a ResStringPool chunk. Each string is cut to 2000 chars and repeated offsets are cached, so hostile pools
// (many indices pointing at one huge string) cannot multiply decoding work beyond the chunk size.
function stringPool(buffer: Buffer, p: number, header: number, size: number, max: number): string[] {
  if (header < 28 || p + header > buffer.length) throw new Error("String pool manifest rusak.");
  const count = buffer.readUInt32LE(p + 8), utf8 = Boolean(buffer.readUInt32LE(p + 16) & 256), start = p + buffer.readUInt32LE(p + 20), limit = p + size;
  if (count > max || p + header + count * 4 > limit) throw new Error("String pool manifest terlalu besar.");
  const length8 = (q: number) => {if (q >= limit || buffer[q] & 128 && q + 1 >= limit) throw new Error("String manifest terpotong."); const n = buffer[q]; return n & 128 ? {length: ((n & 127) << 8) | buffer[q + 1], next: q + 2} : {length: n, next: q + 1};};
  const cache = new Map<number, string>(); let budget = size * 2 + 65536;
  return Array.from({length: count}, (_, i) => {
    let q = start + buffer.readUInt32LE(p + header + i * 4); const hit = cache.get(q); if (hit !== undefined) return hit;
    const at = q; if (q + 2 > limit) throw new Error("Offset string manifest tidak valid.");
    let value: string;
    if (utf8) { q = length8(q).next; const l = length8(q); if (l.next + l.length > limit) throw new Error("String manifest terpotong."); const n = Math.min(l.length, 8000); budget -= n; value = buffer.toString("utf8", l.next, l.next + n).slice(0, 2000); }
    else {
      let n = buffer.readUInt16LE(q); q += 2;
      if (n & 0x8000) { if (q + 2 > limit) throw new Error("String manifest terpotong."); n = ((n & 0x7fff) << 16) | buffer.readUInt16LE(q); q += 2; }
      if (q + n * 2 > limit) throw new Error("String manifest terpotong.");
      n = Math.min(n, 2000); budget -= n * 2; value = buffer.toString("utf16le", q, q + n * 2);
    }
    if (budget < 0) throw new Error("String pool tidak wajar.");
    cache.set(at, value); return value;
  });
}
// Global string pool of resources.arsc (UI labels, messages, google-services values such as Firebase URLs).
export function resourceStrings(buffer: Buffer, max = 400000): string[] {
  if (buffer.length < 20 || buffer.readUInt16LE(0) !== 2) throw new Error("resources.arsc tidak valid.");
  const p = buffer.readUInt16LE(2), size = buffer.readUInt32LE(p + 4);
  if (p < 12 || p + 8 > buffer.length || buffer.readUInt16LE(p) !== 1 || size < 28 || p + size > buffer.length) throw new Error("String pool resources.arsc tidak ditemukan.");
  return stringPool(buffer, p, buffer.readUInt16LE(p + 2), size, max);
}
