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
    if (type === 1) {
      if (header < 28 || p + header > buffer.length) throw new Error("String pool manifest rusak.");
      const count = buffer.readUInt32LE(p + 8), utf8 = Boolean(buffer.readUInt32LE(p + 16) & 256), start = p + buffer.readUInt32LE(p + 20);
      if (count > 10000 || p + header + count * 4 > p + size) throw new Error("String pool manifest terlalu besar.");
      const length8 = (q: number) => {if (q >= p + size) throw new Error("String manifest terpotong."); const n = buffer[q]; return n & 128 ? {length: ((n & 127) << 8) | buffer[q + 1], next: q + 2} : {length: n, next: q + 1};};
      strings = Array.from({length: count}, (_, i) => {
        let q = start + buffer.readUInt32LE(p + header + i * 4);
        if (q + 2 > p + size) throw new Error("Offset string manifest tidak valid.");
        if (utf8) { q = length8(q).next; const l = length8(q); if (l.next + l.length > p + size) throw new Error("String manifest terpotong."); return buffer.toString("utf8", l.next, l.next + l.length).slice(0, 2000); }
        let n = buffer.readUInt16LE(q); q += 2;
        if (n & 0x8000) { n = ((n & 0x7fff) << 16) | buffer.readUInt16LE(q); q += 2; }
        if (q + n * 2 > p + size) throw new Error("String manifest terpotong.");
        return buffer.toString("utf16le", q, q + n * 2).slice(0, 2000);
      });
    }
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
