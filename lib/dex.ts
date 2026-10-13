// Bounded DEX table reader (header, string_ids, type_ids, field_ids, method_ids, class_defs). Bytecode is never
// interpreted or executed; every offset/count is checked against the buffer before it is used.
export type DexClass = {name: string; superclass: string};
export type Dex = {version: string; strings: string[]; types: string[]; methods: string[]; fields: string[]; classes: DexClass[]};
const NO_INDEX = 0xffffffff, MAX_STRING = 4096, MAX_IDS = 65536, MAX_STRINGS = 1_000_000;
const fail = (message: string): never => {throw new Error(message);};
const clip = (s: string) => s.length > 200 ? s.slice(0, 200) : s;
export function parseDex(b: Buffer, deadline = Infinity): Dex {
  if (b.length < 0x70 || b.toString("latin1", 0, 4) !== "dex\n" || b[7] !== 0) fail("Header DEX tidak valid.");
  const version = b.toString("latin1", 4, 7); if (!/^0[3-4]\d$/.test(version)) fail("Versi DEX tidak dikenal.");
  if (b.readUInt32LE(0x28) !== 0x12345678) fail("Urutan byte DEX tidak didukung.");
  const header = b.readUInt32LE(0x24); if (header < 0x70 || header > b.length) fail("Ukuran header DEX tidak valid.");
  if (b.readUInt32LE(0x20) > b.length) fail("File DEX terpotong.");
  const table = (at: number, item: number, max: number) => {
    const n = b.readUInt32LE(at), off = b.readUInt32LE(at + 4);
    if (n > max || n && (off < header || off + n * item > b.length)) fail("Tabel DEX di luar batas atau terlalu besar.");
    return [n, off];
  };
  const [ns, os] = table(0x38, 4, MAX_STRINGS), [nt, ot] = table(0x40, 4, MAX_IDS), [nf, of] = table(0x50, 8, MAX_IDS), [nm, om] = table(0x58, 8, MAX_IDS), [nc, oc] = table(0x60, 32, MAX_IDS);
  const tick = (i: number) => {if ((i & 0xffff) === 0 && Date.now() > deadline) fail("Batas waktu pembacaan DEX tercapai.");};
  // Overlapping string offsets could otherwise multiply decoding work; distinct legit strings never exceed the file size.
  let budget = b.length + 65536; const strings = new Array<string>(ns);
  for (let i = 0; i < ns; i++) {
    tick(i); let p = b.readUInt32LE(os + i * 4), units = 0;
    for (let s = 0; ; s += 7) {if (s > 28 || p >= b.length) fail("Panjang string DEX rusak."); const x = b[p++]; units += (x & 0x7f) * 2 ** s; if (!(x & 0x80)) break;}
    const n = Math.min(units, MAX_STRING); if ((budget -= n) < 0) fail("Tabel string DEX tidak wajar.");
    strings[i] = mutf8(b, p, n);
  }
  const str = (i: number) => i < ns ? strings[i] : fail("Indeks string DEX tidak valid.");
  const types = Array.from({length: nt}, (_, i) => str(b.readUInt32LE(ot + i * 4)));
  const type = (i: number) => i < nt ? types[i] : fail("Indeks tipe DEX tidak valid.");
  const refs = (n: number, o: number) => Array.from({length: n}, (_, i) => {tick(i); const q = o + i * 8; return `${clip(type(b.readUInt16LE(q)))}->${clip(str(b.readUInt32LE(q + 4)))}`;});
  const fields = refs(nf, of), methods = refs(nm, om);
  const classes = Array.from({length: nc}, (_, i) => {const q = oc + i * 32, s = b.readUInt32LE(q + 8); return {name: type(b.readUInt32LE(q)), superclass: s === NO_INDEX ? "" : type(s)};});
  return {version, strings, types, methods, fields, classes};
}
// MUTF-8 (DEX string_data_item): decodes at most n UTF-16 units; stray bytes become U+FFFD instead of throwing.
function mutf8(b: Buffer, p: number, n: number) {
  const end = Math.min(b.length, p + n); let ascii = end - p === n;
  for (let i = p; ascii && i < end; i++) if (b[i] === 0 || b[i] > 0x7f) ascii = false;
  if (ascii) return b.toString("latin1", p, end);
  const out = new Uint16Array(n); let k = 0;
  while (k < n && p < b.length) {
    const c = b[p++]; if (c === 0) break;
    if (c < 0x80) out[k++] = c;
    else if ((c & 0xe0) === 0xc0 && p < b.length) out[k++] = (c & 0x1f) << 6 | b[p++] & 0x3f;
    else if ((c & 0xf0) === 0xe0 && p + 1 < b.length) {out[k++] = (c & 0x0f) << 12 | (b[p] & 0x3f) << 6 | b[p + 1] & 0x3f; p += 2;}
    else out[k++] = 0xfffd;
  }
  return String.fromCharCode(...out.subarray(0, k));
}
