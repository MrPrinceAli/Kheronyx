// Recovers strings hidden by simple encodings directly in string tables (DEX string_ids, native .rodata): base64,
// hex and reversed text. Bytecode-level tricks (byte/char arrays, XOR, StringBuilder) are handled in lib/dex.ts.
export type Hidden = {value: string; technique: string; where?: string};
const B64 = /^(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$|^[A-Za-z0-9_-]{16,}$/, HEX = /^(?:[0-9a-fA-F]{2}){6,}$/;
const REVERSED = /\/\/:(?:s?ptth|s?sw|pct)|AA:\d{6,12}(?![\d])|\.(?:moc|gro|ten|oi|ppa|di|zyx|pot)\b|php\./;
const TEXT = /^[\x20-\x7e\t\r\n]{6,}$/;
export const readable = (s: string) => TEXT.test(s) && /[A-Za-z]{2}/.test(s);
export function decodeHidden(s: string): Hidden | null {
  if (s.length < 8 || s.length > 4096) return null;
  if (HEX.test(s)) {const d = Buffer.from(s, "hex").toString("latin1"); if (readable(d) && /[a-z]{3}|[:/.]/i.test(d)) return {value: d, technique: "hex"};}
  else if (s.length >= 16 && B64.test(s) && !/^[a-z]+$|^[A-Z]+$|^[A-Za-z]+$/.test(s)) {
    const d = Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("latin1"); if (readable(d) && d.length >= 6) return {value: d, technique: "base64"};
  }
  if (REVERSED.test(s)) {const d = [...s].reverse().join(""); if (readable(d)) return {value: d, technique: "teks dibalik"};}
  return null;
}
// One pass over a string list; `keep` decides which recovered values matter (e.g. URLs, tokens, webhooks).
export function hiddenStrings(list: Iterable<string>, keep: (s: string) => boolean, max = 200): Hidden[] {
  const out: Hidden[] = [], seen = new Set<string>();
  for (const s of list) {
    if (out.length >= max) break;
    const h = s.length >= 8 && s.length <= 4096 ? decodeHidden(s) : null;
    if (h && keep(h.value) && !seen.has(h.value)) {seen.add(h.value); out.push(h);}
  }
  return out;
}
