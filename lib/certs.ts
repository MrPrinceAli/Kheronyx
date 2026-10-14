import { X509Certificate } from "node:crypto";
// Minimal strict DER walker for PKCS#7 SignedData (APK v1 META-INF/*.RSA|DSA|EC, PE Authenticode). Certificates are
// parsed for identity only; signatures are NOT verified.
export type CertInfo = {subject: string; issuer: string; sha256: string; serial: string; validFrom: string; validTo: string; selfSigned: boolean; key?: string};
type Tlv = {tag: number; at: number; start: number; end: number};
function tlv(b: Buffer, p: number, limit: number): Tlv {
  if (p + 2 > limit) throw new Error("DER terpotong.");
  const tag = b[p]; let len = b[p + 1], q = p + 2;
  if ((tag & 0x1f) === 0x1f) throw new Error("Tag DER tidak didukung.");
  if (len & 0x80) {const n = len & 0x7f; if (!n || n > 4 || q + n > limit) throw new Error("Panjang DER tidak valid."); len = 0; for (let i = 0; i < n; i++) len = len * 256 + b[q++];}
  if (q + len > limit) throw new Error("DER di luar batas.");
  return {tag, at: p, start: q, end: q + len};
}
function children(b: Buffer, t: Tlv) {const out: Tlv[] = []; for (let p = t.start; p < t.end; p = out[out.length - 1].end) {if (out.length >= 2000) throw new Error("DER terlalu kompleks."); out.push(tlv(b, p, t.end));} return out;}
const SIGNED_DATA = Buffer.from("2a864886f70d010702", "hex");
export function pkcs7(b: Buffer): {certs: Buffer[]; signerSerials: string[]} {
  const root = tlv(b, 0, b.length), [oid, wrapped] = root.tag === 0x30 ? children(b, root) : [];
  if (!oid || oid.tag !== 6 || !b.subarray(oid.start, oid.end).equals(SIGNED_DATA) || wrapped?.tag !== 0xa0) throw new Error("Bukan PKCS#7 SignedData.");
  const sd = tlv(b, wrapped.start, wrapped.end); if (sd.tag !== 0x30) throw new Error("SignedData tidak valid.");
  const parts = children(b, sd), set = parts.find(p => p.tag === 0xa0), infos = parts[parts.length - 1];
  const certs = set ? children(b, set).filter(c => c.tag === 0x30).slice(0, 20).map(c => b.subarray(c.at, c.end)) : [];
  const signerSerials = infos?.tag === 0x31 ? children(b, infos).slice(0, 10).flatMap(si => {const id = si.tag === 0x30 ? children(b, si)[1] : undefined; const serial = id?.tag === 0x30 ? children(b, id)[1] : undefined; return serial?.tag === 2 ? [b.subarray(serial.start, serial.end).toString("hex").replace(/^(00)+(?=.)/, "").toUpperCase()] : [];}) : [];
  return {certs, signerSerials};
}
// Authenticode SpcIndirectDataContent.messageDigest: the PE image hash the signer claims to have signed. Comparing it with
// the file's own hash only proves a mismatch (copied/"cloned" signature or file modified after signing); a match is NOT a
// signature verification. Returns the node:crypto algorithm name and digest, or undefined for other content types.
const DIGESTS: Record<string, string> = {"2b0e03021a": "sha1", "608648016503040201": "sha256", "608648016503040202": "sha384", "608648016503040203": "sha512", "2a864886f70d0205": "md5"};
export function authenticodeDigest(b: Buffer): {algorithm: string; digest: Buffer} | undefined {
  const root = tlv(b, 0, b.length), [, wrapped] = root.tag === 0x30 ? children(b, root) : [];
  if (wrapped?.tag !== 0xa0) return;
  const sd = tlv(b, wrapped.start, wrapped.end), encap = sd.tag === 0x30 ? children(b, sd)[2] : undefined, [, content] = encap?.tag === 0x30 ? children(b, encap) : [];
  if (content?.tag !== 0xa0) return;
  const spc = tlv(b, content.start, content.end), info = spc.tag === 0x30 ? children(b, spc)[1] : undefined, [alg, digest] = info?.tag === 0x30 ? children(b, info) : [];
  const oid = alg?.tag === 0x30 ? children(b, alg)[0] : undefined, name = oid?.tag === 6 ? DIGESTS[b.subarray(oid.start, oid.end).toString("hex")] : undefined;
  return name && digest?.tag === 4 && digest.end - digest.start <= 64 ? {algorithm: name, digest: b.subarray(digest.start, digest.end)} : undefined;
}
const iso = (s: string) => {const d = new Date(s); return Number.isNaN(d.getTime()) ? s.slice(0, 40) : d.toISOString();};
const dn = (s: string) => s.split("\n").filter(Boolean).join(", ").replace(/[\x00-\x1f\x7f]/g, "").slice(0, 300);
export function certInfo(der: Buffer): CertInfo {
  const x = new X509Certificate(der), k = x.publicKey, d = k.asymmetricKeyDetails;
  return {subject: dn(x.subject), issuer: dn(x.issuer), sha256: x.fingerprint256.replace(/:/g, "").toLowerCase(), serial: x.serialNumber.replace(/^(00)+(?=.)/, "").toUpperCase().slice(0, 80), validFrom: iso(x.validFrom), validTo: iso(x.validTo), selfSigned: x.subject === x.issuer, key: `${k.asymmetricKeyType || "?"}${d?.modulusLength ? `-${d.modulusLength}` : d?.namedCurve ? `-${d.namedCurve}` : ""}`};
}
export const certSummary = (c: CertInfo) => `subject "${c.subject}", SHA-256 ${c.sha256}, berlaku ${c.validFrom.slice(0, 10)} s.d. ${c.validTo.slice(0, 10)}`;
