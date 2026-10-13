import { certInfo, certSummary, pkcs7, type CertInfo } from "./certs";
import { unzipEntry, zipDirectory, type ZipEntry } from "./zip";
// Reads APK signer certificates (v2/v3/v3.1 APK Signing Block, v1 JAR PKCS#7). Identity only: digests and
// signatures are not verified, so a valid-looking certificate does not prove the APK is untampered.
const SCHEMES: Record<number, string> = {0x7109871a: "v2", 0xf05368c0: "v3", 0x1b93ad61: "v3.1"};
function lp(b: Buffer, p: number) {
  if (p + 4 > b.length) throw new Error("Blok tanda tangan APK terpotong.");
  const n = b.readUInt32LE(p); if (p + 4 + n > b.length) throw new Error("Blok tanda tangan APK di luar batas.");
  return {value: b.subarray(p + 4, p + 4 + n), next: p + 4 + n};
}
function items(b: Buffer) {const out: Buffer[] = []; for (let p = 0; p < b.length && out.length < 32;) {const x = lp(b, p); out.push(x.value); p = x.next;} return out;}
// signer := signed data (digests, certificates, ...) first; identical position for v2 and v3.
const signerCerts = (value: Buffer) => items(lp(value, 0).value).flatMap(signer => {const data = lp(signer, 0).value; return items(lp(data, lp(data, 0).next).value);});
export function signingBlock(b: Buffer, cd: number) {
  const found: {scheme: string; certs: Buffer[]}[] = [];
  if (cd < 32 || cd > b.length || b.toString("latin1", cd - 16, cd) !== "APK Sig Block 42") return found;
  const size = b.readBigUInt64LE(cd - 24); if (size < 24n || size > BigInt(cd - 8)) throw new Error("Ukuran APK Signing Block tidak valid.");
  const start = cd - Number(size) - 8; if (b.readBigUInt64LE(start) !== size) throw new Error("APK Signing Block tidak konsisten.");
  for (let p = start + 8, n = 0; p < cd - 24 && n < 64; n++) {
    if (p + 12 > cd - 24) throw new Error("Pasangan APK Signing Block terpotong.");
    const len = b.readBigUInt64LE(p); if (len < 4n || len > BigInt(cd - 24 - p - 8)) throw new Error("Pasangan APK Signing Block di luar batas.");
    const id = b.readUInt32LE(p + 8), scheme = SCHEMES[id];
    if (scheme) found.push({scheme, certs: signerCerts(b.subarray(p + 12, p + 8 + Number(len)))});
    p += 8 + Number(len);
  }
  return found;
}
export type Signing = {schemes: string[]; certificates: CertInfo[]; errors: string[]};
export function apkSigning(buffer: Buffer, entries: ZipEntry[]): Signing {
  const schemes: string[] = [], certs = new Map<string, CertInfo>(), errors: string[] = [];
  const add = (der: Buffer) => {try {const c = certInfo(der); if (!certs.has(c.sha256) && certs.size < 5) certs.set(c.sha256, c);} catch {errors.push("Sertifikat X.509 tidak dapat dibaca.");}};
  try {for (const s of signingBlock(buffer, zipDirectory(buffer).offset)) {schemes.push(s.scheme); s.certs.forEach(add);}}
  catch (e) {errors.push(e instanceof Error ? e.message : "APK Signing Block tidak dapat dibaca.");}
  const v1 = entries.filter(e => /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(e.name)).slice(0, 3);
  if (v1.length) schemes.unshift("v1");
  for (const e of v1) try {pkcs7(unzipEntry(buffer, e, 1024 * 1024)).certs.forEach(add);} catch {errors.push(`${e.name.slice(0, 80)} bukan PKCS#7 yang dapat dibaca.`);}
  return {schemes: [...new Set(schemes)], certificates: [...certs.values()], errors};
}
// Indonesian indicators for certificate traits commonly seen in quickly-built scam APKs.
export function signingIndicators(s: Signing, now = Date.now()) {
  const out: {name: string; evidence: string}[] = [];
  if (!s.schemes.length) out.push({name: "APK tidak bertanda tangan", evidence: "Tidak ada APK Signing Block v2/v3 maupun signature v1 di META-INF. Android menolak memasang APK tanpa tanda tangan; file mungkin rusak, dimodifikasi, atau bukan rilis resmi."});
  for (const c of s.certificates) {
    if (/CN=Android Debug/i.test(c.subject)) out.push({name: "Ditandatangani sertifikat debug Android", evidence: `Sertifikat debug bawaan Android Studio, bukan kunci rilis penerbit: ${certSummary(c)}.`});
    if (/emailAddress=android@android\.com/i.test(c.subject) && /CN=Android(?:,|$)/.test(c.subject)) out.push({name: "Ditandatangani kunci uji AOSP publik", evidence: `Kunci testkey/platform AOSP bersifat publik sehingga siapa pun dapat menandatangani dengannya: ${certSummary(c)}.`});
    const age = (now - Date.parse(c.validFrom)) / 86400000;
    if (c.selfSigned && age >= -2 && age < 60) out.push({name: "Sertifikat penanda tangan sangat baru", evidence: `Sertifikat swa-tanda-tangan dibuat ${Math.max(0, Math.round(age))} hari sebelum analisis; umum pada APK penipuan yang dibuat ulang per kampanye: ${certSummary(c)}.`});
  }
  return out;
}
