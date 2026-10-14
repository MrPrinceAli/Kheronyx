import { X509Certificate, constants, createHash, createPublicKey, verify, type KeyObject } from "node:crypto";
import { certInfo, certSummary, pkcs7, type CertInfo } from "./certs";
import { unzipEntry, zipDirectory, type ZipEntry } from "./zip";
// Reads APK signer certificates (v2/v3/v3.1 APK Signing Block, v1 JAR PKCS#7) and cryptographically verifies the
// v2/v3 blocks: signed-data signature with the signer's public key, public key == certificate key, and the chunked
// content digest over the ZIP sections. v1 (JAR) signatures are identity-only (not verified).
const SCHEMES: Record<number, string> = {0x7109871a: "v2", 0xf05368c0: "v3", 0x1b93ad61: "v3.1"};
function lp(b: Buffer, p: number) {
  if (p + 4 > b.length) throw new Error("Blok tanda tangan APK terpotong.");
  const n = b.readUInt32LE(p); if (p + 4 + n > b.length) throw new Error("Blok tanda tangan APK di luar batas.");
  return {value: b.subarray(p + 4, p + 4 + n), next: p + 4 + n};
}
function items(b: Buffer) {const out: Buffer[] = []; for (let p = 0; p < b.length && out.length < 32;) {const x = lp(b, p); out.push(x.value); p = x.next;} return out;}
// signer := signed data (digests, certificates, ...) first; identical position for v2 and v3.
const signerCerts = (signers: Buffer[]) => signers.flatMap(signer => {const data = lp(signer, 0).value; return items(lp(data, lp(data, 0).next).value);});
export type Block = {scheme: string; certs: Buffer[]; signers: Buffer[]};
export function signingBlock(b: Buffer, cd: number) {
  const found: Block[] = [];
  if (cd < 32 || cd > b.length || b.toString("latin1", cd - 16, cd) !== "APK Sig Block 42") return found;
  const size = b.readBigUInt64LE(cd - 24); if (size < 24n || size > BigInt(cd - 8)) throw new Error("Ukuran APK Signing Block tidak valid.");
  const start = cd - Number(size) - 8; if (b.readBigUInt64LE(start) !== size) throw new Error("APK Signing Block tidak konsisten.");
  for (let p = start + 8, n = 0; p < cd - 24 && n < 64; n++) {
    if (p + 12 > cd - 24) throw new Error("Pasangan APK Signing Block terpotong.");
    const len = b.readBigUInt64LE(p); if (len < 4n || len > BigInt(cd - 24 - p - 8)) throw new Error("Pasangan APK Signing Block di luar batas.");
    const id = b.readUInt32LE(p + 8), scheme = SCHEMES[id];
    if (scheme) {const signers = items(lp(b.subarray(p + 12, p + 8 + Number(len)), 0).value).slice(0, 4); found.push({scheme, signers, certs: signerCerts(signers)});}
    p += 8 + Number(len);
  }
  return found;
}
// Signature algorithm IDs of APK Signature Scheme v2/v3 (content digest: chunked SHA-256/512, or verity which is not recomputed).
type Alg = {hash: "sha256" | "sha512"; kind: "pss" | "pkcs1" | "ec" | "dsa"; content: "sha256" | "sha512" | "verity"; label: string};
const ALGS: Record<number, Alg> = {
  0x0101: {hash: "sha256", kind: "pss", content: "sha256", label: "RSA-PSS SHA-256"}, 0x0102: {hash: "sha512", kind: "pss", content: "sha512", label: "RSA-PSS SHA-512"},
  0x0103: {hash: "sha256", kind: "pkcs1", content: "sha256", label: "RSA PKCS#1 SHA-256"}, 0x0104: {hash: "sha512", kind: "pkcs1", content: "sha512", label: "RSA PKCS#1 SHA-512"},
  0x0201: {hash: "sha256", kind: "ec", content: "sha256", label: "ECDSA SHA-256"}, 0x0202: {hash: "sha512", kind: "ec", content: "sha512", label: "ECDSA SHA-512"},
  0x0301: {hash: "sha256", kind: "dsa", content: "sha256", label: "DSA SHA-256"},
  0x0421: {hash: "sha256", kind: "pkcs1", content: "verity", label: "RSA PKCS#1 SHA-256 (verity)"}, 0x0423: {hash: "sha256", kind: "ec", content: "verity", label: "ECDSA SHA-256 (verity)"}, 0x0425: {hash: "sha256", kind: "dsa", content: "verity", label: "DSA SHA-256 (verity)"},
};
const CHUNK = 1024 * 1024;
// Chunked digest (spec: 0xa5 || u32 len || chunk per 1 MB chunk; 0x5a || u32 count || chunk digests) over ZIP entries,
// central directory and EOCD (with its CD offset replaced by the signing block offset). Views only, no copies.
export function contentDigest(b: Buffer, blockStart: number, cd: number, eocd: number, alg: "sha256" | "sha512", deadline = Infinity): Buffer | null {
  const end = Buffer.from(b.subarray(eocd)); end.writeUInt32LE(blockStart, 16);
  const sections = [b.subarray(0, blockStart), b.subarray(cd, eocd), end], count = sections.reduce((n, s) => n + Math.ceil(s.length / CHUNK), 0);
  const top = createHash(alg), head = Buffer.alloc(5); head[0] = 0x5a; head.writeUInt32LE(count, 1); top.update(head);
  let n = 0;
  for (const s of sections) for (let p = 0; p < s.length; p += CHUNK) {
    if ((n++ & 15) === 0 && Date.now() > deadline) return null;
    const chunk = s.subarray(p, Math.min(s.length, p + CHUNK)), h = Buffer.alloc(5); h[0] = 0xa5; h.writeUInt32LE(chunk.length, 1);
    top.update(createHash(alg).update(h).update(chunk).digest());
  }
  return top.digest();
}
const keyOf = (der: Buffer) => createPublicKey({key: der, format: "der", type: "spki"});
function checkSigner(scheme: string, signer: Buffer, digestOf: (alg: "sha256" | "sha512") => Buffer | null): [boolean | null, string] {
  const sd = lp(signer, 0); let p = sd.next; if (scheme !== "v2") p += 8; // v3: minSdk, maxSdk
  const sigs = items(lp(signer, p).value), pub = lp(signer, lp(signer, p).next).value;
  const parsed = sigs.map(s => ({id: s.readUInt32LE(0), sig: lp(s, 4).value}));
  if (!parsed.length) return [false, "tidak ada tanda tangan"];
  const usable = parsed.filter(s => ALGS[s.id]).sort((x, y) => Number(ALGS[x.id].content === "verity") - Number(ALGS[y.id].content === "verity"));
  if (!usable.length) return [null, `algoritma tidak didukung (${parsed.map(s => `0x${s.id.toString(16)}`).join(", ")})`];
  let key: KeyObject; try {key = keyOf(pub);} catch {return [false, "kunci publik penanda tangan tidak valid"];}
  const {id, sig} = usable[0], alg = ALGS[id];
  const ok = verify(alg.hash, sd.value, alg.kind === "pss" ? {key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: alg.hash === "sha256" ? 32 : 64} : alg.kind === "pkcs1" ? {key, padding: constants.RSA_PKCS1_PADDING} : {key, dsaEncoding: "der"}, sig);
  if (!ok) return [false, `tanda tangan ${alg.label} atas signed data tidak cocok`];
  const digests = items(lp(sd.value, 0).value).map(d => ({id: d.readUInt32LE(0), value: lp(d, 4).value})), certs = items(lp(sd.value, lp(sd.value, 0).next).value);
  if (!certs.length) return [false, "tidak ada sertifikat di signed data"];
  try {if (!new X509Certificate(certs[0]).publicKey.export({type: "spki", format: "der"}).equals(key.export({type: "spki", format: "der"}))) return [false, "kunci publik tidak cocok dengan sertifikat"];} catch {return [false, "sertifikat penanda tangan tidak dapat dibaca"];}
  const expected = digests.find(d => d.id === id)?.value; if (!expected) return [false, "digest untuk algoritma tanda tangan tidak ada"];
  if (alg.content === "verity") return [null, `tanda tangan ${alg.label} valid; digest isi verity tidak dihitung ulang`];
  const actual = digestOf(alg.content); if (!actual) return [null, `tanda tangan ${alg.label} valid; digest isi dilewati karena batas waktu`];
  return actual.equals(expected) ? [true, `${alg.label} valid, digest isi cocok`] : [false, `${alg.label} sah atas signed data tetapi digest isi APK TIDAK cocok (isi diubah setelah ditandatangani)`];
}
export type Signing = {schemes: string[]; certificates: CertInfo[]; errors: string[]; verified?: boolean | null; verification?: string[]};
export function apkSigning(buffer: Buffer, entries: ZipEntry[], deadline = Infinity): Signing {
  const schemes: string[] = [], certs = new Map<string, CertInfo>(), errors: string[] = [], verification: string[] = []; let verified = null as boolean | null;
  const add = (der: Buffer) => {try {const c = certInfo(der); if (!certs.has(c.sha256) && certs.size < 5) certs.set(c.sha256, c);} catch {errors.push("Sertifikat X.509 tidak dapat dibaca.");}};
  try {
    const dir = zipDirectory(buffer), blocks = signingBlock(buffer, dir.offset);
    const start = blocks.length ? dir.offset - Number(buffer.readBigUInt64LE(dir.offset - 24)) - 8 : 0, cache = new Map<string, Buffer | null>();
    const digestOf = (alg: "sha256" | "sha512") => {if (!cache.has(alg)) cache.set(alg, contentDigest(buffer, start, dir.offset, dir.end, alg, deadline)); return cache.get(alg)!;};
    for (const s of blocks) {
      schemes.push(s.scheme); s.certs.forEach(add);
      s.signers.forEach((signer, i) => {
        let r: [boolean | null, string]; try {r = checkSigner(s.scheme, signer, digestOf);} catch {r = [false, "struktur signer rusak"];}
        verification.push(`${s.scheme}${s.signers.length > 1 ? ` signer ${i + 1}` : ""}: ${r[1]}`);
        verified = r[0] === false || verified === false ? false : r[0] === true ? (verified ?? true) : verified;
      });
      if (!s.signers.length) {verified = false; verification.push(`${s.scheme}: tidak ada signer`);}
    }
    // Any unverifiable signer keeps the overall answer open unless something already failed.
    if (verified === true && verification.some(v => /tidak didukung|dilewati|tidak dihitung/.test(v))) verified = null;
  } catch (e) {errors.push(e instanceof Error ? e.message : "APK Signing Block tidak dapat dibaca.");}
  const v1 = entries.filter(e => /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(e.name)).slice(0, 3);
  if (v1.length) schemes.unshift("v1");
  for (const e of v1) try {pkcs7(unzipEntry(buffer, e, 1024 * 1024)).certs.forEach(add);} catch {errors.push(`${e.name.slice(0, 80)} bukan PKCS#7 yang dapat dibaca.`);}
  if (verified === null && v1.length && !verification.length) verification.push("hanya skema v1 (JAR); tanda tangan v1 tidak diverifikasi");
  return {schemes: [...new Set(schemes)], certificates: [...certs.values()], errors, verified, verification: verification.slice(0, 6)};
}
// Indonesian indicators for certificate traits commonly seen in quickly-built scam APKs.
export function signingIndicators(s: Signing, now = Date.now()) {
  const out: {name: string; evidence: string}[] = [];
  if (!s.schemes.length) out.push({name: "APK tidak bertanda tangan", evidence: "Tidak ada APK Signing Block v2/v3 maupun signature v1 di META-INF. Android menolak memasang APK tanpa tanda tangan; file mungkin rusak, dimodifikasi, atau bukan rilis resmi."});
  if (s.verified === false) out.push({name: "Tanda tangan APK tidak valid (kemungkinan dimodifikasi/repackaged)", evidence: `Verifikasi kriptografis APK Signature Scheme gagal: ${(s.verification || []).join("; ")}. Android menolak memasang APK seperti ini; file kemungkinan diubah setelah ditandatangani (repackaging/injeksi kode) atau sengaja dirusak.`.slice(0, 600)});
  for (const c of s.certificates) {
    if (/CN=Android Debug/i.test(c.subject)) out.push({name: "Ditandatangani sertifikat debug Android", evidence: `Sertifikat debug bawaan Android Studio, bukan kunci rilis penerbit: ${certSummary(c)}.`});
    if (/emailAddress=android@android\.com/i.test(c.subject) && /CN=Android(?:,|$)/.test(c.subject)) out.push({name: "Ditandatangani kunci uji AOSP publik", evidence: `Kunci testkey/platform AOSP bersifat publik sehingga siapa pun dapat menandatangani dengannya: ${certSummary(c)}.`});
    const age = (now - Date.parse(c.validFrom)) / 86400000;
    if (c.selfSigned && age >= -2 && age < 60) out.push({name: "Sertifikat penanda tangan sangat baru", evidence: `Sertifikat swa-tanda-tangan dibuat ${Math.max(0, Math.round(age))} hari sebelum analisis; umum pada APK penipuan yang dibuat ulang per kampanye: ${certSummary(c)}.`});
  }
  return out;
}
