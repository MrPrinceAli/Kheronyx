// Anti-analysis tricks seen in real MalwareBazaar samples (SpyNote, SMSspy), rebuilt as tiny fixtures.
import { test } from "node:test";
import assert from "node:assert/strict";
import AdmZip from "adm-zip";
import { extractFile } from "../lib/extract";
import { parseAssessment } from "../lib/ai";
import { readZip, salvageBinaryXml, unzipEntry } from "../lib/zip";
import type { Artifact } from "../lib/types";

test("BadPack: a junk compression method on deflated data is inflated like Android does", () => {
  const zip = new AdmZip(); zip.addFile("AndroidManifest.xml", Buffer.alloc(4000, 65)); const buffer = zip.toBuffer();
  const central = buffer.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02])), local = buffer.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
  buffer.writeUInt16LE(24539, central + 10); buffer.writeUInt16LE(24539, local + 8);
  const [entry] = readZip(buffer);
  assert.equal(entry.method, 24539);
  assert.equal(unzipEntry(buffer, entry, 1 << 20).length, 4000);
});

test("an empty classes.dex is a packer sign, not a failed extraction", async () => {
  const zip = new AdmZip(); zip.addFile("AndroidManifest.xml", Buffer.from("not binary xml")); zip.addFile("classes.dex", Buffer.alloc(0));
  const a = await extractFile(zip.toBuffer(), "kurir.apk");
  assert.ok(a.indicators.some(i => i.name.startsWith("File kode utama kosong")));
  assert.ok(!a.limitations.some(l => /classes\.dex tidak berhasil dibedah/.test(l)));
});

const verdict = (risk: string, confidence = "high") => JSON.stringify({risk, confidence, summary: "s", findings: [], recommendations: ["r"], limitations: ["l"]});
const artifact = (incomplete: boolean) => ({filename: "x.apk", kind: "apk", size: 1, sha256: "0".repeat(64), metadata: {}, strings: [], urls: [], indicators: [], limitations: [], incomplete}) as Artifact;

test("incomplete extraction blocks a safe verdict but keeps concrete danger", () => {
  assert.equal(parseAssessment(verdict("low"), artifact(true)).risk, "unknown");
  const high = parseAssessment(verdict("high"), artifact(true));
  assert.equal(high.risk, "high"); assert.equal(high.confidence, "medium");
  assert.equal(parseAssessment(verdict("low"), artifact(false)).risk, "low");
});

test("BadPack manifest: lying ZIP sizes and a zeroed AXML type are salvaged", async () => {
  const axml = Buffer.alloc(96); axml.writeUInt16LE(0, 0); axml.writeUInt16LE(8, 2); axml.writeUInt32LE(96, 4); axml.writeUInt16LE(1, 8);
  const zip = new AdmZip(); zip.addFile("AndroidManifest.xml", axml); zip.getEntries()[0].header.method = 0;
  const buffer = zip.toBuffer(), central = buffer.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  buffer.writeUInt16LE(47927, central + 10); buffer.writeUInt32LE(30, central + 20);
  const [entry] = readZip(buffer);
  assert.throws(() => unzipEntry(buffer, entry, 1 << 20));
  const repaired = salvageBinaryXml(buffer, entry, 1 << 20);
  assert.equal(repaired?.length, 96); assert.equal(repaired?.readUInt16LE(0), 3);
});
