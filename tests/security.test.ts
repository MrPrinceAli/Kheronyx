import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import AdmZip from "adm-zip";
import { createSession, validateSession, verifyPassword } from "../lib/auth";
import { extractFile, fileKind } from "../lib/extract";
import { parseAssessment, INCOMPLETE_NOTE } from "../lib/ai";
import { readZip, unzipEntry } from "../lib/zip";
import type { Artifact } from "../lib/types";
process.env.ACCESS_PASSWORD="test-only-password";process.env.SESSION_SECRET="a-test-secret-long-enough-for-session-signing";delete process.env.ACCESS_PASSWORD_HASH;
test("session rejects forgery, extra segments, expiration, and changed signing secret",()=>{
  const now=Date.now(),token=createSession(now);assert.match(validateSession(token,now)||"",/^[a-f0-9]{32}$/);
  assert.equal(validateSession(token+".suffix",now),null);assert.equal(validateSession(token.replace(/.$/,"!"),now),null);
  assert.equal(validateSession(token,now+13*3600*1000),null);
  const old=process.env.SESSION_SECRET;process.env.SESSION_SECRET="changed";assert.equal(validateSession(token,now),null);process.env.SESSION_SECRET=old;
  assert.equal(verifyPassword("wrong"),false);assert.equal(verifyPassword("test-only-password"),true);
});
test("file types distinguish JPEG from disk images and keep DMG unavailable",()=>{assert.equal(fileKind("photo.JPEG"),"jpg");assert.throws(()=>fileKind("disk.img"));assert.throws(()=>fileKind("installer.dmg"),/coming soon/);});
test("rejects disguised executables and empty uploads before analysis",async()=>{await assert.rejects(extractFile(Buffer.from("MZfake malware"),"picture.png"),/ekstensinya/);await assert.rejects(extractFile(Buffer.alloc(0),"file.pdf"),/Ukuran/);});
test("PNG metadata reports appended payload without claiming malware",async()=>{
  const png=Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAACXBIWXMAAAPoAAAD6AG1e1JrAAAADElEQVQImWP4//8/AAX+Av5Y8msOAAAAAElFTkSuQmCC","base64");
  const result=await extractFile(Buffer.concat([png,Buffer.from("MZ appended test payload")]),"photo.png");assert.equal(result.kind,"png");assert.equal(result.incomplete,false);assert.deepEqual(result.metadata.dimensions,{width:1,height:1,bitDepth:8});assert.ok(result.indicators.some(i=>i.name.includes("akhir gambar")));assert.equal(result.sha256.length,64);
});
test("JPEG extracts dimensions from a real encoder-produced image",async()=>{
  const jpg=readFileSync(new URL("./fixtures/one-pixel.jpg",import.meta.url));
  const result=await extractFile(jpg,"photo.jpg");assert.equal(result.incomplete,false);assert.deepEqual(result.metadata.dimensions,{width:1,height:1});
});
test("PDF extracts text and metadata without executing document content",async()=>{
  const objects=["<< /Type /Catalog /Pages 2 0 R >>","<< /Type /Pages /Kids [3 0 R] /Count 1 >>","<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>","<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"];
  const stream="BT /F1 12 Tf 10 100 Td (Hello Kheronyx) Tj ET";objects.push(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
  let text="%PDF-1.4\n";const offsets=[0];for(let i=0;i<objects.length;i++){offsets.push(Buffer.byteLength(text));text+=`${i+1} 0 obj\n${objects[i]}\nendobj\n`;}
  const xref=Buffer.byteLength(text);text+=`xref\n0 6\n0000000000 65535 f \n${offsets.slice(1).map(n=>`${String(n).padStart(10,"0")} 00000 n \n`).join("")}trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  const result=await extractFile(Buffer.from(text),"document.pdf");assert.equal(result.incomplete,false);assert.equal(result.metadata.pages,1);assert.match(String(result.metadata.textExcerpt),/Hello Kheronyx/);
});
test("malformed EXE remains explicitly incomplete",async()=>{const result=await extractFile(Buffer.from("MZ not a valid portable executable"),"broken.exe");assert.equal(result.incomplete,true);assert.ok(result.limitations.some(l=>l.includes("tidak boleh dianggap aman")));});
test("APK parses archive safely and does not treat an unreadable manifest as safe",async()=>{const zip=new AdmZip();zip.addFile("AndroidManifest.xml",Buffer.from("broken binary manifest"));zip.addFile("classes.dex",Buffer.from("https://example.com/ innocent test string"));const buffer=zip.toBuffer();const result=await extractFile(buffer,"test.apk");assert.equal(result.kind,"apk");assert.equal(result.incomplete,true);assert.equal(result.metadata.entries,2);});
test("ZIP decompression is bounded even if central directory size is forged",()=>{
  const zip=new AdmZip();zip.addFile("AndroidManifest.xml",Buffer.alloc(2*1024*1024,65));const buffer=zip.toBuffer();const central=buffer.indexOf(Buffer.from([0x50,0x4b,0x01,0x02]));buffer.writeUInt32LE(100,central+24);const entries=readZip(buffer);assert.throws(()=>unzipEntry(buffer,entries[0],1024));
});
const artifact:Artifact={filename:"sample.png",kind:"png",size:42,sha256:"a".repeat(64),metadata:{},strings:[],urls:[],indicators:[],limitations:["No sandbox"],incomplete:true};
test("incomplete extraction forces unknown risk even when AI claims low risk",()=>{const result=parseAssessment(JSON.stringify({risk:"low",confidence:"high",summary:"Example",findings:[],recommendations:["Review"],limitations:["Example"]}),artifact);assert.equal(result.risk,"unknown");assert.equal(result.confidence,"low");assert.ok(result.limitations.includes(INCOMPLETE_NOTE));assert.ok(!result.limitations.includes("No sandbox"),"technical parser limitations stay in the artifact");assert.ok(result.limitations.length<=5);});
test("rejects invalid model output rather than inventing a report",()=>{assert.throws(()=>parseAssessment('{"summary":"safe"}',artifact));assert.throws(()=>parseAssessment("malformed response",artifact));});
