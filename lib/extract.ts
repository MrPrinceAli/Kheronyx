import { createHash } from "node:crypto";
import type { Artifact, FileKind } from "./types";
import { readZip, unzipEntry } from "./zip";
import { androidManifest } from "./axml";
import { KIND_LIMITS, formatMB } from "./limits";
export function fileKind(filename: string): FileKind {
  const ext = filename.split(".").pop()?.toLowerCase();
  if (ext === "jpeg") return "jpg";
  if (ext === "dmg") throw new Error("Dukungan DMG coming soon.");
  if (["pdf", "apk", "exe", "png", "jpg"].includes(ext || "")) return ext as FileKind;
  throw new Error("Format belum didukung. Pilih PDF, APK, EXE, PNG, atau JPG.");
}
export function validateSignature(buffer: Buffer, kind: FileKind) {
  const valid = kind === "pdf" ? buffer.subarray(0, 1024).includes(Buffer.from("%PDF-")) : kind === "png" ? buffer.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])) : kind === "jpg" ? buffer.length >= 3 && buffer[0] === 255 && buffer[1] === 216 && buffer[2] === 255 : kind === "exe" ? buffer.toString("ascii",0,2) === "MZ" : buffer.length >= 4 && buffer.readUInt32LE(0) === 0x04034b50;
  if (!valid) throw new Error("Isi file tidak cocok dengan ekstensinya. File ditolak.");
}
export function printableStrings(buffer: Buffer, max = 250) {
  const sample = buffer.subarray(0, 2 * 1024 * 1024).toString("latin1");
  return [...new Set(sample.match(/[\x20-\x7e]{7,220}/g) || [])].slice(0,max);
}
function entropy(buffer: Buffer) {
  const counts = new Uint32Array(256); for (const b of buffer) counts[b]++;
  let n = 0; for (const c of counts) if (c) {const p = c / buffer.length; n -= p * Math.log2(p);} return Math.round(n * 100) / 100;
}
function png(buffer: Buffer, a: Artifact) {
  let p = 8, end = false; const chunks: {type: string; size: number}[] = []; const texts: string[] = [];
  while (p + 12 <= buffer.length && chunks.length < 2000) {
    const size = buffer.readUInt32BE(p), type = buffer.toString("ascii",p+4,p+8);
    if (p + size + 12 > buffer.length || !/^[A-Za-z]{4}$/.test(type)) throw new Error("Struktur chunk PNG tidak valid.");
    chunks.push({type,size});
    if (type === "IHDR" && size === 13) a.metadata.dimensions = {width:buffer.readUInt32BE(p+8),height:buffer.readUInt32BE(p+12),bitDepth:buffer[p+16]};
    if (["tEXt","iTXt"].includes(type)) texts.push(buffer.toString("utf8",p+8,p+8+Math.min(size,3000)));
    if (type === "zTXt") a.limitations.push("Metadata PNG terkompresi tidak didekompresi.");
    p += size + 12; if (type === "IEND") {end = true; break;}
  }
  if (!end || chunks[0]?.type !== "IHDR") throw new Error("Struktur PNG tidak lengkap.");
  a.metadata.chunks = chunks.slice(0,80); a.metadata.text = texts.slice(0,10);
  if (p < buffer.length) a.indicators.push({name:"Data setelah akhir gambar",evidence:`${buffer.length-p} byte setelah chunk IEND.`});
  a.limitations.push("Pixel tidak dirender; steganografi dan eksploit decoder gambar tidak dapat dipastikan.");
}
function jpg(buffer: Buffer, a: Artifact) {
  let p = 2; const metadata: {marker:string; size:number; text?:string}[] = []; let dimensions = false;
  while (p + 4 <= buffer.length && metadata.length < 500) {
    if (buffer[p] !== 255) throw new Error("Marker JPEG tidak valid.");
    while (p < buffer.length && buffer[p] === 255) p++;
    const marker = buffer[p++]; if (marker === 0xda || marker === 0xd9) break;
    if (marker === 1 || marker >= 0xd0 && marker <= 0xd7) continue;
    const size = buffer.readUInt16BE(p); if (size < 2 || p + size > buffer.length) throw new Error("Segmen JPEG terpotong.");
    const row: {marker:string;size:number;text?:string} = {marker:marker.toString(16),size};
    if (marker >= 0xe0 && marker <= 0xef || marker === 0xfe) row.text = printableStrings(buffer.subarray(p+2,p+size),12).join(" | ").slice(0,2000);
    metadata.push(row);
    if ([0xc0,0xc1,0xc2,0xc3,0xc5,0xc6,0xc7,0xc9,0xca,0xcb,0xcd,0xce,0xcf].includes(marker) && size >= 8) {a.metadata.dimensions = {height:buffer.readUInt16BE(p+3),width:buffer.readUInt16BE(p+5)};dimensions=true;}
    p += size;
  }
  const eoi = buffer.lastIndexOf(Buffer.from([255,217])); if (eoi < 0 || !dimensions) throw new Error("Struktur JPEG tidak lengkap.");
  a.metadata.segments = metadata.slice(0,50);
  if (eoi + 2 < buffer.length) a.indicators.push({name:"Data setelah akhir gambar",evidence:`${buffer.length-eoi-2} byte setelah marker EOI.`});
  a.limitations.push("Pixel tidak dirender; steganografi dan eksploit decoder gambar tidak dapat dipastikan.");
}
function pe(buffer: Buffer, a: Artifact) {
  if (buffer.length < 64) throw new Error("Header EXE terpotong.");
  const p = buffer.readUInt32LE(60); if (p + 24 > buffer.length || buffer.readUInt32LE(p) !== 0x4550) throw new Error("EXE bukan Portable Executable yang valid.");
  const count = buffer.readUInt16LE(p+6), optionalSize = buffer.readUInt16LE(p+20), opt = p+24;
  if (count > 96 || opt + optionalSize + count * 40 > buffer.length || optionalSize < 96) throw new Error("Tabel section EXE tidak valid.");
  const magic = buffer.readUInt16LE(opt); if (magic !== 0x10b && magic !== 0x20b) throw new Error("Format optional header EXE belum didukung.");
  const directory = opt + (magic === 0x20b ? 112 : 96), sections: {name:string;size:number;entropy:number;flags:string;virtualAddress:number;virtualSize:number;offset:number}[] = [];
  let fileEnd = opt+optionalSize+count*40;
  for(let i=0;i<count;i++) {
    const s=opt+optionalSize+i*40,size=buffer.readUInt32LE(s+16),offset=buffer.readUInt32LE(s+20),flags=buffer.readUInt32LE(s+36);
    if(offset+size>buffer.length) throw new Error("Section EXE terpotong.");
    const row={name:buffer.toString("ascii",s,s+8).replace(/\0/g,""),size,entropy:entropy(buffer.subarray(offset,offset+size)),flags:flags.toString(16),virtualAddress:buffer.readUInt32LE(s+12),virtualSize:buffer.readUInt32LE(s+8),offset}; sections.push(row); fileEnd=Math.max(fileEnd,offset+size);
    if(size>1000 && row.entropy>7.5) a.indicators.push({name:"Section berentropi tinggi",evidence:`${row.name}: entropy ${row.entropy}; bisa berupa kompresi, enkripsi, atau packing.`});
    if((flags & 0x20000000) && (flags & 0x80000000)) a.indicators.push({name:"Section executable dan writable",evidence:`Section ${row.name} memiliki kedua flag tersebut.`});
  }
  const toOffset=(rva:number)=>{const s=sections.find(s=>rva>=s.virtualAddress && rva<s.virtualAddress+Math.max(s.size,s.virtualSize));return s?s.offset+rva-s.virtualAddress:-1;};
  const imports:string[]=[];
  if(directory+16<=opt+optionalSize) {
    const rva=buffer.readUInt32LE(directory+8); let q=toOffset(rva);
    for(let i=0;q>=0 && q+20<=buffer.length && i<100;i++,q+=20) {
      const nameRva=buffer.readUInt32LE(q+12);if(!nameRva)break;const n=toOffset(nameRva);if(n>=0 && n<buffer.length){const e=buffer.indexOf(0,n);imports.push(buffer.toString("ascii",n,Math.min(e<0?n+200:e,n+200)));}
    }
  }
  const hasCertificate=directory+40<=opt+optionalSize && buffer.readUInt32LE(directory+36)>0;
  a.metadata={architecture:buffer.readUInt16LE(p+4).toString(16),peFormat:magic===0x20b?"PE32+":"PE32",sections,importedLibraries:imports,certificateTablePresent:hasCertificate,overlayBytes:Math.max(0,buffer.length-fileEnd)};
  a.limitations.push("Program tidak dijalankan. Import function, signature Authenticode, reputasi penerbit, dan isi packed/encrypted belum diverifikasi.");
}
function apk(buffer: Buffer, a: Artifact) {
  const entries=readZip(buffer); const manifest=entries.find(e=>e.name==="AndroidManifest.xml"); if(!manifest)throw new Error("APK tidak memiliki AndroidManifest.xml.");
  a.metadata.entries=entries.length; a.metadata.nativeLibraries=entries.filter(e=>/^lib\/.+\.so$/.test(e.name)).map(e=>e.name).slice(0,60);
  a.metadata.signatureFiles=entries.filter(e=>/^META-INF\/.+\.(RSA|DSA|EC|SF)$/i.test(e.name)).map(e=>e.name).slice(0,20);
  const suspicious=entries.filter(e=>e.name.split(/[\\/]/).includes("..") || e.name.startsWith("/") || /^[A-Za-z]:/.test(e.name));
  if(suspicious.length)a.indicators.push({name:"Path arsip mencurigakan",evidence:suspicious.slice(0,10).map(e=>e.name).join(", ")});
  try {
    const tags=androidManifest(unzipEntry(buffer,manifest,2*1024*1024));
    a.metadata.manifest=tags.find(t=>t.tag==="manifest")?.attributes;
    a.metadata.sdk=tags.find(t=>t.tag==="uses-sdk")?.attributes;
    a.metadata.application=tags.find(t=>t.tag==="application")?.attributes;
    a.metadata.permissions=tags.filter(t=>t.tag.startsWith("uses-permission")).map(t=>t.attributes.name).filter(Boolean);
    a.metadata.exportedComponents=tags.filter(t=>t.attributes.exported==="true").map(t=>({tag:t.tag,...t.attributes})).slice(0,50);
  } catch {a.incomplete=true; a.limitations.push("Manifest APK tidak berhasil dibaca sepenuhnya.");}
  const dex=entries.filter(e=>/^classes\d*\.dex$/.test(e.name)); a.metadata.dexFiles=dex.map(e=>({name:e.name,size:e.size}));
  for(const e of dex.slice(0,3)) {
    try {const data=unzipEntry(buffer,e,16*1024*1024);a.strings.push(...printableStrings(data,180));}catch{a.incomplete=true;a.limitations.push(`Kode ${e.name} tidak berhasil dibedah dalam batas sumber daya.`);}
  }
  if(dex.length>3)a.limitations.push("String hanya diambil dari tiga file DEX pertama.");
  a.limitations.push("APK tidak dijalankan. Kode tidak didekompilasi seluruhnya, library native dan signature APK v2/v3 belum diverifikasi; izin luas bukan bukti malware.");
}
async function pdf(buffer:Buffer,a:Artifact) {
  const raw=buffer.toString("latin1");
  for(const [token,name] of [["/JavaScript","JavaScript tertanam"],["/JS","Objek skrip"],["/OpenAction","Tindakan saat dibuka"],["/Launch","Tindakan launch"],["/EmbeddedFile","File tertanam"]])if(raw.includes(token))a.indicators.push({name,evidence:`Token ${token} ditemukan pada struktur PDF; memerlukan penilaian konteks.`});
  const {getDocument}=await import("pdfjs-dist/legacy/build/pdf.mjs");
  const task=getDocument({data:new Uint8Array(buffer),isEvalSupported:false,useSystemFonts:false,disableFontFace:true,useWorkerFetch:false,verbosity:0});
  try {
    const doc=await task.promise; a.metadata.pages=doc.numPages;
    const metadata=await doc.getMetadata();a.metadata.info=metadata.info;
    const text:string[]=[];
    for(let i=1;i<=Math.min(doc.numPages,10);i++) {
      const page=await doc.getPage(i);const content=await page.getTextContent();text.push(content.items.map(i=>"str" in i?i.str:"").join(" ").slice(0,2500));
      const annotations=await page.getAnnotations(); for(const n of annotations.slice(0,50))if(n.url)a.urls.push(String(n.url).slice(0,1000));page.cleanup();
    }
    a.metadata.textExcerpt=text.join("\n").slice(0,18000);
    const actions=await doc.getJSActions();if(actions)a.metadata.javascript=JSON.stringify(actions).slice(0,8000);
    const attachments=await doc.getAttachments();if(attachments)a.metadata.attachments=Object.values(attachments).slice(0,30).map(value=>{const x=value as {filename:string;content:Uint8Array};return {filename:x.filename,size:x.content.length};});
    if(doc.numPages>10)a.limitations.push("Teks dan tautan hanya diekstrak dari sepuluh halaman pertama.");
    a.limitations.push("PDF tidak dibuka secara interaktif; lampiran tidak dipindai secara terpisah dan eksploit reader tidak dapat dipastikan.");
  } finally {await task.destroy();}
}
export async function extractFile(buffer:Buffer,filename:string):Promise<Artifact> {
  const kind=fileKind(filename); if(!buffer.length || buffer.length>KIND_LIMITS[kind])throw new Error(`Ukuran file ${kind.toUpperCase()} harus antara 1 byte dan ${formatMB(KIND_LIMITS[kind])}.`);
  validateSignature(buffer,kind);
  const a:Artifact={filename:filename.replace(/[\x00-\x1f\x7f]/g,"").slice(0,180),kind,size:buffer.length,sha256:createHash("sha256").update(buffer).digest("hex"),metadata:{},strings:printableStrings(buffer),urls:[],indicators:[],limitations:[],incomplete:false};
  try {if(kind==="pdf")await pdf(buffer,a);else if(kind==="exe")pe(buffer,a);else if(kind==="apk")apk(buffer,a);else if(kind==="png")png(buffer,a);else jpg(buffer,a);}catch{a.incomplete=true;a.limitations.push("Struktur internal tidak berhasil dibaca sepenuhnya; hasil tidak boleh dianggap aman.");}
  a.strings=[...new Set(a.strings)].slice(0,500);
  a.urls=[...new Set([...a.urls,...a.strings.flatMap(s=>s.match(/https?:\/\/[^\s<>"'\\]{4,300}/g)||[])])].slice(0,60);
  a.limitations.push("Ini analisis statis berbantuan AI, tanpa antivirus, sandbox eksekusi, atau pencarian reputasi eksternal. Malware baru dan payload tersembunyi dapat terlewat.");
  let sampled=false;
  function bounded(value:unknown,depth=0):unknown {
    if(depth>7){sampled=true;return "[Depth limit]";}
    if(typeof value==="string" && value.length>18000){sampled=true;return value.slice(0,18000);}
    if(Array.isArray(value)){if(value.length>100)sampled=true;return value.slice(0,100).map(v=>bounded(v,depth+1));}
    if(value && typeof value==="object"){const entries=Object.entries(value);if(entries.length>100)sampled=true;return Object.fromEntries(entries.slice(0,100).map(([k,v])=>[k,bounded(v,depth+1)]));}
    return value;
  }
  a.metadata=bounded(a.metadata) as Record<string,unknown>;
  if(sampled)a.limitations.push("Metadata yang besar dibatasi menjadi cuplikan; seluruh konten belum diperiksa.");
  a.limitations.push("String dan URL yang diberikan kepada AI berupa sampel terbatas.");
  return a;
}
