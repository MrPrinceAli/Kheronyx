import { createHash } from "node:crypto";
import { constants, inflateSync } from "node:zlib";
import type { Artifact, FileKind } from "./types";
import { readZip, unzipEntry } from "./zip";
import { androidManifest, resourceStrings } from "./axml";
import { KIND_LIMITS, MB, formatMB } from "./limits";
import { parseDex } from "./dex";
import { Signals, behaviorIndicator, behaviorMetadata, evaluate, hasLauncher, manifestModel, redactSecrets, type Behavior } from "./behaviors";
import { apkSigning, signingIndicators } from "./apk-signing";
import { entropy, findPayloads } from "./apk-payloads";
import { importBehaviors, readImports } from "./pe-imports";
import { certInfo, certSummary, pkcs7 } from "./certs";
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
// UTF-16LE runs (.NET user strings, Windows resources) that printableStrings cannot see.
function wideStrings(buffer: Buffer, max = 400) {
  return [...new Set((buffer.subarray(0, 4 * MB).toString("latin1").match(/(?:[\x20-\x7e]\x00){7,220}/g) || []).map(s => s.replace(/\x00/g, "")))].slice(0, max);
}
// Exfiltration/lure signals that apply to any file type (Telegram bots, webhooks, raw-IP panels...).
function stringSignals(a: Artifact, strings: string[], extra: Behavior[] = [], lure = true) {
  const sig = new Signals(); sig.strings(strings);
  const list = evaluate(sig, manifestModel(null), extra).filter(b => extra.includes(b) || b.id.startsWith("exfil_") || lure && b.id === "lure_keywords");
  if (list.length) {a.metadata.behaviors = behaviorMetadata(list); a.indicators.unshift(...list.map(behaviorIndicator));}
  a.urls.push(...sig.rankedUrls().slice(0, 40));
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
  const headers=Math.min(buffer.readUInt32LE(opt+60),buffer.length), rvaCount=opt+(magic===0x20b?108:92), dirs=rvaCount+4<=opt+optionalSize?Math.min(buffer.readUInt32LE(rvaCount),16):0;
  const dir=(i:number)=>i<dirs && directory+i*8+8<=opt+optionalSize?{rva:buffer.readUInt32LE(directory+i*8),size:buffer.readUInt32LE(directory+i*8+4)}:{rva:0,size:0};
  const toOffset=(rva:number,length=1)=>{if(rva+length<=headers)return rva;const s=sections.find(s=>rva>=s.virtualAddress && rva<s.virtualAddress+Math.max(s.size,s.virtualSize));if(!s || rva-s.virtualAddress+length>s.size)return -1;return s.offset+rva-s.virtualAddress;};
  const imports=readImports(buffer,toOffset,magic===0x20b,dir(1).rva,dir(13).rva), names=imports.flatMap(i=>i.functions), total=imports.reduce((n,i)=>n+i.count,0);
  const wide=wideStrings(buffer), strings=[...a.strings,...wide], peBehaviors:Behavior[]=importBehaviors(imports);
  const shadow=strings.filter(x=>/vssadmin(?:\.exe)?\s+delete\s+shadows|shadowcopy\s+delete|bcdedit.{0,40}recoveryenabled\s+no|wbadmin\s+delete/i.test(x)).slice(0,3);
  if(shadow.length)peBehaviors.push({id:"shadow_delete",name:"Menghapus cadangan/shadow copy (pola ransomware)",severity:"high",evidence:shadow.map(x=>x.slice(0,160))});
  const dotnet=imports.length===1 && imports[0].dll==="mscoree.dll", packerSections=sections.map(s=>s.name).filter(n=>/^(?:UPX\d|\.aspack|\.adata|\.MPRESS\d|\.themida|\.vmp\d|\.petite|\.nsp\d|\.enigma\d|\.packed)$/i.test(n));
  const dense=sections.filter(s=>s.size>1000 && s.entropy>7.2).map(s=>`${s.name} (${s.entropy})`);
  if(packerSections.length || !dotnet && total<15 && dense.length)peBehaviors.push({id:"packed",name:"Kemungkinan dikemas (packed)",severity:"medium",evidence:[packerSections.length?`section packer: ${packerSections.join(", ")}`:"",`${total} fungsi import${names.some(f=>/^(?:LoadLibrary|GetProcAddress)/.test(f))?" (resolusi API dinamis lewat LoadLibrary/GetProcAddress)":""}`,dense.length?`section entropi tinggi: ${dense.slice(0,4).join(", ")}`:""].filter(Boolean)});
  // Authenticode: WIN_CERTIFICATE at a file offset (not an RVA). Certificates are read, signatures are not verified.
  const security=dir(4); let authenticode:Record<string,unknown>|undefined;
  if(security.size && security.rva+8<=buffer.length && security.rva+security.size<=buffer.length) {
    try {
      const length=Math.min(buffer.readUInt32LE(security.rva),security.size); if(buffer.readUInt16LE(security.rva+6)!==2 || length<8 || length>4*MB)throw new Error();
      const {certs,signerSerials}=pkcs7(buffer.subarray(security.rva+8,security.rva+length)), infos=certs.slice(0,8).flatMap(c=>{try{return [certInfo(c)];}catch{return [];}});
      const signer=infos.find(c=>signerSerials.includes(c.serial))||infos[0];
      if(signer){const {serial:_,selfSigned,...rest}=signer;authenticode={signer:rest,selfSigned,chain:infos.map(c=>c.subject).slice(0,4)};if(selfSigned)peBehaviors.push({id:"self_signed",name:"Authenticode swa-tanda-tangan",severity:"medium",evidence:[`Penanda tangan tidak diterbitkan CA: ${certSummary(signer)}`]});}
    } catch {a.limitations.push("Sertifikat Authenticode ada tetapi tidak berhasil dibaca.");}
  }
  const priority=(f:string)=>peBehaviors.some(b=>b.evidence.some(e=>e.endsWith(`!${f}`)))?0:1; let room=500;
  a.metadata={architecture:buffer.readUInt16LE(p+4).toString(16),peFormat:magic===0x20b?"PE32+":"PE32",sections,importedLibraries:imports.map(i=>i.dll),importCount:total,
    imports:imports.slice(0,60).map(i=>{const functions=[...i.functions].sort((x,y)=>priority(x)-priority(y)).slice(0,Math.max(0,Math.min(40,room)));room-=functions.length;return {dll:i.dll,count:i.count,functions,...i.delay?{delay:true}:{}};}),
    dotnet,certificateTablePresent:security.size>0,...authenticode?{authenticode}:{},overlayBytes:Math.max(0,buffer.length-fileEnd)};
  stringSignals(a,strings,peBehaviors);
  a.strings.push(...wide.slice(0,150));
  a.limitations.push("Program tidak dijalankan. Import function dibaca dari tabel import statis (API yang diresolusi saat runtime tidak terlihat); sertifikat Authenticode hanya dibaca tanpa verifikasi tanda tangan; reputasi penerbit dan isi packed/encrypted belum diverifikasi.");
}
// Known commercial packers/protectors (also used by malware to hide the real DEX).
const PACKER_FILES=/^(?:lib\/[^/]+\/)?(?:libjiagu[^/]*|libsecexe|libsecmain|libDexHelper[^/]*|libexecmain|libshell[a-z0-9_]*|libtup|libprotectClass|libnqshield|libmobisec|libbaiduprotect|libAppGuard|libitsec|libjgdtc)\.so$|^assets\/(?:ijiami\.dat|secData0\.jar|jiagu[^/]*|libjiagu[^/]*)$/i;
const PACKER_APPS=/^(?:com\.stub\.StubApp|com\.secneo\.apkwrapper\.|com\.tencent\.StubShell\.|com\.shell\.SuperApplication|s\.h\.e\.l\.l\.|com\.wrapper\.proxyapplication\.|com\.baidu\.protect\.|com\.bangcle\.)/;
// All classes*.dex are parsed one at a time (each ≤64 MB inflated, released before the next) within a shared
// 20 s / 768 MB budget, so a 250 MB APK stays well inside the function limits.
const DEX_MAX=64*MB, DEX_BUDGET_MS=20000, DEX_TOTAL=768*MB;
function apk(buffer: Buffer, a: Artifact) {
  const entries=readZip(buffer); const manifest=entries.find(e=>e.name==="AndroidManifest.xml"); if(!manifest)throw new Error("APK tidak memiliki AndroidManifest.xml.");
  a.metadata.entries=entries.length; a.metadata.nativeLibraries=entries.filter(e=>/^lib\/.+\.so$/.test(e.name)).map(e=>e.name).slice(0,60);
  a.metadata.signatureFiles=entries.filter(e=>/^META-INF\/.+\.(RSA|DSA|EC|SF)$/i.test(e.name)).map(e=>e.name).slice(0,20);
  const suspicious=entries.filter(e=>e.name.split(/[\\/]/).includes("..") || e.name.startsWith("/") || /^[A-Za-z]:/.test(e.name));
  if(suspicious.length)a.indicators.push({name:"Path arsip mencurigakan",evidence:suspicious.slice(0,10).map(e=>e.name).join(", ")});
  const tampered=entries.filter(e=>e.flags&1 || ![0,8].includes(e.method));
  if(tampered.length)a.indicators.push({name:"Header ZIP dimanipulasi (teknik anti-analisis)",evidence:`${tampered.length} entri memakai flag enkripsi palsu atau metode kompresi tak dikenal yang diabaikan Android tetapi menggagalkan alat analisis: ${tampered.slice(0,5).map(e=>e.name.slice(0,80)).join(", ")}`});
  let tags:ReturnType<typeof androidManifest>|null=null;
  try {
    tags=androidManifest(unzipEntry(buffer,manifest,2*1024*1024));
    a.metadata.manifest=tags.find(t=>t.tag==="manifest")?.attributes;
    a.metadata.sdk=tags.find(t=>t.tag==="uses-sdk")?.attributes;
    a.metadata.application=tags.find(t=>t.tag==="application")?.attributes;
    a.metadata.permissions=tags.filter(t=>t.tag.startsWith("uses-permission")).map(t=>t.attributes.name).filter(Boolean);
    a.metadata.exportedComponents=tags.filter(t=>t.attributes.exported==="true").map(t=>({tag:t.tag,...t.attributes})).slice(0,50);
  } catch {a.incomplete=true; a.limitations.push("Manifest APK tidak berhasil dibaca sepenuhnya.");}
  const m=manifestModel(tags), count=(re:RegExp)=>m.components.filter(c=>re.test(c.tag)).length;
  if(m.parsed)a.metadata.components={activities:count(/^activity/),services:count(/^service$/),receivers:count(/^receiver$/),providers:count(/^provider$/),launcher:hasLauncher(m)};
  const sig=new Signals(), budget={deadline:Date.now()+DEX_BUDGET_MS,bytes:DEX_TOTAL}, stats:Record<string,unknown>[]=[], skipped:string[]=[], started=Date.now();
  const scan=(name:string,data:Buffer)=>{const d=parseDex(data,budget.deadline);sig.refs(d.methods);sig.refs(d.fields);sig.classes(d.classes);sig.strings(d.strings);stats.push({name:name.slice(0,120),size:data.length,version:d.version,strings:d.strings.length,methods:d.methods.length,classes:d.classes.length});};
  const dex=entries.filter(e=>/^classes\d*\.dex$/.test(e.name)).sort((x,y)=>(parseInt(x.name.slice(7))||1)-(parseInt(y.name.slice(7))||1));
  for(const e of dex) {
    if(Date.now()>budget.deadline || e.size>budget.bytes){skipped.push(e.name);continue;}
    let data:Buffer|undefined;
    try {data=unzipEntry(buffer,e,DEX_MAX);budget.bytes-=data.length;scan(e.name,data);}
    catch(error){
      if(Date.now()>budget.deadline){skipped.push(e.name);continue;}
      console.error(`Kheronyx DEX ${e.name} failed:`,error instanceof Error?error.message:error);
      a.incomplete=true;a.limitations.push(`Kode ${e.name} tidak berhasil dibedah dalam batas sumber daya.`);if(data)a.strings.push(...printableStrings(data,120));
    }
  }
  const extra:Behavior[]=[];
  const payloads=findPayloads(buffer,entries,budget,scan);
  if(payloads.length) {
    a.metadata.hiddenPayloads=payloads.slice(0,20);
    const code=payloads.filter(x=>/DEX|Arsip kode/.test(x.kind)), blobs=payloads.filter(x=>/Blob/.test(x.kind));
    extra.push({id:"hidden_payload",name:"Payload kode tersembunyi (packing/dropper)",severity:code.length?"high":blobs.length?"medium":"low",evidence:payloads.slice(0,6).map(x=>`${x.name} — ${x.kind}${x.entropy?`, entropi ${x.entropy}`:""}${x.dex?`, ${x.dex} DEX dibedah`:""}`)});
  }
  const packers=[...entries.filter(e=>PACKER_FILES.test(e.name)).map(e=>e.name),...PACKER_APPS.test(m.application)?[`application ${m.application}`]:[]];
  if(packers.length)extra.push({id:"packer",name:"Proteksi/packer aplikasi terdeteksi",severity:"medium",evidence:packers.slice(0,6)});
  const arsc=entries.find(e=>e.name==="resources.arsc");
  if(arsc && Date.now()<budget.deadline)try {sig.strings(resourceStrings(unzipEntry(buffer,arsc,48*MB)),"res: ");}catch{a.limitations.push("String resource (resources.arsc) tidak berhasil dibaca.");}
  let certSha256:string|undefined;
  try {
    const signing=apkSigning(buffer,entries);certSha256=signing.certificates[0]?.sha256;
    a.metadata.signing={schemes:signing.schemes,certificates:signing.certificates.map(({subject,issuer,sha256,validFrom,validTo,key})=>({subject,issuer,sha256,validFrom,validTo,key}))};
    a.indicators.push(...signingIndicators(signing));
    if(signing.errors.length)a.limitations.push("Sebagian data sertifikat penanda tangan APK tidak dapat dibaca.");
  } catch {a.limitations.push("Sertifikat penanda tangan APK tidak berhasil dibaca.");}
  const behaviors=evaluate(sig,m,extra,{certSha256});
  a.metadata.behaviors=behaviorMetadata(behaviors); a.indicators.unshift(...behaviors.map(behaviorIndicator));
  const urls=sig.rankedUrls(), hosts=[...new Set(urls.slice(0,200).filter(u=>/telegram|discord|slack|ngrok|trycloudflare|webhook|pipedream|000webhost|:\/\/(?:\d{1,3}\.){3}\d{1,3}|\.php\b|firebaseio|firebasedatabase/i.test(u)).map(u=>u.split("/")[2]))].slice(0,8);
  const campaign={certSha256:certSha256?[certSha256]:[],telegramBots:[...sig.bots],chatIds:[...sig.chats],hosts};
  if(Object.values(campaign).some(v=>v.length))a.metadata.campaign=campaign;
  a.metadata.dexFiles=[...stats,...skipped.map(name=>({name,skipped:true}))].slice(0,40);
  a.metadata.dexScan={parsed:stats.length,skipped:skipped.length,inflatedMB:Math.round((DEX_TOTAL-budget.bytes)/MB),ms:Date.now()-started};
  a.strings=[...sig.samples(),...a.strings]; a.urls.push(...urls.slice(0,60));
  if(skipped.length)a.limitations.push(`${skipped.length} file DEX tidak dibedah karena batas waktu/ukuran analisis; perilaku di dalamnya bisa terlewat.`);
  a.limitations.push("APK tidak dijalankan. Bytecode tidak didekompilasi (hanya tabel string, metode, dan kelas DEX yang dibaca), library native tidak dianalisis, dan tanda tangan APK hanya dibaca sertifikatnya tanpa verifikasi kriptografis; izin luas bukan bukti malware.");
}
const PDF_TOKENS:[string,string][]=[["JavaScript|JS","JavaScript tertanam"],["OpenAction","Tindakan saat dibuka"],["AA","Tindakan otomatis (/AA)"],["Launch","Tindakan launch (membuka program/file)"],["EmbeddedFiles?","File tertanam"],["SubmitForm","Formulir mengirim data (/SubmitForm)"],["ImportData","Impor data eksternal (/ImportData)"],["RichMedia","Konten RichMedia/Flash"],["XFA","Formulir XFA"]];
// Raw token scan over the file plus bounded inflation of compressed object streams (/ObjStm), where droppers often hide actions.
function pdfTokens(buffer:Buffer,raw:string,a:Artifact) {
  const objectAt=(text:string,i:number)=>{const m=[...text.slice(Math.max(0,i-3000),i).matchAll(/(\d+)\s+(\d+)\s+obj\b/g)].pop();return m?`obj ${m[1]} ${m[2]}`:"obj ?";};
  const segments:{text:string;where:(i:number)=>string}[]=[{text:raw,where:i=>objectAt(raw,i)}]; let decoded=0;
  for(const m of raw.matchAll(/\/Type\s*\/ObjStm\b/g)) {
    if(segments.length>200 || decoded>32*MB)break;
    const at=m.index, s=raw.indexOf("stream",at); if(s<0 || s-at>4000 || !/\/FlateDecode/.test(raw.slice(Math.max(raw.lastIndexOf(" obj",at),at-2000),s)))continue;
    let start=s+6; if(raw[start]==="\r")start++; if(raw[start]==="\n")start++;
    const end=raw.indexOf("endstream",start); if(end<0 || end-start>16*MB)continue;
    try {const text=inflateSync(buffer.subarray(start,end),{finishFlush:constants.Z_SYNC_FLUSH,maxOutputLength:4*MB}).toString("latin1"),label=objectAt(raw,at);decoded+=text.length;segments.push({text,where:()=>`di dalam ObjStm ${label}`});}catch{}
  }
  if(segments.length>1)a.metadata.objectStreams=segments.length-1;
  const snippet=(text:string,i:number)=>text.slice(Math.max(0,i-40),i+140).replace(/[^\x20-\x7e]+/g," ").replace(/\s+/g," ").trim();
  for(const [token,name] of PDF_TOKENS) {
    const re=new RegExp(`\\/(?:${token})(?![\\w#])`,"g"); let count=0; const context:string[]=[];
    for(const seg of segments)for(const m of seg.text.matchAll(re)){if(count++<3)context.push(`${seg.where(m.index)}: ${snippet(seg.text,m.index)}`);if(count>100000)break;}
    if(count)a.indicators.push({name,evidence:`${count} kemunculan /${token.replace(/s\?$/,"")}; konteks: ${context.join(" | ")}`.slice(0,900)});
    if(name==="Tindakan saat dibuka" && context.some(c=>/\/(?:JS|JavaScript)\b/.test(c)))a.indicators.push({name:"JavaScript dijalankan saat dokumen dibuka",evidence:context.filter(c=>/\/(?:JS|JavaScript)\b/.test(c)).join(" | ").slice(0,600)});
  }
}
async function pdf(buffer:Buffer,a:Artifact) {
  pdfTokens(buffer,buffer.toString("latin1"),a);
  const {getDocument}=await import("pdfjs-dist/legacy/build/pdf.mjs");
  const task=getDocument({data:new Uint8Array(buffer),isEvalSupported:false,useSystemFonts:false,disableFontFace:true,useWorkerFetch:false,verbosity:0});
  try {
    const doc=await task.promise; a.metadata.pages=doc.numPages;
    const metadata=await doc.getMetadata();a.metadata.info=metadata.info;
    const text:string[]=[], scripts:string[]=[], local:string[]=[];
    const actions=await doc.getJSActions();if(actions)scripts.push(JSON.stringify(actions));
    for(let i=1;i<=Math.min(doc.numPages,30);i++) {
      const page=await doc.getPage(i);
      if(i<=10){const content=await page.getTextContent();text.push(content.items.map(i=>"str" in i?i.str:"").join(" ").slice(0,2500));}
      for(const n of (await page.getAnnotations()).slice(0,100)) {
        if(n.url)a.urls.push(String(n.url).slice(0,1000));else if(n.unsafeUrl){const u=String(n.unsafeUrl).slice(0,300);if(/^(?:file:|smb:|\\\\)/i.test(u))local.push(u);else if(/^https?:/i.test(u))a.urls.push(u);}
        if(n.actions)scripts.push(JSON.stringify({page:i,annotation:n.subtype,actions:n.actions}));
      }
      const pageActions=await page.getJSActions();if(pageActions && Object.keys(pageActions).length)scripts.push(JSON.stringify({page:i,actions:pageActions}));
      page.cleanup();
    }
    a.metadata.textExcerpt=text.join("\n").slice(0,18000);
    if(scripts.length)a.metadata.javascript=scripts.join("\n").slice(0,20000);
    if(local.length)a.indicators.push({name:"Tautan ke file lokal/jaringan",evidence:`Tautan non-HTTP dapat membocorkan kredensial jaringan atau membuka file: ${[...new Set(local)].slice(0,5).join(", ")}`});
    const attachments=await doc.getAttachments();if(attachments)a.metadata.attachments=Object.values(attachments).slice(0,30).map(value=>{const x=value as {filename:string;content:Uint8Array};return {filename:x.filename,size:x.content.length};});
    if(doc.numPages>10)a.limitations.push(`Teks hanya diekstrak dari 10 halaman pertama; tautan, anotasi, dan skrip halaman dari ${Math.min(doc.numPages,30)} halaman pertama.`);
    stringSignals(a,[...text,...scripts,...a.urls],[],false);
    a.limitations.push("PDF tidak dibuka secara interaktif; lampiran tidak dipindai secara terpisah dan eksploit reader tidak dapat dipastikan.");
  } finally {await task.destroy();}
}
export async function extractFile(buffer:Buffer,filename:string):Promise<Artifact> {
  const kind=fileKind(filename); if(!buffer.length || buffer.length>KIND_LIMITS[kind])throw new Error(`Ukuran file ${kind.toUpperCase()} harus antara 1 byte dan ${formatMB(KIND_LIMITS[kind])}.`);
  validateSignature(buffer,kind);
  const a:Artifact={filename:filename.replace(/[\x00-\x1f\x7f]/g,"").slice(0,180),kind,size:buffer.length,sha256:createHash("sha256").update(buffer).digest("hex"),metadata:{},strings:printableStrings(buffer),urls:[],indicators:[],limitations:[],incomplete:false};
  try {if(kind==="pdf")await pdf(buffer,a);else if(kind==="exe")pe(buffer,a);else if(kind==="apk")apk(buffer,a);else if(kind==="png")png(buffer,a);else jpg(buffer,a);}catch(error){console.error(`Kheronyx ${kind} extraction failed:`,error instanceof Error?error.message:error);a.incomplete=true;a.limitations.push("Struktur internal tidak berhasil dibaca sepenuhnya; hasil tidak boleh dianggap aman.");}
  // Telegram bot tokens and webhook secrets are redacted everywhere (strings, URLs, metadata, indicators).
  a.strings=[...new Set(a.strings.map(redactSecrets))].slice(0,500);
  a.urls=[...new Set([...a.urls,...a.strings.flatMap(s=>s.match(/https?:\/\/[^\s<>"'\\]{4,300}/g)||[])].map(redactSecrets))].slice(0,60);
  a.indicators=a.indicators.map(i=>({name:i.name,evidence:redactSecrets(i.evidence)}));
  a.limitations.push("Ini analisis statis berbantuan AI, tanpa antivirus, sandbox eksekusi, atau pencarian reputasi eksternal. Malware baru dan payload tersembunyi dapat terlewat.");
  let sampled=false;
  function bounded(value:unknown,depth=0):unknown {
    if(depth>7){sampled=true;return "[Depth limit]";}
    if(typeof value==="string"){if(value.length>20000)sampled=true;return redactSecrets(value.slice(0,20000));}
    if(Array.isArray(value)){if(value.length>100)sampled=true;return value.slice(0,100).map(v=>bounded(v,depth+1));}
    if(value && typeof value==="object"){const entries=Object.entries(value);if(entries.length>100)sampled=true;return Object.fromEntries(entries.slice(0,100).map(([k,v])=>[k,bounded(v,depth+1)]));}
    return value;
  }
  a.metadata=bounded(a.metadata) as Record<string,unknown>;
  // Keep the AI evidence (see assess(): 120k chars incl. VirusTotal) comfortably bounded even for samples that trip every rule.
  const evidenceSize=()=>JSON.stringify({...a,strings:a.strings.slice(0,180),urls:a.urls.slice(0,40)}).length;
  if(evidenceSize()>100000){
    sampled=true; a.strings=a.strings.map(s=>s.slice(0,120)); a.indicators=a.indicators.slice(0,40).map(i=>({name:i.name,evidence:i.evidence.slice(0,300)}));
    for(const [key,value] of Object.entries(a.metadata))if(Array.isArray(value))a.metadata[key]=key==="behaviors"?value.map(b=>({...b,evidence:b.evidence.slice(0,2)})):value.slice(0,15);
  }
  if(evidenceSize()>100000)for(const key of Object.keys(a.metadata))if(JSON.stringify(a.metadata[key]).length>8000)a.metadata[key]="[Dipangkas: terlalu besar untuk bukti AI]";
  if(sampled)a.limitations.push("Metadata yang besar dibatasi menjadi cuplikan; seluruh konten belum diperiksa.");
  a.limitations.push("String dan URL yang diberikan kepada AI berupa sampel terbatas.");
  return a;
}
