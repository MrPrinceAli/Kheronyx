import { randomUUID } from "node:crypto";
import { NextResponse } from "next/server";
import { sameOrigin, sessionId } from "@/lib/auth";
import { aiConfigured, assess } from "@/lib/ai";
import { bucketName, db, rateLimit, saveReport } from "@/lib/db";
import { extractFile, fileKind } from "@/lib/extract";
import { blobConfigured, quarantinePath, readBlob, removeBlob } from "@/lib/blob";
import { KIND_LIMITS, sizeLimits } from "@/lib/limits";
import { inspectVirusTotal } from "@/lib/virustotal";
import type { Report } from "@/lib/types";
export const runtime="nodejs";
export const maxDuration=300;
export async function POST(request:Request) {
  const session=await sessionId();if(!session)return NextResponse.json({error:"Login diperlukan."},{status:401});
  if(!sameOrigin(request))return NextResponse.json({error:"Permintaan ditolak."},{status:403});
  if(!aiConfigured())return NextResponse.json({error:"AI belum terhubung. Isi AI_API_KEY di .env atau Environment Variables Vercel."},{status:503});
  let path:string|undefined;const start=Date.now();
  try {
    if(!await rateLimit(`analyze:${session}`,20,3600))return NextResponse.json({error:"Batas 20 analisis per jam tercapai. Coba lagi nanti."},{status:429});
    let buffer:Buffer,filename:string,uploadVirusTotal=false;
    if(request.headers.get("content-type")?.includes("application/json")) {
      const body=await request.json();path=body.path;filename=body.filename;uploadVirusTotal=body.uploadVirusTotal===true;
      if(typeof filename!=="string" || filename.length>200 || !quarantinePath(session,path)){path=undefined;throw new Error("Referensi upload tidak valid.");}
      const kind=fileKind(filename);if(!path.endsWith(`.${kind}`))throw new Error("Referensi upload tidak valid.");
      if(blobConfigured())buffer=await readBlob(path,KIND_LIMITS[kind]);
      else {
        const supabase=db();if(!supabase)throw new Error("Storage belum terhubung.");
        const {data:info,error:infoError}=await supabase.storage.from(bucketName()).info(path);
        if(infoError || !info)throw new Error("File tidak ditemukan. Upload ulang.");
        if(Number(info.size || info.metadata?.size || 0)>sizeLimits("supabase")[kind])throw new Error("File melebihi batas storage.");
        const {data,error}=await supabase.storage.from(bucketName()).download(path);
        if(error || !data)throw new Error("File belum dapat diambil. Upload ulang.");buffer=Buffer.from(await data.arrayBuffer());
      }
    }else {
      if(Number(request.headers.get("content-length")||0)>4*1024*1024+10000)throw new Error("Tanpa storage, batas upload langsung adalah 4 MB.");
      const body=await request.formData();const file=body.get("file");uploadVirusTotal=body.get("uploadVirusTotal")==="true";
      if(!(file instanceof File) || file.size>4*1024*1024)throw new Error("Pilih file maksimal 4 MB atau hubungkan Supabase untuk file besar.");filename=file.name;buffer=Buffer.from(await file.arrayBuffer());
    }
    const artifact=await extractFile(buffer,filename);
    artifact.virusTotal=await inspectVirusTotal(artifact,buffer,uploadVirusTotal);
    const {assessment,model}=await assess(artifact);
    const report:Report={id:randomUUID(),createdAt:new Date().toISOString(),filename:artifact.filename,kind:artifact.kind,size:artifact.size,sha256:artifact.sha256,model,durationMs:Date.now()-start,assessment,artifact};
    let persisted=false,warning:string|undefined;
    try{persisted=await saveReport(report);}catch(error){warning=error instanceof Error?error.message:"Laporan gagal disimpan.";}
    return NextResponse.json({report,persisted,warning},{headers:{"Cache-Control":"no-store"}});
  }catch(error){return NextResponse.json({error:error instanceof Error?error.message:"Analisis gagal. Tidak ada kesimpulan keamanan yang dibuat."},{status:400});}
  finally{
    if(path && blobConfigured())await removeBlob(path).catch(()=>console.error("Kheronyx quarantine cleanup failed; scheduled retention cleanup will retry."));
    else if(path && db()){const {error}=await db()!.storage.from(bucketName()).remove([path]);if(error)console.error("Kheronyx quarantine cleanup failed; scheduled retention cleanup will retry.");}
  }
}
