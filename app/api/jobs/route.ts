import { NextResponse } from "next/server";
import { sameOrigin, sessionId } from "@/lib/auth";
import { aiConfigured } from "@/lib/ai";
import { rateLimit } from "@/lib/db";
import { blobSize, quarantinePath } from "@/lib/blob";
import { fileKind } from "@/lib/extract";
import { KIND_LIMITS } from "@/lib/limits";
import { createJob, jobsConfigured, kick, listJobs, runnable } from "@/lib/jobs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
// after() keeps running the analysis for up to this long once the response is sent.
export const maxDuration=300;
export async function POST(request:Request) {
  const session=await sessionId();if(!session)return NextResponse.json({error:"Login diperlukan."},{status:401});
  if(!sameOrigin(request))return NextResponse.json({error:"Permintaan ditolak."},{status:403});
  if(!aiConfigured())return NextResponse.json({error:"AI belum terhubung. Isi AI_API_KEY di .env atau Environment Variables Vercel."},{status:503});
  if(!jobsConfigured())return NextResponse.json({error:"Analisis latar belakang memerlukan Blob dan Supabase."},{status:503});
  try {
    if(!await rateLimit(`analyze:${session}`,20,3600))return NextResponse.json({error:"Batas 20 analisis per jam tercapai. Coba lagi nanti."},{status:429});
    const body=await request.json();const {path,filename}=body;
    if(typeof filename!=="string" || filename.length>200 || !quarantinePath(session,path))throw new Error("Referensi upload tidak valid.");
    const kind=fileKind(filename);if(!path.endsWith(`.${kind}`))throw new Error("Referensi upload tidak valid.");
    const size=await blobSize(path);if(!size)throw new Error("File belum terunggah. Upload ulang.");
    if(size>KIND_LIMITS[kind])throw new Error("File melebihi batas untuk format ini.");
    const job=await createJob({path,filename,kind,size,uploadVirusTotal:body.uploadVirusTotal===true});
    kick(job.id);
    return NextResponse.json({job},{status:202});
  } catch(error){return NextResponse.json({error:error instanceof Error?error.message:"Analisis gagal dijadwalkan."},{status:400});}
}
export async function GET() {
  if(!await sessionId())return NextResponse.json({error:"Login diperlukan."},{status:401});
  if(!jobsConfigured())return NextResponse.json({jobs:[]});
  try {
    const jobs=await listJobs();
    // Opening the dashboard also resumes work whose retry time has come, even without the scheduler.
    if(jobs.some(runnable))kick();
    return NextResponse.json({jobs},{headers:{"Cache-Control":"no-store"}});
  } catch(error){return NextResponse.json({error:error instanceof Error?error.message:"Status analisis gagal dimuat."},{status:503});}
}
