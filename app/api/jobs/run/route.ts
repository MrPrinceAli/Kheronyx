import { createHash, timingSafeEqual } from "node:crypto";
import { NextResponse } from "next/server";
import { jobsConfigured, kick } from "@/lib/jobs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export const maxDuration=300;
// Resumes queued jobs. Called by the Supabase scheduler (JOBS_SECRET) and the daily Vercel cron (CRON_SECRET).
function authorized(request:Request) {
  const supplied=createHash("sha256").update(request.headers.get("authorization") || "").digest();
  return [process.env.JOBS_SECRET,process.env.CRON_SECRET].some(secret=>secret && timingSafeEqual(supplied,createHash("sha256").update(`Bearer ${secret}`).digest()));
}
async function run(request:Request) {
  if(!authorized(request))return NextResponse.json({error:"Unauthorized"},{status:401});
  if(!jobsConfigured())return NextResponse.json({skipped:true});
  kick();
  return NextResponse.json({ok:true},{status:202});
}
export const GET=run;
export const POST=run;
