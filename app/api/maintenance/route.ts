import { createHash, timingSafeEqual } from "node:crypto";
import { NextResponse } from "next/server";
import { bucketName, db } from "@/lib/db";
import { blobConfigured, cleanupBlobs } from "@/lib/blob";
export const maxDuration=60;
export async function GET(request:Request) {
  const secret=process.env.CRON_SECRET;
  const supplied=createHash("sha256").update(request.headers.get("authorization") || "").digest();
  const expected=createHash("sha256").update(`Bearer ${secret || ""}`).digest();
  if(!secret || !timingSafeEqual(supplied,expected))return NextResponse.json({error:"Unauthorized"},{status:401});
  const cutoff=Date.now()-24*3600*1000;let deleted=0;
  if(blobConfigured()){try{deleted+=await cleanupBlobs(cutoff);}catch{return NextResponse.json({error:"Blob cleanup failed"},{status:500});}}
  const supabase=db();if(!supabase)return NextResponse.json({deleted});
  // Bounded scheduled cleanup catches abandoned signed uploads. Successful scans delete immediately.
  const {data:folders,error}=await supabase.storage.from(bucketName()).list("",{limit:500});
  if(error)return NextResponse.json({error:"Cleanup failed"},{status:500});
  for(const folder of folders || []) {
    if(folder.id || !/^[a-f0-9]{32}$/.test(folder.name))continue;
    const {data:files,error:listError}=await supabase.storage.from(bucketName()).list(folder.name,{limit:100});
    if(listError)continue;
    const paths=(files || []).filter(f=>f.id && new Date(f.created_at || "").getTime()<cutoff).map(f=>`${folder.name}/${f.name}`);
    if(paths.length){const {error:removeError}=await supabase.storage.from(bucketName()).remove(paths);if(!removeError)deleted+=paths.length;}
  }
  // Finished and failed jobs only matter for a few days; their reports live in kheronyx_reports.
  await supabase.from("kheronyx_jobs").delete().in("status",["done","failed"]).lt("updated_at",new Date(Date.now()-7*24*3600*1000).toISOString());
  const {error:reportError}=await supabase.from("kheronyx_reports").delete().lt("created_at",new Date(Date.now()-30*24*3600*1000).toISOString());
  return NextResponse.json({deleted,reportRetentionOk:!reportError});
}
