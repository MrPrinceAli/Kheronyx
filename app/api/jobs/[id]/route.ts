import { NextResponse } from "next/server";
import { sameOrigin, sessionId } from "@/lib/auth";
import { deleteJob, kick, retryJob } from "@/lib/jobs";
export const runtime="nodejs";
export const maxDuration=300;
type Context={params:Promise<{id:string}>};
const valid=(id:string)=>/^[0-9a-f-]{36}$/.test(id);
async function guard(request:Request) {
  if(!await sessionId())return NextResponse.json({error:"Login diperlukan."},{status:401});
  if(!sameOrigin(request))return NextResponse.json({error:"Permintaan ditolak."},{status:403});
  return null;
}
// Manual retry of a failed job: resets its attempts and starts it right away.
export async function POST(request:Request,{params}:Context) {
  const denied=await guard(request);if(denied)return denied;
  const {id}=await params;if(!valid(id))return NextResponse.json({error:"Analisis tidak valid."},{status:400});
  if(!await retryJob(id))return NextResponse.json({error:"Analisis ini tidak dapat diulang."},{status:409});
  kick(id);
  return NextResponse.json({ok:true},{status:202});
}
export async function DELETE(request:Request,{params}:Context) {
  const denied=await guard(request);if(denied)return denied;
  const {id}=await params;if(!valid(id))return NextResponse.json({error:"Analisis tidak valid."},{status:400});
  try{await deleteJob(id);return NextResponse.json({ok:true});}catch(error){return NextResponse.json({error:error instanceof Error?error.message:"Analisis gagal dihapus."},{status:409});}
}
