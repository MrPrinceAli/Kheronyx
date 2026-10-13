import { NextResponse } from "next/server";
import { handleUpload, type HandleUploadBody } from "@vercel/blob/client";
import { sameOrigin, sessionId } from "@/lib/auth";
import { blobConfigured, quarantinePath } from "@/lib/blob";
import { fileKind } from "@/lib/extract";
import { KIND_LIMITS, formatMB } from "@/lib/limits";
import { aiConfigured } from "@/lib/ai";
// Issues short-lived client tokens so the browser uploads straight to the private Blob store
// (multipart, retried per part) without the file ever passing through this function. Upload quotas are
// charged earlier, when POST /api/uploads reserves the path.
export async function POST(request:Request) {
  const session=await sessionId();if(!session)return NextResponse.json({error:"Login diperlukan."},{status:401});
  if(!sameOrigin(request))return NextResponse.json({error:"Permintaan ditolak."},{status:403});
  if(!aiConfigured())return NextResponse.json({error:"AI belum terhubung. Isi API key terlebih dahulu."},{status:503});
  if(!blobConfigured())return NextResponse.json({error:"Blob storage belum terhubung."},{status:503});
  try {
    const body=await request.json() as HandleUploadBody;
    if(body.type!=="blob.generate-client-token")throw new Error("Permintaan upload tidak valid.");
    const result=await handleUpload({request,body,onBeforeGenerateToken:async(pathname,clientPayload)=>{
      if(!quarantinePath(session,pathname))throw new Error("Referensi upload tidak valid.");
      const kind=fileKind(pathname),size=Number(JSON.parse(clientPayload || "{}").size);
      if(!Number.isFinite(size) || size<1 || size>KIND_LIMITS[kind])throw new Error(`Batas file ${kind.toUpperCase()} adalah ${formatMB(KIND_LIMITS[kind])}.`);
      return {maximumSizeInBytes:KIND_LIMITS[kind],addRandomSuffix:false,allowOverwrite:false,validUntil:Date.now()+3600*1000};
    }});
    return NextResponse.json(result);
  } catch(error){return NextResponse.json({error:error instanceof Error?error.message:"Upload gagal."},{status:400});}
}
