import { randomUUID } from "node:crypto";
import { NextResponse } from "next/server";
import { sameOrigin, sessionId } from "@/lib/auth";
import { bucketName, db, rateLimit } from "@/lib/db";
import { fileKind } from "@/lib/extract";
import { aiConfigured } from "@/lib/ai";
import { blobConfigured, quarantinePath, removeBlob, uploadMode } from "@/lib/blob";
import { formatMB, LARGE_FILE_BYTES, sizeLimits } from "@/lib/limits";
export async function POST(request:Request) {
  const session=await sessionId();if(!session)return NextResponse.json({error:"Login diperlukan."},{status:401});
  if(!sameOrigin(request))return NextResponse.json({error:"Permintaan ditolak."},{status:403});
  if(!aiConfigured())return NextResponse.json({error:"AI belum terhubung. Isi API key terlebih dahulu."},{status:503});
  const mode=uploadMode();if(mode==="direct")return NextResponse.json({error:"Storage belum terhubung."},{status:503});
  try {
    const body=await request.json();if(typeof body.filename!=="string" || typeof body.size!=="number")throw new Error("Informasi file tidak valid.");
    const kind=fileKind(body.filename),limit=sizeLimits(mode)[kind];if(body.size<1 || body.size>limit)throw new Error(`Batas file ${kind.toUpperCase()} adalah ${formatMB(limit)}.`);
    if(!await rateLimit(`upload:${session}`,12,600))return NextResponse.json({error:"Terlalu banyak upload. Coba lagi nanti."},{status:429});
    // Each large file is downloaded once by the analyzer; 30 per month keeps the Hobby Blob transfer allowance (10 GB) safe.
    if(mode==="blob" && body.size>LARGE_FILE_BYTES && !await rateLimit("blob:large-files",30,30*24*3600))return NextResponse.json({error:"Kuota file besar (di atas 50 MB) bulan ini sudah habis. Gunakan file yang lebih kecil."},{status:429});
    const path=`${session}/${randomUUID()}.${kind}`;
    if(mode==="blob")return NextResponse.json({path,mode});
    const {data,error}=await db()!.storage.from(bucketName()).createSignedUploadUrl(path);
    if(error || !data)throw new Error("Upload belum dapat disiapkan. Periksa konfigurasi storage.");
    return NextResponse.json({path,mode,token:data.token,signedUrl:data.signedUrl});
  } catch(error){return NextResponse.json({error:error instanceof Error?error.message:"Upload gagal."},{status:400});}
}
export async function DELETE(request:Request) {
  const session=await sessionId();if(!session)return NextResponse.json({error:"Login diperlukan."},{status:401});
  if(!sameOrigin(request))return NextResponse.json({error:"Permintaan ditolak."},{status:403});
  try {const {path}=await request.json();if(!quarantinePath(session,path))throw new Error();if(blobConfigured())await removeBlob(path);else{const {error}=await db()!.storage.from(bucketName()).remove([path]);if(error)throw new Error();}return NextResponse.json({ok:true});}catch{return NextResponse.json({error:"File belum dapat dihapus."},{status:400});}
}
