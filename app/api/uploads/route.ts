import { randomUUID } from "node:crypto";
import { NextResponse } from "next/server";
import { sameOrigin, sessionId } from "@/lib/auth";
import { bucketName, db, rateLimit } from "@/lib/db";
import { fileKind, MAX_BYTES } from "@/lib/extract";
import { aiConfigured } from "@/lib/ai";
export async function POST(request:Request) {
  const session=await sessionId();if(!session)return NextResponse.json({error:"Login diperlukan."},{status:401});
  if(!sameOrigin(request))return NextResponse.json({error:"Permintaan ditolak."},{status:403});
  if(!aiConfigured())return NextResponse.json({error:"AI belum terhubung. Isi API key terlebih dahulu."},{status:503});
  const supabase=db();if(!supabase)return NextResponse.json({error:"Storage belum terhubung."},{status:503});
  try {
    const body=await request.json();if(typeof body.filename!=="string" || typeof body.size!=="number")throw new Error("Informasi file tidak valid.");
    const kind=fileKind(body.filename);if(body.size<1 || body.size>MAX_BYTES || kind==="pdf" && body.size>10*1024*1024)throw new Error("Batas file 40 MB; PDF maksimal 10 MB.");
    if(!await rateLimit(`upload:${session}`,12,600))return NextResponse.json({error:"Terlalu banyak upload. Coba lagi nanti."},{status:429});
    const path=`${session}/${randomUUID()}.${kind}`;
    const {data,error}=await supabase.storage.from(bucketName()).createSignedUploadUrl(path);
    if(error || !data)throw new Error("Upload belum dapat disiapkan. Periksa konfigurasi storage.");
    return NextResponse.json({path,token:data.token,signedUrl:data.signedUrl});
  } catch(error){return NextResponse.json({error:error instanceof Error?error.message:"Upload gagal."},{status:400});}
}
export async function DELETE(request:Request) {
  const session=await sessionId();if(!session)return NextResponse.json({error:"Login diperlukan."},{status:401});
  if(!sameOrigin(request))return NextResponse.json({error:"Permintaan ditolak."},{status:403});
  try {const {path}=await request.json();if(typeof path!=="string" || !new RegExp(`^${session}/[a-f0-9-]{36}\\.(pdf|apk|exe|png|jpg)$`).test(path))throw new Error();const {error}=await db()!.storage.from(bucketName()).remove([path]);if(error)throw new Error();return NextResponse.json({ok:true});}catch{return NextResponse.json({error:"File belum dapat dihapus."},{status:400});}
}
