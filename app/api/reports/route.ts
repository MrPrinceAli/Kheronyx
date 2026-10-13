import { NextResponse } from "next/server";
import { z } from "zod";
import { sessionId } from "@/lib/auth";
import { deleteReport, listReports } from "@/lib/db";
export const dynamic="force-dynamic";
export async function GET() {
  if(!await sessionId())return NextResponse.json({error:"Login diperlukan."},{status:401});
  try{return NextResponse.json({reports:await listReports()},{headers:{"Cache-Control":"no-store"}});}catch(error){return NextResponse.json({error:error instanceof Error?error.message:"Riwayat gagal dimuat."},{status:503});}
}
const removal=z.object({id:z.string().uuid()});
export async function DELETE(request:Request) {
  if(!await sessionId())return NextResponse.json({error:"Login diperlukan."},{status:401});
  const parsed=removal.safeParse(await request.json().catch(()=>null));
  if(!parsed.success)return NextResponse.json({error:"Laporan tidak valid."},{status:400});
  try{await deleteReport(parsed.data.id);return NextResponse.json({ok:true});}catch(error){return NextResponse.json({error:error instanceof Error?error.message:"Riwayat gagal dihapus."},{status:503});}
}
