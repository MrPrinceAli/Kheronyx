import { NextResponse } from "next/server";
import { sessionId } from "@/lib/auth";
import { listReports } from "@/lib/db";
export const dynamic="force-dynamic";
export async function GET() {
  if(!await sessionId())return NextResponse.json({error:"Login diperlukan."},{status:401});
  try{return NextResponse.json({reports:await listReports()},{headers:{"Cache-Control":"no-store"}});}catch(error){return NextResponse.json({error:error instanceof Error?error.message:"Riwayat gagal dimuat."},{status:503});}
}
