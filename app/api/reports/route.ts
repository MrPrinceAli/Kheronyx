import { NextResponse } from "next/server";
import { z } from "zod";
import { sessionId } from "@/lib/auth";
import { deleteReport, listReports, readReport } from "@/lib/db";
import { kickSandbox, sandboxDue } from "@/lib/sandbox";
export const dynamic="force-dynamic";
// after() may run a due sandbox check (incl. AI re-assessment) once the response is sent.
export const maxDuration=300;
export async function GET(request:Request) {
  if(!await sessionId())return NextResponse.json({error:"Login diperlukan."},{status:401});
  // ?id= returns one report (dashboard polling while its Tria.ge sandbox is pending) and resumes due sandbox checks.
  const id=new URL(request.url).searchParams.get("id");
  if(id!==null){
    if(!z.string().uuid().safeParse(id).success)return NextResponse.json({error:"Laporan tidak valid."},{status:400});
    try{if(await sandboxDue().catch(()=>false))kickSandbox();const report=await readReport(id);return report?NextResponse.json({report},{headers:{"Cache-Control":"no-store"}}):NextResponse.json({error:"Laporan tidak ditemukan."},{status:404});}catch(error){return NextResponse.json({error:error instanceof Error?error.message:"Laporan gagal dimuat."},{status:503});}
  }
  try{return NextResponse.json({reports:await listReports()},{headers:{"Cache-Control":"no-store"}});}catch(error){return NextResponse.json({error:error instanceof Error?error.message:"Riwayat gagal dimuat."},{status:503});}
}
const removal=z.object({id:z.string().uuid()});
export async function DELETE(request:Request) {
  if(!await sessionId())return NextResponse.json({error:"Login diperlukan."},{status:401});
  const parsed=removal.safeParse(await request.json().catch(()=>null));
  if(!parsed.success)return NextResponse.json({error:"Laporan tidak valid."},{status:400});
  try{await deleteReport(parsed.data.id);return NextResponse.json({ok:true});}catch(error){return NextResponse.json({error:error instanceof Error?error.message:"Riwayat gagal dihapus."},{status:503});}
}
