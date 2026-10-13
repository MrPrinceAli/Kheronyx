import { NextResponse } from "next/server";
import { sessionId } from "@/lib/auth";
import { aiConfigured } from "@/lib/ai";
import { storageConfigured } from "@/lib/db";
export const dynamic="force-dynamic";
export async function GET() {
  if(!await sessionId())return NextResponse.json({error:"Login diperlukan."},{status:401});
  return NextResponse.json({aiReady:aiConfigured(),storageReady:storageConfigured(),maxBytes:(storageConfigured()?40:4)*1024*1024,model:process.env.AI_MODEL || "Auto"},{headers:{"Cache-Control":"no-store"}});
}
