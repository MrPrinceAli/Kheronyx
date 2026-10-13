import { NextResponse } from "next/server";
import { sessionId } from "@/lib/auth";
import { aiConfigured, modelConfig } from "@/lib/ai";
import { storageConfigured } from "@/lib/db";
import { virusTotalConfigured } from "@/lib/virustotal";
import { uploadMode } from "@/lib/blob";
import { jobsConfigured } from "@/lib/jobs";
import { sizeLimits } from "@/lib/limits";
export const dynamic="force-dynamic";
export async function GET() {
  if(!await sessionId())return NextResponse.json({error:"Login diperlukan."},{status:401});
  return NextResponse.json({aiReady:aiConfigured(),storageReady:storageConfigured(),virusTotalReady:virusTotalConfigured(),jobs:jobsConfigured(),upload:uploadMode(),limits:sizeLimits(uploadMode()),...modelConfig()},{headers:{"Cache-Control":"no-store"}});
}
