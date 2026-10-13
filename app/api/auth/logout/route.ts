import { NextResponse } from "next/server";
import { COOKIE, cookieOptions, sameOrigin } from "@/lib/auth";
export async function POST(request:Request) {
  if(!sameOrigin(request))return NextResponse.json({error:"Permintaan ditolak."},{status:403});
  const response=NextResponse.json({ok:true});response.cookies.set(COOKIE,"",{...cookieOptions,maxAge:0});return response;
}
