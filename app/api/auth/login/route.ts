import { NextResponse } from "next/server";
import { authConfigured, COOKIE, cookieOptions, createSession, sameOrigin, verifyPassword } from "@/lib/auth";
import { rateLimit } from "@/lib/db";
export async function POST(request:Request) {
  if(!sameOrigin(request))return NextResponse.json({error:"Permintaan ditolak."},{status:403});
  if(!authConfigured())return NextResponse.json({error:"Login belum dikonfigurasi di server."},{status:503});
  if(Number(request.headers.get("content-length")||0)>2048)return NextResponse.json({error:"Permintaan terlalu besar."},{status:413});
  try {
    const ip=request.headers.get("x-vercel-forwarded-for") || request.headers.get("x-forwarded-for")?.split(",")[0] || "local";
    if(!await rateLimit(`login:${ip}`,8,900))return NextResponse.json({error:"Terlalu banyak percobaan. Tunggu 15 menit."},{status:429});
    const body=await request.json(); if(typeof body.password!=="string" || !verifyPassword(body.password))return NextResponse.json({error:"Password tidak cocok. Coba lagi."},{status:401});
    const response=NextResponse.json({ok:true});response.cookies.set(COOKIE,createSession(),cookieOptions);return response;
  } catch {return NextResponse.json({error:"Login belum dapat diproses. Coba lagi nanti."},{status:503});}
}
