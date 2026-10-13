import { NextResponse } from "next/server";
import { authConfigured, COOKIE, cookieOptions, createSession, sameOrigin, verifyPassword } from "@/lib/auth";
import { clearRateLimit, rateLimit, rateLimited } from "@/lib/db";
export async function POST(request:Request) {
  if(!sameOrigin(request))return NextResponse.json({error:"Permintaan ditolak."},{status:403});
  if(!authConfigured())return NextResponse.json({error:"Login belum dikonfigurasi di server."},{status:503});
  if(Number(request.headers.get("content-length")||0)>2048)return NextResponse.json({error:"Permintaan terlalu besar."},{status:413});
  try {
    const ip=request.headers.get("x-vercel-forwarded-for") || request.headers.get("x-forwarded-for")?.split(",")[0] || "local";
    // Only wrong passwords count toward the lockout; a successful login clears it. Once locked, every attempt
    // (right or wrong) is refused, so the response never confirms a guess during the lockout.
    const key=`login:${ip}`;
    if(await rateLimited(key,8))return NextResponse.json({error:"Terlalu banyak password salah. Tunggu 15 menit."},{status:429});
    const body=await request.json();
    if(typeof body.password!=="string" || !verifyPassword(body.password)){await rateLimit(key,8,900);return NextResponse.json({error:"Password tidak cocok. Coba lagi."},{status:401});}
    await clearRateLimit(key).catch(()=>{});
    const response=NextResponse.json({ok:true});response.cookies.set(COOKIE,createSession(),cookieOptions);return response;
  } catch {return NextResponse.json({error:"Login belum dapat diproses. Coba lagi nanti."},{status:503});}
}
