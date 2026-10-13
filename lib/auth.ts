import { createHmac, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";
export const COOKIE = "kheronyx_session";
const TTL = 60 * 60 * 12;
export function authConfigured() { return Boolean(process.env.SESSION_SECRET && (process.env.ACCESS_PASSWORD || process.env.ACCESS_PASSWORD_HASH)); }
function signature(value: string) { return createHmac("sha256", process.env.SESSION_SECRET || "").update(value).digest("base64url"); }
export function verifyPassword(value: string) {
  if (!value || value.length > 256 || !authConfigured()) return false;
  if (process.env.ACCESS_PASSWORD_HASH) {
    const [salt, hash] = process.env.ACCESS_PASSWORD_HASH.split(":");
    if (!salt || !hash) return false;
    const actual = scryptSync(value, salt, 64); const expected = Buffer.from(hash, "hex");
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  }
  const actual = createHmac("sha256", process.env.SESSION_SECRET!).update(value).digest();
  const expected = createHmac("sha256", process.env.SESSION_SECRET!).update(process.env.ACCESS_PASSWORD!).digest();
  return timingSafeEqual(actual, expected);
}
export function createSession(now = Date.now()) {
  if (!authConfigured()) throw new Error("Login belum dikonfigurasi.");
  const payload = Buffer.from(JSON.stringify({ id: randomBytes(16).toString("hex"), exp: now + TTL * 1000 })).toString("base64url");
  return `${payload}.${signature(payload)}`;
}
export function validateSession(token?: string, now = Date.now()): string | null {
  if (!token || token.length > 1000 || !authConfigured()) return null;
  const parts = token.split("."); if (parts.length !== 2) return null;
  const actual = Buffer.from(parts[1]); const expected = Buffer.from(signature(parts[0]));
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
  try { const p = JSON.parse(Buffer.from(parts[0], "base64url").toString()); return typeof p.id === "string" && /^[a-f0-9]{32}$/.test(p.id) && typeof p.exp === "number" && p.exp > now && p.exp <= now + TTL * 1000 + 1000 ? p.id : null; } catch { return null; }
}
export async function sessionId() { return validateSession((await cookies()).get(COOKIE)?.value); }
export const cookieOptions = {httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict" as const, path: "/", maxAge: TTL};
export function sameOrigin(request: Request) {
  const origin = request.headers.get("origin"); if (!origin) return true;
  try { return new URL(origin).host === (request.headers.get("host") || new URL(request.url).host); } catch { return false; }
}
