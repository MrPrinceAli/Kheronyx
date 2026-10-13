import { createClient, type SupabaseClient, type WebSocketLikeConstructor } from "@supabase/supabase-js";
import { createHash } from "node:crypto";
import WebSocket from "ws";
import type { Report } from "./types";
let client: SupabaseClient | undefined;
export const bucketName = () => process.env.SUPABASE_BUCKET || "kheronyx-quarantine";
export function storageConfigured() { return Boolean(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY); }
export function db() {
  if (!storageConfigured()) return null;
  client ||= createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, {auth: {persistSession: false, autoRefreshToken: false}, realtime: {transport: WebSocket as unknown as WebSocketLikeConstructor}});
  return client;
}
const counters = new Map<string, {count: number; reset: number}>();
export async function rateLimit(key: string, limit: number, seconds: number) {
  const hashed = createHash("sha256").update(key).digest("hex");
  const supabase = db();
  if (supabase) {
    const {data, error} = await supabase.rpc("kheronyx_rate_limit", {p_key: hashed, p_limit: limit, p_window_seconds: seconds});
    if (error) throw new Error("Layanan pembatasan permintaan belum siap. Coba lagi nanti.");
    return data === true;
  }
  const now = Date.now();
  for (const [k,v] of counters) if (v.reset <= now) counters.delete(k);
  const current = counters.get(hashed) || {count: 0, reset: now + seconds * 1000};
  current.count++; counters.set(hashed, current); return current.count <= limit;
}
export async function saveReport(report: Report) {
  const supabase = db(); if (!supabase) return false;
  const {error} = await supabase.from("kheronyx_reports").insert({id: report.id, created_at: report.createdAt, filename: report.filename, kind: report.kind, size: report.size, sha256: report.sha256, risk: report.assessment.risk, report});
  if (error) throw new Error("Laporan selesai tetapi gagal disimpan. Unduh laporan untuk menyimpannya."); return true;
}
export async function listReports() {
  const supabase = db(); if (!supabase) return [];
  const {data, error} = await supabase.from("kheronyx_reports").select("report").order("created_at", {ascending: false}).limit(30);
  if (error) throw new Error("Riwayat belum dapat dimuat."); return (data || []).map(row => row.report as Report);
}
export async function readReport(id: string): Promise<Report | null> {
  const supabase = db(); if (!supabase) return null;
  const {data, error} = await supabase.from("kheronyx_reports").select("report").eq("id", id).maybeSingle();
  if (error) throw new Error("Laporan belum dapat dimuat.");
  return data?.report as Report || null;
}
export async function updateReport(report: Report) {
  const supabase = db(); if (!supabase) return false;
  const {data, error} = await supabase.from("kheronyx_reports").update({risk: report.assessment.risk, report}).eq("id", report.id).eq("sha256", report.sha256).select("id").maybeSingle();
  if (error || !data) throw new Error("Hasil diperbarui tetapi gagal disimpan. Unduh JSON untuk menyimpannya.");
  return true;
}
