import { createHash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { z } from "zod";
import { rateLimit } from "./db";
import type { Artifact, VirusTotalResult, VirusTotalStats } from "./types";

const BASE = "https://www.virustotal.com/api/v3";
const count = z.number().int().min(0).max(10000);
const statsSchema = z.object({
  malicious: count, suspicious: count, harmless: count, undetected: count,
  timeout: count.default(0), failure: count.default(0),
  "confirmed-timeout": count.default(0), "type-unsupported": count.default(0),
});
const attributesSchema = z.object({
  last_analysis_stats: statsSchema.optional(), last_analysis_date: countTimestamp().optional(),
  last_analysis_results: z.record(z.string(), z.unknown()).optional(),
  stats: statsSchema.optional(), date: countTimestamp().optional(),
  results: z.record(z.string(), z.unknown()).optional(),
  status: z.enum(["queued", "in-progress", "completed"]).optional(),
});
function countTimestamp() { return z.number().int().min(1).max(253402300799); }

export function virusTotalConfigured() { return Boolean(process.env.VIRUSTOTAL_API_KEY?.trim()); }
type Options = { requestGate?: () => Promise<boolean>; signal?: AbortSignal };
class ProviderError extends Error {
  constructor(public status: "not_found" | "rate_limited" | "error", message: string) { super(message); }
}

function initial(sha256: string): VirusTotalResult {
  if (!/^[a-f0-9]{64}$/.test(sha256)) throw new Error("Hash SHA-256 tidak valid.");
  return {
    status: "not_configured", sha256, checkedAt: new Date().toISOString(), source: "hash_lookup",
    message: "VirusTotal belum aktif. API key belum diisi.",
    url: `https://www.virustotal.com/gui/file/${sha256}/detection`,
  };
}

async function readJson(response: Response) {
  if (!response.body) throw new Error("Empty provider response");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = []; let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read(); if (done) break;
      size += value.length;
      if (size > 1024 * 1024) { await reader.cancel(); throw new Error("Oversized provider response"); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function client(options: Options, timeoutMs: number) {
  const key = process.env.VIRUSTOTAL_API_KEY?.trim() || "";
  const signal = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs);
  const identifier = createHash("sha256").update(key).digest("hex");
  const gate = options.requestGate || (async () => {
    if (!await rateLimit(`virustotal:minute:${identifier}`, 4, 60)) return false;
    return rateLimit(`virustotal:day:${identifier}`, 500, 86400);
  });
  return {
    signal,
    async request(url: string, init?: RequestInit) {
      signal.throwIfAborted();
      if (!await gate()) throw new ProviderError("rate_limited", "Kuota VirusTotal tercapai. Coba perbarui hasil nanti.");
      const response = await fetch(url, {
        ...init, headers: { ...init?.headers, "x-apikey": key, accept: "application/json" },
        signal, cache: "no-store", redirect: "error",
      });
      if (!response.ok) {
        await response.body?.cancel().catch(() => {});
        if (response.status === 404) throw new ProviderError("not_found", "Hash file belum tercatat di VirusTotal.");
        if (response.status === 429) throw new ProviderError("rate_limited", "Kuota VirusTotal tercapai. Coba perbarui hasil nanti.");
        if ([401, 403].includes(response.status)) throw new ProviderError("error", "API key atau akses VirusTotal ditolak. Periksa konfigurasi key.");
        throw new ProviderError("error", "VirusTotal belum dapat dihubungi. Coba perbarui hasil nanti.");
      }
      return readJson(response);
    },
  };
}

function normalized(attributes: unknown, result: VirusTotalResult, analysis = false): VirusTotalResult {
  const data = attributesSchema.parse(attributes);
  const stats = analysis ? data.stats : data.last_analysis_stats;
  const timestamp = analysis ? data.date : data.last_analysis_date;
  if (analysis && data.status !== "completed" || !stats || !timestamp) {
    return { ...result, status: "pending", message: "Pemindaian VirusTotal belum selesai. Perbarui hasil setelah beberapa saat." };
  }
  const total = Object.values(stats).reduce((sum, n) => sum + n, 0);
  if (!total) return { ...result, status: "pending", message: "VirusTotal belum memberikan hasil engine antivirus." };
  const detections = Object.entries((analysis ? data.results : data.last_analysis_results) || {}).flatMap(([name, value]) => {
    const entry = z.object({ engine_name: z.string().max(200).optional(), category: z.string(), result: z.string().max(1000).nullable().optional() }).safeParse(value);
    if (!entry.success || !["malicious", "suspicious"].includes(entry.data.category)) return [];
    return [{ engine: (entry.data.engine_name || name).slice(0, 120), category: entry.data.category as "malicious" | "suspicious", result: entry.data.result?.slice(0, 250) || null }];
  });
  if (detections.filter(d => d.category === "malicious").length > stats.malicious || detections.filter(d => d.category === "suspicious").length > stats.suspicious) throw new Error("Inconsistent VirusTotal detection counts");
  return {
    ...result, status: "completed", stats: stats as VirusTotalStats, detections: detections.slice(0, 12),
    analysedAt: new Date(timestamp * 1000).toISOString(),
    message: "Hasil antivirus VirusTotal tersedia. Nol deteksi bukan jaminan aman.",
  };
}

function failed(error: unknown, result: VirusTotalResult): VirusTotalResult {
  if (result.analysisId) return { ...result, status: "pending", message: "File sudah dikirim ke VirusTotal. Hasil belum tersedia; perbarui setelah beberapa saat." };
  if (error instanceof ProviderError) return { ...result, status: error.status, message: error.message };
  return { ...result, status: "error", message: "Pemeriksaan VirusTotal gagal atau melewati batas waktu. Belum ada hasil antivirus." };
}

async function lookup(api: ReturnType<typeof client>, result: VirusTotalResult) {
  const body = await api.request(`${BASE}/files/${result.sha256}`);
  if (body.data?.type !== "file" || body.data?.id !== result.sha256) throw new Error("Mismatched VirusTotal file hash");
  return normalized(body.data.attributes, result);
}

export async function lookupVirusTotal(sha256: string, options: Options = {}): Promise<VirusTotalResult> {
  const result = initial(sha256); if (!virusTotalConfigured()) return result;
  try { return await lookup(client(options, 15000), result); } catch (error) { return failed(error, result); }
}

export function trustedUploadUrl(value: unknown) {
  if (typeof value !== "string") throw new Error("Invalid VirusTotal upload URL");
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.hostname !== "www.virustotal.com" || url.username || url.password || url.port || !["/_ah/upload/", "/api/v3/files/upload/"].some(prefix => url.pathname.startsWith(prefix))) throw new Error("Untrusted VirusTotal upload URL");
  // Official documentation includes legacy HTTP URLs; credentials always travel over HTTPS.
  url.protocol = "https:";
  return url.toString();
}

export async function inspectVirusTotal(artifact: Artifact, buffer: Buffer, uploadUnknown = false, options: Options = {}): Promise<VirusTotalResult> {
  let result = initial(artifact.sha256); if (!virusTotalConfigured()) return result;
  const api = client(options, 35000);
  try {
    try { return await lookup(api, result); }
    catch (error) {
      if (!(error instanceof ProviderError) || error.status !== "not_found" || !uploadUnknown) return failed(error, result);
    }
    const url = buffer.length > 32 * 1024 * 1024 ? trustedUploadUrl((await api.request(`${BASE}/files/upload_url`)).data) : `${BASE}/files`;
    const form = new FormData();
    form.append("file", new Blob([new Uint8Array(buffer)], { type: "application/octet-stream" }), `${artifact.sha256}.${artifact.kind}`);
    const body = await api.request(url, { method: "POST", body: form });
    const analysisId = body.data?.id;
    if (body.data?.type !== "analysis" || typeof analysisId !== "string" || !/^[a-zA-Z0-9_=:-]{1,250}$/.test(analysisId)) throw new Error("Invalid VirusTotal analysis ID");
    result = { ...result, source: "file_upload", status: "pending", analysisId, message: "Menunggu hasil pemindaian VirusTotal." };
    for (let attempt = 0; attempt < 2; attempt++) {
      if (attempt) await delay(5000, undefined, { signal: api.signal });
      const analysis = await api.request(`${BASE}/analyses/${encodeURIComponent(analysisId)}`);
      if (analysis.data?.id !== analysisId || analysis.data?.type !== "analysis" || analysis.meta?.file_info?.sha256 && analysis.meta.file_info.sha256 !== artifact.sha256) throw new Error("Mismatched VirusTotal analysis");
      result = normalized(analysis.data.attributes, result, true);
      if (result.status === "completed") return result;
    }
    return result;
  } catch (error) { return failed(error, result); }
}
