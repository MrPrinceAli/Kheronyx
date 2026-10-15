import { randomUUID } from "node:crypto";
import { after } from "next/server";
import { db, saveReport, storageConfigured } from "./db";
import { blobConfigured, readBlob, removeBlob } from "./blob";
import { KIND_LIMITS } from "./limits";
import { analyzeBuffer, PermanentError, type AnalysisStage } from "./pipeline";
import { pendingTriage, runDueSandbox, startTriage, triageKind, triageReady } from "./sandbox";
import type { FileKind } from "./types";

export type JobStatus = "queued" | "running" | "done" | "failed";
export type Job = {id: string; createdAt: string; filename: string; kind: FileKind; size: number; status: JobStatus; stage: AnalysisStage | null; attempts: number; retryAt: string | null; error: string | null; reportId: string | null};
type Row = {id: string; created_at: string; path: string; filename: string; kind: FileKind; size: number; upload_virustotal: boolean; upload_triage?: boolean; status: JobStatus; stage: AnalysisStage | null; attempts: number; locked_until: string | null; error: string | null; report_id: string | null};

export const MAX_ATTEMPTS = 5;
// Longer than the 300 s function limit, so a job whose worker was killed becomes claimable again.
const LEASE_SECONDS = 330;
const BACKOFF_SECONDS = [30, 60, 120, 300];
const TABLE = "kheronyx_jobs";

// Background jobs need durable state (Supabase) and a file that outlives the request (Blob).
export function jobsConfigured() { return blobConfigured() && storageConfigured(); }

const toJob = (row: Row): Job => ({id: row.id, createdAt: row.created_at, filename: row.filename, kind: row.kind, size: row.size, status: row.status, stage: row.stage, attempts: row.attempts, retryAt: row.status === "queued" ? row.locked_until : null, error: row.error, reportId: row.report_id});
const client = () => { const supabase = db(); if (!supabase) throw new Error("Storage belum terhubung."); return supabase; };
const update = async (id: string, fields: Partial<Row>) => { await client().from(TABLE).update({...fields, updated_at: new Date().toISOString()}).eq("id", id); };
// Cancelling deletes the job row; the worker notices at its next stage change and stops without saving.
class CancelledError extends Error {}
const advance = async (id: string, stage: AnalysisStage) => {
  const {data} = await client().from(TABLE).update({stage, updated_at: new Date().toISOString()}).eq("id", id).select("id");
  if (!data?.length) throw new CancelledError();
};

export async function createJob(input: {path: string; filename: string; kind: FileKind; size: number; uploadVirusTotal: boolean; uploadTriage?: boolean}) {
  const id = randomUUID();
  const fields: Record<string, unknown> = {id, path: input.path, filename: input.filename.replace(/[\x00-\x1f\x7f]/g, "").slice(0, 180), kind: input.kind, size: input.size, upload_virustotal: input.uploadVirusTotal};
  let {data, error} = await client().from(TABLE).insert(input.uploadTriage ? {...fields, upload_triage: true} : fields).select().single();
  // Sandbox opt-in must never block the analysis (e.g. before migration 202610150001 adds upload_triage).
  if (error && input.uploadTriage) ({data, error} = await client().from(TABLE).insert(fields).select().single());
  if (error || !data) throw new Error("Analisis belum dapat dijadwalkan. Coba lagi.");
  return toJob(data as Row);
}

// Active and failed jobs only; finished jobs show up as reports.
export async function listJobs() {
  const {data, error} = await client().from(TABLE).select("*").in("status", ["queued", "running", "failed"]).order("created_at", {ascending: false}).limit(20);
  if (error) throw new Error("Status analisis belum dapat dimuat.");
  return (data as Row[]).map(toJob);
}

export function runnable(job: Job) {
  return (job.status === "queued" || job.status === "running") && job.attempts < MAX_ATTEMPTS && (!job.retryAt || Date.parse(job.retryAt) <= Date.now());
}

export async function retryJob(id: string) {
  const {data} = await client().from(TABLE).update({status: "queued", attempts: 0, locked_until: null, stage: null, updated_at: new Date().toISOString()}).eq("id", id).eq("status", "failed").select("id");
  return Boolean(data?.length);
}

// Removes a failed job, or cancels a queued/running one (its worker stops at the next stage).
export async function deleteJob(id: string) {
  const {data} = await client().from(TABLE).select("path").eq("id", id).maybeSingle();
  if (!data) return false;
  await removeBlob(data.path).catch(() => {});
  await client().from(TABLE).delete().eq("id", id);
  return true;
}

async function claim(id?: string) {
  const {data, error} = await client().rpc("kheronyx_claim_job", {p_id: id ?? null, p_lease_seconds: LEASE_SECONDS, p_max_attempts: MAX_ATTEMPTS});
  if (error) throw new Error("Antrean analisis belum dapat diakses.");
  return (data as Row[] | null)?.[0] ?? null;
}

// Runs one claimed job to completion. Returns the time a transient failure may be retried, if any.
async function runClaimed(row: Row): Promise<number | null> {
  try {
    await advance(row.id, "download");
    const buffer = await readBlob(row.path, KIND_LIMITS[row.kind]).catch(error => {
      if (error instanceof Error && /tidak ditemukan|melebihi batas/.test(error.message)) throw new PermanentError(error.message);
      throw error;
    });
    // The report reuses the job id, so a retry after a crash overwrites instead of duplicating.
    const report = await analyzeBuffer(buffer, row.filename, row.upload_virustotal, {id: row.id, onStage: stage => advance(row.id, stage)});
    await advance(row.id, "save");
    // Opt-in Tria.ge sandbox (APK/EXE): the report is saved and shown first; the submission (search, else upload,
    // ≤ ~60 s) runs before the quarantine copy is deleted and can never fail the analysis.
    const sandbox = row.upload_triage === true && triageReady() && triageKind(row.kind);
    if (sandbox) report.artifact.triage = pendingTriage();
    await saveReport(report);
    await update(row.id, {status: "done", stage: null, locked_until: null, error: null, report_id: report.id});
    const {keepBlob} = sandbox ? await startTriage(report, buffer, row.path) : {keepBlob: false};
    if (!keepBlob) await removeBlob(row.path).catch(() => {});
    return null;
  } catch (error) {
    if (error instanceof CancelledError) return null;
    const message = error instanceof Error ? error.message : "Analisis gagal.";
    if (error instanceof PermanentError || row.attempts >= MAX_ATTEMPTS) {
      await update(row.id, {status: "failed", locked_until: null, error: row.attempts >= MAX_ATTEMPTS && !(error instanceof PermanentError) ? `${message} Percobaan otomatis sudah habis.` : message});
      // A rejected file can never succeed; keep the file only when a manual retry could still help.
      if (error instanceof PermanentError) await removeBlob(row.path).catch(() => {});
      return null;
    }
    const retryAt = Date.now() + BACKOFF_SECONDS[Math.min(row.attempts, BACKOFF_SECONDS.length) - 1] * 1000;
    await update(row.id, {status: "queued", locked_until: new Date(retryAt).toISOString(), error: message});
    return retryAt;
  }
}

// Continues analysis after the response is sent, so the browser may close. Transient failures are retried
// in the same invocation while its time budget allows; later retries come from the scheduler or the next
// dashboard visit (see /api/jobs/run and GET /api/jobs).
export function kick(id?: string) {
  const started = Date.now();
  after(async () => {
    try {
      for (;;) {
        const row = await claim(id); if (!row) break;
        const retryAt = await runClaimed(row);
        if (!retryAt || retryAt - started > 90_000) break;
        await new Promise(resolve => setTimeout(resolve, Math.max(0, retryAt - Date.now()) + 500));
      }
      // Sandbox checks that came due (e.g. a reused Tria.ge analysis) while time is left in this invocation.
      await runDueSandbox(started);
    } catch (error) { console.error("Kheronyx job runner failed:", error instanceof Error ? error.message : error); }
  });
}
