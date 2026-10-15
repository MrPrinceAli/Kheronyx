import { after } from "next/server";
import { assess as defaultAssess } from "./ai";
import { blobConfigured, readBlob, removeBlob } from "./blob";
import { db, readReport, storageConfigured, updateReport } from "./db";
import { KIND_LIMITS } from "./limits";
import { applyThreatIntel, inspectThreatIntel, type ThreatIntelOptions } from "./threat-intel";
import { TRIAGE_KINDS, applyTriageIndicators, checkTriage, findSiblings, mergeTriageHosts, submitTriage, triageConfigured, type TriageOptions } from "./triage";
import type { FileKind, Report, ThreatIntelResult, TriageResult } from "./types";

// Durable Tria.ge polling (kheronyx_sandbox): the analysis job submits or reuses a sample (≤ 60 s, before the quarantine
// blob is deleted), then the Supabase scheduler (/api/jobs/run), dashboard polling and report refreshes run due checks.
// Once reported, the digest is merged into the report, new hosts get reputation lookups, and the AI re-assesses.
// Sandbox problems never fail or block the main analysis.
type Row = {report_id: string; sha256: string; sample_id: string | null; path: string | null; status: "pending" | "running" | "done" | "failed"; attempts: number; next_check: string; created_at: string};
const TABLE = "kheronyx_sandbox", LEASE_SECONDS = 300, DEADLINE_MS = 280_000, MAX_ATTEMPTS = 40;

export function triageReady() { return triageConfigured() && blobConfigured() && storageConfigured(); }
export const triageKind = (kind: FileKind) => TRIAGE_KINDS.includes(kind);
// Placeholder stored with the first report save, so the dashboard starts waiting right away.
export const pendingTriage = (): TriageResult => { const at = new Date().toISOString(); return {status: "pending", submittedAt: at, checkedAt: at, nextCheck: at, message: "Menyiapkan sandbox Tria.ge…"}; };
const client = () => { const supabase = db(); if (!supabase) throw new Error("Storage belum terhubung."); return supabase; };

// Reputation lookups only for hosts the sandbox added; merged into the stored result (hits stay, notes deduplicated).
export function mergeIntel(old: ThreatIntelResult | undefined, fresh: ThreatIntelResult): ThreatIntelResult {
  if (!old) return fresh;
  const by = <T>(list: T[], key: (x: T) => string) => list.filter((x, i, a) => a.findIndex(y => key(y) === key(x)) === i);
  const notes = (a?: string[], b?: string[]) => { const s = [...new Set([...a ?? [], ...b ?? []])].slice(0, 6); return s.length ? s : undefined; };
  const out: ThreatIntelResult = {...old, checkedAt: fresh.checkedAt, hosts: [...new Set([...old.hosts, ...fresh.hosts])].slice(0, 20), urlhaus: by([...old.urlhaus, ...fresh.urlhaus], x => x.target).slice(0, 12), threatfox: by([...old.threatfox, ...fresh.threatfox], x => x.term).slice(0, 12), domains: by([...old.domains, ...fresh.domains], x => x.domain).slice(0, 12)};
  const skipped = notes(old.skipped, fresh.skipped), errors = notes(old.errors, fresh.errors);
  if (skipped) out.skipped = skipped; else delete out.skipped;
  if (errors) out.errors = errors; else delete out.errors;
  return out;
}

export type FinishDeps = {assess?: typeof defaultAssess; threatIntel?: ThreatIntelOptions; inspect?: typeof inspectThreatIntel; siblings?: typeof findSiblings; budgetMs?: number; now?: () => number};
type Cert = {subject?: string; issuer?: string; validFrom?: string; validTo?: string};
// Once per report: earlier builds of the same family (same signing certificate first) that Tria.ge did run (≤ 25 s).
async function withSiblings(report: Report, triage: TriageResult, find: typeof findSiblings, now: number): Promise<TriageResult> {
  const family = triage.family?.[0]; if (!family || triage.siblingsCheckedAt) return triage;
  const cert = (report.artifact.metadata.signing as {certificates?: Cert[]} | undefined)?.certificates?.[0];
  const siblings = await find({family, sha256: report.sha256, cert: cert?.subject ? {subject: cert.subject, issuer: cert.issuer, validFrom: cert.validFrom, validTo: cert.validTo} : undefined}, {signal: AbortSignal.timeout(25_000)}).catch(() => undefined);
  return siblings ? {...triage, siblings: siblings.length ? siblings : undefined, siblingsCheckedAt: new Date(now).toISOString()} : triage;
}
// Applies a sandbox result to a report. Only a reported digest changes evidence: hosts merged, indicators added, new
// hosts checked (≤ 15 s), then the AI re-assesses the enriched artifact. If the AI fails the earlier verdict stays.
export async function finishTriage(report: Report, triage: TriageResult, {assess = defaultAssess, threatIntel, inspect = inspectThreatIntel, siblings = findSiblings, budgetMs = 200_000, now = Date.now}: FinishDeps = {}): Promise<Report> {
  const artifact = structuredClone(report.artifact); artifact.triage = triage;
  if (triage.status !== "reported") return {...report, artifact};
  const started = now(); artifact.triage = triage = await withSiblings(report, triage, siblings, started); budgetMs -= now() - started;
  const added = mergeTriageHosts(artifact);
  applyTriageIndicators(artifact);
  if (added.length) {
    try {
      const probe = {...artifact, sha256: "", urls: [], metadata: {campaign: {hosts: added}}};
      applyThreatIntel(artifact, mergeIntel(artifact.threatIntel, await inspect(probe, threatIntel)));
    } catch {}
  }
  try {
    const {assessment, model} = await assess(artifact, {budgetMs});
    assessment.limitations = [...new Set([...assessment.limitations.filter(l => !l.startsWith("Sandbox Tria.ge:")), "Sandbox Tria.ge: penilaian sudah diperbarui dengan hasil saat file dijalankan di Tria.ge (bukan di Kheronyx)."])].slice(0, 12);
    artifact.triage = {...triage, reassessedAt: new Date(now()).toISOString()};
    return {...report, artifact, assessment, model};
  } catch {
    artifact.triage = {...triage, message: [triage.message, "Penilaian AI belum diperbarui dengan bukti sandbox; penilaian awal tetap dipakai."].filter(Boolean).join(" ")};
    return {...report, artifact};
  }
}

const rowStatus = (t: TriageResult) => t.nextCheck ? (t.status === "running" ? "running" : "pending") : t.status === "reported" ? "done" : "failed";
async function knownSample(sha256: string) {
  const {data} = await client().from(TABLE).select("sample_id").eq("sha256", sha256).not("sample_id", "is", null).order("created_at", {ascending: false}).limit(1);
  return (data as {sample_id: string}[] | null)?.[0]?.sample_id;
}

// Called by the job runner after the report is saved and before the quarantine blob is removed. Returns whether the
// blob must be kept for a later upload retry. Never throws.
export async function startTriage(report: Report, buffer: Buffer, path: string, options: TriageOptions = {}): Promise<{keepBlob: boolean}> {
  try {
    const previous = report.artifact.triage;
    const known = await knownSample(report.sha256).catch(() => undefined);
    const {result, retryUpload} = await submitTriage({sha256: report.sha256, kind: report.kind, buffer, known}, previous, {...options, signal: options.signal ?? AbortSignal.timeout(75_000)});
    report.artifact.triage = result;
    await updateReport(report).catch(() => {});
    if (!result.nextCheck) return {keepBlob: false};
    const {error} = await client().from(TABLE).upsert({report_id: report.id, sha256: report.sha256, sample_id: result.sampleId ?? null, path: retryUpload ? path : null, status: rowStatus(result), attempts: 0, next_check: result.nextCheck, updated_at: new Date().toISOString()}, {onConflict: "report_id"});
    if (error) { report.artifact.triage = {...result, nextCheck: undefined, status: result.sampleId ? result.status : "failed", message: "Pemantauan sandbox belum dapat dijadwalkan; buka hasilnya langsung di tria.ge."}; await updateReport(report).catch(() => {}); return {keepBlob: false}; }
    return {keepBlob: retryUpload};
  } catch (error) {
    console.error("Kheronyx Tria.ge submission failed:", error instanceof Error ? error.message : error);
    return {keepBlob: false};
  }
}

async function finishRow(row: Row, fields: Partial<Row>) {
  await client().from(TABLE).update({...fields, updated_at: new Date().toISOString()}).eq("report_id", row.report_id);
  if (row.path && fields.path === null) await removeBlob(row.path).catch(() => {});
}
// One leased check: retry the upload (no sample yet) or poll the sample; finished results update the report.
export async function checkRow(row: Row, deadline: number) {
  const report = await readReport(row.report_id).catch(() => undefined);
  if (report === null) { if (row.path) await removeBlob(row.path).catch(() => {}); await client().from(TABLE).delete().eq("report_id", row.report_id); return; }
  if (!report) { await finishRow(row, {next_check: new Date(Date.now() + 60_000).toISOString()}); return; }
  const previous: TriageResult = report.artifact.triage ?? {status: "pending", submittedAt: row.created_at, checkedAt: row.created_at};
  let next: TriageResult, keep = false;
  if (!row.sample_id) {
    const buffer = row.path ? await readBlob(row.path, KIND_LIMITS[report.kind]).catch(() => undefined) : undefined;
    ({result: next, retryUpload: keep} = await submitTriage({sha256: report.sha256, kind: report.kind, buffer}, previous));
  } else next = await checkTriage({...previous, sampleId: previous.sampleId || row.sample_id}, report.sha256);
  if (next.nextCheck && row.attempts >= MAX_ATTEMPTS) next = {...next, nextCheck: undefined, status: "failed", message: "Pemeriksaan sandbox Tria.ge dihentikan setelah terlalu banyak percobaan."};
  const updated = await finishTriage(report, next, {budgetMs: deadline - Date.now() - 20_000});
  try { await updateReport(updated); }
  catch { if (row.path) await removeBlob(row.path).catch(() => {}); await client().from(TABLE).delete().eq("report_id", row.report_id); return; }
  const t = updated.artifact.triage!;
  await finishRow(row, {sample_id: t.sampleId ?? row.sample_id, status: rowStatus(t), next_check: t.nextCheck ?? new Date().toISOString(), path: keep ? row.path : null});
}

// Cheap check used by GET /api/jobs and report polling before scheduling a worker.
export async function sandboxDue() {
  if (!triageReady()) return false;
  const {data, error} = await client().from(TABLE).select("report_id").in("status", ["pending", "running"]).lte("next_check", new Date().toISOString()).limit(1);
  return !error && Boolean(data?.length);
}

// Runs due checks one by one; new checks only start in the first minute of an invocation, so a re-assessment keeps
// ≥ 200 s of the 300 s function budget. Each claim is leased (300 s): parallel workers never double-check.
export async function runDueSandbox(started = Date.now()) {
  try {
    while (triageReady() && Date.now() - started < 60_000) {
      const {data, error} = await client().rpc("kheronyx_claim_sandbox", {p_limit: 1, p_lease_seconds: LEASE_SECONDS});
      const row = (data as Row[] | null)?.[0]; if (error || !row) return;
      await checkRow(row, started + DEADLINE_MS);
    }
  } catch (error) { console.error("Kheronyx sandbox runner failed:", error instanceof Error ? error.message : error); }
}
// After the response is sent (scheduler, dashboard polling).
export function kickSandbox() { const started = Date.now(); after(() => runDueSandbox(started)); }
