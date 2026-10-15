import { z } from "zod";
export const riskLevels = ["low", "medium", "high", "critical", "unknown"] as const;
export type Risk = typeof riskLevels[number];
export type FileKind = "pdf" | "apk" | "exe" | "png" | "jpg";
export type VirusTotalStats = {
  malicious: number; suspicious: number; harmless: number; undetected: number;
  timeout: number; failure: number; "confirmed-timeout": number; "type-unsupported": number;
};
export type VirusTotalResult = {
  status: "not_configured" | "not_found" | "completed" | "pending" | "rate_limited" | "error";
  sha256: string; checkedAt: string; source: "hash_lookup" | "file_upload";
  message: string; url: string; analysedAt?: string; analysisId?: string;
  stats?: VirusTotalStats;
  detections?: {engine: string; category: "malicious" | "suspicious"; result: string | null}[];
};
// External reputation (abuse.ch MalwareBazaar/URLhaus/ThreatFox, RDAP domain age). Only hits are listed; hosts = what was checked.
export type ThreatIntelResult = {
  checkedAt: string; hosts: string[];
  malwareBazaar?: {family: string | null; tags: string[]; firstSeen?: string; fileType?: string; delivery?: string; vendors?: string[]; reference?: string} | null;
  urlhaus: {target: string; kind: "host" | "url"; status?: string; urlCount?: number; online?: number; threats?: string[]; tags?: string[]; blacklists?: string[]; families?: string[]; firstSeen?: string; reference?: string}[];
  threatfox: {term: string; family: string | null; threatType?: string; confidence?: number; firstSeen?: string; matches: number; reference?: string}[];
  domains: {domain: string; registered?: string; expires?: string; ageDays?: number; registrar?: string}[];
  skipped?: string[]; errors?: string[];
};
// Runtime behaviour observed by VirusTotal's own sandboxes (behaviour_summary), normalized and noise-filtered. Kheronyx
// never executes files; this is third-party evidence. contacted = non-benign network contacts (connectivity checks,
// vendor telemetry, private/reserved IPs and IPs that only served filtered hostnames are dropped).
export type SandboxContact = {host?: string; ip?: string; port?: number; protocol?: string; url?: string; kind: "dns" | "ip" | "http"};
export type SandboxResult = {
  source: "virustotal"; status: "completed" | "empty" | "not_configured" | "rate_limited" | "error"; fetchedAt: string; message?: string;
  sandboxes: string[]; contacted: SandboxContact[]; tags: string[]; verdicts: string[]; labels?: string[];
  mitre: {id: string; description: string; severity?: "info" | "low" | "medium" | "high"}[]; highlights?: string[];
  counts?: {dns: number; ip: number; http: number; processes: number; filesDropped: number; filtered: number};
};
// Tria.ge (Hatching Triage) public sandbox, opt-in per upload (APK/EXE). Kheronyx still never executes files: this is
// third-party evidence, normalized and noise-filtered in lib/triage.ts. Secrets in extracted configs are masked
// ("…" + last 4 characters at most); score uses Triage's 1–10 scale (8–10 malicious, 6–7 suspicious, 1–5 likely benign).
export type TriageStatus = "pending" | "running" | "reported" | "failed" | "skipped" | "rate_limited";
export type TriageConfig = {
  family: string; rule?: string; c2: string[]; botnet?: string; campaign?: string; version?: string; mutex?: string[];
  credentials?: {protocol?: string; host?: string; port?: number; username?: string; password?: string}[];
  keys?: {kind?: string; key?: string; value: string}[]; wallets?: string[]; raw?: string;
};
export type TriageResult = {
  status: TriageStatus; sampleId?: string; url?: string; submittedAt: string; checkedAt: string; reused?: boolean;
  score?: number; family?: string[]; tags?: string[]; configs?: TriageConfig[]; contacted?: SandboxContact[];
  signatures?: {name: string; score?: number; description?: string; label?: string; ttp?: string[]}[];
  platforms?: string[]; message?: string; nextCheck?: string; reassessedAt?: string;
  // Other public Tria.ge samples of the same family (same signing certificate first) that did run, with the servers
  // they contacted: the operator's infrastructure when this file itself stayed silent or was not run.
  siblings?: TriageSibling[]; siblingsCheckedAt?: string;
};
export type TriageSibling = {sampleId: string; url?: string; name?: string; submitted?: string; match: "cert" | "family"; contacted: SandboxContact[]};
export const assessmentSchema = z.object({
  risk: z.enum(riskLevels),
  confidence: z.enum(["low", "medium", "high"]),
  summary: z.string().min(1).max(1800),
  findings: z.array(z.object({
    title: z.string().max(180),
    severity: z.enum(["low", "medium", "high", "critical"]),
    explanation: z.string().max(1400),
    evidence: z.string().max(1000)
  })).max(15),
  recommendations: z.array(z.string().max(700)).min(1).max(8),
  limitations: z.array(z.string().max(700)).min(1).max(8)
});
export type Assessment = z.infer<typeof assessmentSchema>;
export type Artifact = {
  filename: string; kind: FileKind; size: number; sha256: string;
  metadata: Record<string, unknown>; strings: string[]; urls: string[];
  indicators: {name: string; evidence: string}[];
  limitations: string[]; incomplete: boolean; virusTotal?: VirusTotalResult; threatIntel?: ThreatIntelResult; sandbox?: SandboxResult; triage?: TriageResult;
};
export type Report = {
  id: string; createdAt: string; filename: string; kind: FileKind; size: number;
  sha256: string; model: string; durationMs: number; assessment: Assessment; artifact: Artifact;
};
export type AppConfig = { aiReady: boolean; storageReady: boolean; virusTotalReady: boolean; triageReady: boolean; jobs: boolean; upload: "blob" | "supabase" | "direct"; limits: Record<FileKind, number>; model: string; fallbackModel: string };
