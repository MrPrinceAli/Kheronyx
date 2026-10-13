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
  limitations: string[]; incomplete: boolean; virusTotal?: VirusTotalResult;
};
export type Report = {
  id: string; createdAt: string; filename: string; kind: FileKind; size: number;
  sha256: string; model: string; durationMs: number; assessment: Assessment; artifact: Artifact;
};
export type AppConfig = { aiReady: boolean; storageReady: boolean; virusTotalReady: boolean; maxBytes: number; model: string; fallbackModel: string };
