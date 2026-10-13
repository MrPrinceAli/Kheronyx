import { z } from "zod";
export const riskLevels = ["low", "medium", "high", "critical", "unknown"] as const;
export type Risk = typeof riskLevels[number];
export type FileKind = "pdf" | "apk" | "exe" | "png" | "jpg";
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
  limitations: string[]; incomplete: boolean;
};
export type Report = {
  id: string; createdAt: string; filename: string; kind: FileKind; size: number;
  sha256: string; model: string; durationMs: number; assessment: Assessment; artifact: Artifact;
};
export type AppConfig = { aiReady: boolean; storageReady: boolean; maxBytes: number; model: string; fallbackModel: string };
