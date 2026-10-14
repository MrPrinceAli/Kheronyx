import { randomUUID } from "node:crypto";
import { assess } from "./ai";
import { extractFile } from "./extract";
import { applyThreatIntel, inspectThreatIntel } from "./threat-intel";
import { inspectVirusTotal } from "./virustotal";
import type { Report } from "./types";

export type AnalysisStage = "download" | "extract" | "virustotal" | "ai" | "save";
// Failures that retrying cannot fix (wrong format, oversized, file gone); everything else is retried.
export class PermanentError extends Error {}

export async function analyzeBuffer(buffer: Buffer, filename: string, uploadVirusTotal: boolean, {id = randomUUID(), onStage}: {id?: string; onStage?: (stage: AnalysisStage) => Promise<void> | void} = {}): Promise<Report> {
  const start = Date.now();
  await onStage?.("extract");
  // extractFile only throws for files it refuses outright; internal parse errors are recorded as limitations.
  const artifact = await extractFile(buffer, filename).catch(error => { throw new PermanentError(error instanceof Error ? error.message : "File tidak dapat dibedah."); });
  await onStage?.("virustotal");
  // abuse.ch/RDAP reputation (≤15 s, never throws) runs alongside VirusTotal under the same stage.
  const [virusTotal, threatIntel] = await Promise.all([inspectVirusTotal(artifact, buffer, uploadVirusTotal), inspectThreatIntel(artifact)]);
  artifact.virusTotal = virusTotal; applyThreatIntel(artifact, threatIntel);
  await onStage?.("ai");
  const {assessment, model} = await assess(artifact);
  return {id, createdAt: new Date().toISOString(), filename: artifact.filename, kind: artifact.kind, size: artifact.size, sha256: artifact.sha256, model, durationMs: Date.now() - start, assessment, artifact};
}
