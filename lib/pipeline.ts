import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { assess } from "./ai";
import { extractFile } from "./extract";
import { applyThreatIntel, inspectThreatIntel, type ThreatIntelOptions } from "./threat-intel";
import { fetchBehaviour, inspectVirusTotal, mergeSandboxHosts, virusTotalKnown } from "./virustotal";
import type { Artifact, Report, SandboxResult } from "./types";

export type AnalysisStage = "download" | "extract" | "virustotal" | "ai" | "save";
// Failures that retrying cannot fix (wrong format, oversized, file gone); everything else is retried.
export class PermanentError extends Error {}

type ReputationOptions = {virusTotal?: Parameters<typeof inspectVirusTotal>[3]; threatIntel?: ThreatIntelOptions; behaviourWaitMs?: number};
// VirusTotal lookup → (file known) sandbox behaviour → abuse.ch/RDAP. Threat intel waits for the sandbox's contacted
// hosts so they get checked too, but never longer than behaviourWaitMs after the start, so this adds at most ~10 s to
// the old VirusTotal ‖ threat-intel stage. A sandbox digest arriving later still reaches the AI and the report.
export async function inspectReputation(artifact: Artifact, buffer: Buffer, uploadVirusTotal: boolean, {virusTotal: vtOptions, threatIntel: tiOptions, behaviourWaitMs = 10000}: ReputationOptions = {}) {
  const lookup = inspectVirusTotal(artifact, buffer, uploadVirusTotal, vtOptions);
  const behaviour = lookup.then(vt => virusTotalKnown(vt) ? fetchBehaviour(artifact.sha256, vtOptions) : undefined).catch(() => undefined);
  const settle = (s?: SandboxResult) => { if (s && !artifact.sandbox) { artifact.sandbox = s; mergeSandboxHosts(artifact); } };
  const wait = new AbortController();
  settle(await Promise.race([behaviour, delay(behaviourWaitMs, undefined, {signal: wait.signal}).catch(() => undefined)])); wait.abort();
  const [virusTotal, threatIntel, sandbox] = await Promise.all([lookup, inspectThreatIntel(artifact, tiOptions), behaviour]);
  settle(sandbox); artifact.virusTotal = virusTotal; applyThreatIntel(artifact, threatIntel);
}

export async function analyzeBuffer(buffer: Buffer, filename: string, uploadVirusTotal: boolean, {id = randomUUID(), onStage}: {id?: string; onStage?: (stage: AnalysisStage) => Promise<void> | void} = {}): Promise<Report> {
  const start = Date.now();
  await onStage?.("extract");
  // extractFile only throws for files it refuses outright; internal parse errors are recorded as limitations.
  const artifact = await extractFile(buffer, filename).catch(error => { throw new PermanentError(error instanceof Error ? error.message : "File tidak dapat dibedah."); });
  await onStage?.("virustotal");
  // VirusTotal (+ sandbox behaviour) and abuse.ch/RDAP reputation (≤15 s) under the same stage; none of them throws.
  await inspectReputation(artifact, buffer, uploadVirusTotal);
  await onStage?.("ai");
  const {assessment, model} = await assess(artifact);
  return {id, createdAt: new Date().toISOString(), filename: artifact.filename, kind: artifact.kind, size: artifact.size, sha256: artifact.sha256, model, durationMs: Date.now() - start, assessment, artifact};
}
