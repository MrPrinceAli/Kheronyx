import type { Artifact, Assessment, Report, SandboxResult, VirusTotalResult } from "./types";

const findingTitle = "Hasil engine antivirus VirusTotal";
const baselineLimit = "VirusTotal: hasil antivirus dapat mengandung false positive; nol deteksi bukan jaminan bebas malware.";

export function applyVirusTotalEvidence(assessment: Assessment, artifact: Artifact): Assessment {
  const result = artifact.virusTotal; if (!result) return assessment;
  const next: Assessment = {
    ...assessment, summary: assessment.summary.replace(/^VirusTotal: [^\n]*\n\n/, ""), findings: assessment.findings.filter(f => f.title !== findingTitle),
    recommendations: [...assessment.recommendations],
    limitations: assessment.limitations.filter(l => !l.startsWith("VirusTotal:")),
  };
  const stats = result.status === "completed" ? result.stats : undefined;
  if (!stats) {
    next.limitations.push(`VirusTotal: ${result.message}`);
    return next;
  }
  next.limitations.push(baselineLimit);
  const scored = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
  if (!scored) next.limitations.push("VirusTotal: tidak ada engine yang memberikan penilaian untuk tipe file ini.");
  const flagged = stats.malicious + stats.suspicious;
  if (flagged) {
    const severity = stats.malicious ? "high" : "medium";
    const rank = { unknown: 0, low: 1, medium: 2, high: 3, critical: 4 };
    if (rank[next.risk] < rank[severity]) next.risk = severity;
    next.findings.unshift({
      title: findingTitle, severity,
      explanation: `${stats.malicious} engine melabeli malicious dan ${stats.suspicious} melabeli suspicious. Ini perlu ditinjau; label engine belum memastikan atribusi malware dan dapat berupa false positive.`,
      evidence: `VirusTotal SHA-256 ${result.sha256}; malicious=${stats.malicious}, suspicious=${stats.suspicious}, engine dengan penilaian=${scored}; hasil ${result.analysedAt || result.checkedAt}.`,
    });
    const prefix = `VirusTotal: ${stats.malicious} engine melabeli malicious dan ${stats.suspicious} melabeli suspicious. Tinjau deteksi sebelum membuka atau menginstal file.`;
    next.summary = `${prefix}\n\n${next.summary.replace(/^VirusTotal: [^\n]*\n\n/, "")}`.slice(0, 1800);
    const advice = "Hindari membuka atau menginstal file sampai deteksi VirusTotal dan sumber file selesai diverifikasi.";
    next.recommendations = [advice, ...next.recommendations.filter(r => r !== advice)].slice(0, 8);
    next.findings = next.findings.slice(0, 15);
  }
  return next;
}

export function updateVirusTotalReport(report: Report, result: VirusTotalResult): Report {
  if (result.sha256 !== report.sha256) throw new Error("Hasil VirusTotal tidak cocok dengan file laporan.");
  const artifact = { ...report.artifact, virusTotal: result };
  const assessment = applyVirusTotalEvidence(report.assessment, artifact);
  assessment.limitations = [...new Set([...assessment.limitations, "VirusTotal: hasil diperbarui; penjelasan AI tetap berasal dari analisis awal."])];
  return { ...report, artifact, assessment };
}

// A refreshed sandbox digest replaces the stored one only when it is an actual answer (data or "never sandboxed");
// quota/errors never erase earlier behaviour evidence.
export function pickSandbox(old: SandboxResult | undefined, fresh: SandboxResult | undefined) {
  return fresh && (!old || fresh.status === "completed" || fresh.status === "empty") ? fresh : old;
}
