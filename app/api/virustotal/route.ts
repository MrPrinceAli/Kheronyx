import { NextResponse } from "next/server";
import { z } from "zod";
import { sameOrigin, sessionId } from "@/lib/auth";
import { rateLimit, readReport, storageConfigured, updateReport } from "@/lib/db";
import { lookupVirusTotal } from "@/lib/virustotal";
import { updateVirusTotalReport } from "@/lib/virus-total-evidence";

export const runtime = "nodejs";
export const maxDuration = 45;
const input = z.object({ reportId: z.string().uuid(), sha256: z.string().regex(/^[a-f0-9]{64}$/) });

export async function POST(request: Request) {
  const session = await sessionId();
  if (!session) return NextResponse.json({ error: "Login diperlukan." }, { status: 401 });
  if (!sameOrigin(request)) return NextResponse.json({ error: "Permintaan ditolak." }, { status: 403 });
  try {
    const { reportId, sha256 } = input.parse(await request.json());
    if (!await rateLimit(`virustotal-refresh:${session}`, 12, 600)) return NextResponse.json({ error: "Terlalu banyak pembaruan. Coba lagi nanti." }, { status: 429 });
    const stored = storageConfigured() ? await readReport(reportId) : null;
    if (storageConfigured() && (!stored || stored.sha256 !== sha256)) return NextResponse.json({ error: "Laporan tidak ditemukan." }, { status: 404 });
    const virusTotal = await lookupVirusTotal(sha256);
    // An unavailable lookup must not replace already completed evidence or a queued scan.
    if (stored?.artifact.virusTotal && ["completed", "pending"].includes(stored.artifact.virusTotal.status) && virusTotal.status !== "completed") {
      return NextResponse.json({ virusTotal: stored.artifact.virusTotal, report: stored, warning: virusTotal.message }, { headers: { "Cache-Control": "no-store" } });
    }
    const report = stored ? updateVirusTotalReport(stored, { ...virusTotal, source: stored.artifact.virusTotal?.source || virusTotal.source }) : undefined;
    let warning: string | undefined;
    if (report) try { await updateReport(report); } catch (error) { warning = error instanceof Error ? error.message : "Hasil belum tersimpan."; }
    return NextResponse.json({ virusTotal, report, warning }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ error: "Hasil VirusTotal belum dapat diperbarui. Periksa referensi laporan dan coba lagi." }, { status: 400 });
  }
}
