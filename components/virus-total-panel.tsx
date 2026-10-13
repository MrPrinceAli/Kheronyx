import { ArrowUpRight, Loader2, RefreshCw, ShieldCheck } from "lucide-react";
import type { VirusTotalResult } from "@/lib/types";
import styles from "./virus-total.module.css";

const statusText = {
  not_configured: "Belum aktif", not_found: "Belum tercatat", pending: "Menunggu hasil",
  rate_limited: "Kuota tercapai", error: "Belum tersedia", completed: "Hasil tersedia",
};

export function VirusTotalPanel({ result, ready, busy, onRefresh }: {
  result?: VirusTotalResult; ready: boolean; busy: boolean; onRefresh: () => void;
}) {
  if (!result) return null;
  const stats = result.status === "completed" ? result.stats : undefined;
  const scored = stats ? stats.malicious + stats.suspicious + stats.harmless + stats.undetected : 0;
  const flagged = stats ? stats.malicious + stats.suspicious : 0;
  const tone = stats?.malicious ? styles.danger : flagged || !scored ? styles.caution : styles.clear;
  return <section className={styles.panel} aria-label="Hasil VirusTotal">
    <div className={styles.heading}>
      <div className={styles.name}><ShieldCheck size={17} strokeWidth={1.5}/><h3>VirusTotal</h3><span className={`${styles.badge} ${tone}`}>{statusText[result.status]}</span></div>
      <div className={styles.actions}>
        {ready && <button type="button" className="button button-light" aria-label="Perbarui hasil" disabled={busy} onClick={onRefresh}>{busy ? <Loader2 size={13} className="spin"/> : <RefreshCw size={13}/>}<span>Perbarui hasil</span></button>}
        {result.status !== "not_configured" && <a href={result.url} target="_blank" rel="noopener noreferrer" aria-label="Lihat laporan di VirusTotal"><ArrowUpRight size={17}/></a>}
      </div>
    </div>
    {stats ? <>
      <div className={styles.score}><strong className={tone}>{flagged}<span> / {scored}</span></strong><span>engine menandai file<br/><small>{stats.malicious} malicious · {stats.suspicious} suspicious</small></span></div>
      <p>{scored ? "Nol deteksi bukan jaminan aman. Undetected berarti engine tidak memberi kesimpulan tentang keamanan file." : "Tidak ada engine yang memberikan penilaian untuk tipe file ini."}</p>
      {!!result.detections?.length && <div className={styles.detections}>{result.detections.map((d, i) => <span key={`${d.engine}-${i}`}><b>{d.engine}</b>{d.result || d.category}</span>)}</div>}
    </> : <p>{result.message}</p>}
    <div className={styles.meta}><span>{result.source === "file_upload" ? "File dikirim untuk pemindaian" : "Reputasi berdasarkan SHA-256"}</span>{result.analysedAt && <span>Hasil {new Date(result.analysedAt).toLocaleString("id-ID", {dateStyle:"medium", timeStyle:"short"})}</span>}</div>
  </section>;
}
