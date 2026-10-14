import { ArrowUpRight, Radar } from "lucide-react";
import type { ThreatIntelResult } from "@/lib/types";
import styles from "./virus-total.module.css";

// abuse.ch (MalwareBazaar, URLhaus, ThreatFox) and RDAP findings, styled like the VirusTotal panel.
export function ThreatIntelPanel({ result }: { result?: ThreatIntelResult }) {
  if (!result) return null;
  const mb = result.malwareBazaar, young = result.domains.filter(d => d.ageDays !== undefined && d.ageDays < 180);
  const known = Boolean(mb) || result.urlhaus.length > 0 || result.threatfox.length > 0;
  const tone = known ? styles.danger : young.length ? styles.caution : styles.clear;
  const badge = known ? "Tercatat berbahaya" : young.length ? "Domain baru" : result.hosts.length || mb === null ? "Tidak ada catatan" : "Tidak ada target";
  const link = (href?: string) => href ? <a href={href} target="_blank" rel="noopener noreferrer" aria-label="Lihat sumber"><ArrowUpRight size={13}/></a> : null;
  return <section className={styles.panel} aria-label="Intelijen ancaman">
    <div className={styles.heading}>
      <div className={styles.name}><Radar size={17} strokeWidth={1.5}/><h3>Intelijen ancaman</h3><span className={`${styles.badge} ${tone}`}>{badge}</span></div>
    </div>
    {mb && <p><b>MalwareBazaar:</b> file ini sudah dikenal sebagai malware{mb.family ? <> keluarga <b>{mb.family}</b></> : null}{mb.firstSeen ? `, pertama tercatat ${mb.firstSeen.slice(0, 10)}` : ""}. {link(mb.reference)}</p>}
    {!!(mb?.tags.length || mb?.vendors?.length) && <div className={styles.detections}>{[...(mb?.vendors ?? []), ...(mb?.tags ?? [])].slice(0, 8).map(t => <span key={t}>{t}</span>)}</div>}
    {!!result.urlhaus.length && <div className={styles.detections}>{result.urlhaus.map(u => <span key={u.target}><b>URLhaus</b>{u.target}{u.urlCount ? ` · ${u.urlCount} URL` : ""}{u.online ? ` · ${u.online} aktif` : ""} {link(u.reference)}</span>)}</div>}
    {!!result.threatfox.length && <div className={styles.detections}>{result.threatfox.map(t => <span key={t.term}><b>ThreatFox</b>{t.term}{t.family ? ` · ${t.family}` : ""}{t.confidence !== undefined ? ` · keyakinan ${t.confidence}%` : ""} {link(t.reference)}</span>)}</div>}
    {!!result.domains.length && <div className={styles.detections}>{result.domains.slice(0, 6).map(d => <span key={d.domain}><b>{d.ageDays !== undefined && d.ageDays < 180 ? "Domain baru" : "Domain"}</b>{d.domain}{d.ageDays !== undefined ? ` · ${d.ageDays} hari` : ""}</span>)}</div>}
    <p>{known ? "Indikator di atas sudah dilaporkan komunitas keamanan sebagai berbahaya. " : `Diperiksa ${result.hosts.length} server/domain dan hash file. `}Tidak tercatat bukan berarti aman: scam baru sering belum masuk database.</p>
    <div className={styles.meta}><span>Sumber: abuse.ch (MalwareBazaar, URLhaus, ThreatFox) dan RDAP</span><span>Diperiksa {new Date(result.checkedAt).toLocaleString("id-ID", {dateStyle: "medium", timeStyle: "short"})}</span></div>
  </section>;
}
