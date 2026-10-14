import { RadioTower } from "lucide-react";
import type { Report } from "@/lib/types";
import type { Endpoint } from "@/lib/endpoints";
import { hostOf, registrableDomain } from "@/lib/hosts";
import styles from "./virus-total.module.css";

const KIND: Record<string, string> = {telegram: "Bot Telegram", panel: "Panel web", ip: "Server IP langsung", ddns: "Domain dinamis (DDNS)", tunnel: "Tunnel", firebase: "Firebase", webhook: "Webhook", url: "URL", email: "Email"};
const SOURCE: Record<string, string> = {dex: "kode aplikasi", payload: "kode tersembunyi (payload)", resources: "resource", manifest: "manifest", exe: "isi program", dotnet: "string .NET"};
const where = (s: string) => s.startsWith("deobfuscated:") ? `disembunyikan (${s.slice(13)})` : s.startsWith("native:") ? `kode native (${s.slice(7)})` : SOURCE[s] || s;
const concealed = (e: Endpoint) => /^(?:deobfuscated|native):/.test(e.source);
const valid = (e: unknown): e is Endpoint => Boolean(e) && typeof (e as Endpoint).value === "string" && typeof (e as Endpoint).host === "string" && typeof (e as Endpoint).kind === "string" && typeof (e as Endpoint).source === "string";

// C2/exfiltration endpoints (metadata.endpoints from lib/endpoints.ts), with abuse.ch/RDAP hits for the same host inline.
// Addresses are shown as plain text, never as links.
export function EndpointPanel({report}: {report: Report}) {
  const raw = report.artifact.metadata.endpoints, list = Array.isArray(raw) ? raw.filter(valid).slice(0, 25) : [];
  if (!list.length) return null;
  const intel = report.artifact.threatIntel;
  const notes = (e: Endpoint) => {
    if (!intel) return [];
    const out: string[] = [], domain = registrableDomain(e.host), age = domain ? intel.domains.find(d => d.domain === domain && d.ageDays !== undefined) : undefined;
    if (intel.urlhaus.some(u => (u.kind === "host" ? u.target : hostOf(u.target)) === e.host)) out.push("tercatat URLhaus");
    const fox = intel.threatfox.find(t => t.term === e.host); if (fox) out.push(`tercatat ThreatFox${fox.family ? ` (${fox.family})` : ""}`);
    if (age) out.push(`domain berumur ${age.ageDays} hari`);
    return out;
  };
  const rows = list.map(e => ({e, notes: notes(e)})), known = rows.some(r => r.notes.some(n => n.startsWith("tercatat")));
  const hidden = list.some(concealed), direct = list.some(e => e.kind === "ip" || e.kind === "ddns" || e.kind === "tunnel");
  const tone = known ? styles.danger : hidden || direct || list.some(e => e.kind === "telegram" || e.kind === "webhook") ? styles.caution : "";
  const badge = known ? "Tercatat berbahaya" : hidden ? "Sengaja disembunyikan" : direct ? "Koneksi langsung" : `${list.length} alamat`;
  const app = report.kind === "apk" ? "aplikasi" : "program";
  return <section className={styles.panel} aria-label="Jalur komunikasi ke pelaku">
    <div className={styles.heading}>
      <div className={styles.name}><RadioTower size={17} strokeWidth={1.5}/><h3>Jalur komunikasi ke pelaku</h3><span className={`${styles.badge} ${tone}`}>{badge}</span></div>
    </div>
    <p>Alamat yang dipakai {app} ini untuk mengirim data atau menerima perintah dari penipu. {hidden ? "Sebagian alamat sengaja disembunyikan di dalam kode, tanda kuat ada yang ingin ditutupi. " : ""}{direct ? `Server IP langsung atau domain dinamis sering dipakai untuk mengendalikan ${report.kind === "apk" ? "HP" : "perangkat"} korban dari jauh. ` : ""}Jangan membuka alamat-alamat ini.</p>
    <div className={styles.detections}>{rows.map(({e, notes}) => <span key={`${e.kind}:${e.value}`}><b>{KIND[e.kind] || e.kind}</b>{e.value} · {where(e.source)}{e.via ? ` · ${e.via}` : ""}{notes.length ? <strong className={notes.some(n => n.startsWith("tercatat")) ? styles.danger : styles.caution}> · {notes.join(" · ")}</strong> : null}</span>)}</div>
    <div className={styles.meta}><span>Ditemukan dari isi file tanpa menjalankannya</span><span>Alamat yang diunduh atau didekripsi saat {app} berjalan tidak terlihat, jadi daftar ini bisa belum lengkap</span></div>
  </section>;
}
