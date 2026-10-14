import { useState } from "react";
import { Check, Copy, Fingerprint, RadioTower, UserX } from "lucide-react";
import type { Report } from "@/lib/types";
import type { Endpoint } from "@/lib/endpoints";
import { hostOf, registrableDomain } from "@/lib/hosts";
import panel from "./virus-total.module.css";
import styles from "./trace.module.css";

const KIND: Record<string, string> = {telegram: "Bot Telegram", panel: "Panel web", ip: "Server IP langsung", ddns: "Domain dinamis (DDNS)", tunnel: "Tunnel", firebase: "Firebase", webhook: "Webhook", url: "URL", email: "Email"};
// Labels when the file is judged malicious; neutral wording otherwise, so legitimate developers are never called attackers.
const TAG: Record<string, string> = {telegram: "BOT PELAKU", email: "EMAIL PELAKU", url: "URL TERKAIT"};
const SOURCE: Record<string, string> = {dex: "kode aplikasi", payload: "kode tersembunyi (payload)", resources: "resource", manifest: "manifest", exe: "isi program", dotnet: "string .NET"};
const where = (s: string) => s.startsWith("deobfuscated:") ? `disembunyikan (${s.slice(13)})` : s.startsWith("native:") ? `kode native (${s.slice(7)})` : SOURCE[s] || s;
const concealed = (e: Endpoint) => e.source.startsWith("deobfuscated:");
const valid = (e: unknown): e is Endpoint => Boolean(e) && typeof (e as Endpoint).value === "string" && typeof (e as Endpoint).host === "string" && typeof (e as Endpoint).kind === "string" && typeof (e as Endpoint).source === "string";
const strings = (v: unknown) => Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
// "C=DE, ST=Frankfurt, O=..., CN=..., emailAddress=..." -> {C: "DE", ...}
const subject = (s: string) => Object.fromEntries(s.split(/,\s*(?=[A-Za-z.]+=)/).map(p => [p.slice(0, p.indexOf("=")), p.slice(p.indexOf("=") + 1)]).filter(([k, v]) => k && v));

function CopyValue({value}: {value: string}) {
  const [done, setDone] = useState(false);
  return <button type="button" className={styles.copy} aria-label={`Salin ${value}`} title="Salin" onClick={() => navigator.clipboard?.writeText(value).then(() => {setDone(true); setTimeout(() => setDone(false), 1400);}).catch(() => {})}>{done ? <Check size={12}/> : <Copy size={12}/>}</button>;
}
function Row({tag, label, value, note, danger}: {tag: string; label: string; value: string; note?: string; danger?: boolean}) {
  return <div className={styles.row}>
    <span className={`${styles.tag} ${danger ? styles.danger : ""}`}>{tag}</span>
    <div className={styles.body}><small>{label}</small><code>{value}</code>{note && <em>{note}</em>}</div>
    <CopyValue value={value}/>
  </div>;
}

// Everything that points at the operator: C2/exfiltration endpoints (metadata.endpoints, with abuse.ch/RDAP hits inline),
// Telegram bot/chat ids, the signer identity the author typed into the certificate, its fingerprint, the package name and
// malware family. Addresses are plain text, never links.
export function EndpointPanel({report}: {report: Report}) {
  const m = report.artifact.metadata as Record<string, unknown>, intel = report.artifact.threatIntel;
  const list = Array.isArray(m.endpoints) ? m.endpoints.filter(valid).slice(0, 25) : [];
  const campaign = (m.campaign ?? {}) as Record<string, unknown>, bots = strings(campaign.telegramBots), chats = strings(campaign.chatIds);
  const cert = (m.signing as {certificates?: {subject?: string; sha256?: string; validFrom?: string}[]} | undefined)?.certificates?.[0];
  const signer = (m.authenticode as {signer?: string} | undefined)?.signer;
  const pkg = typeof (m.manifest as {package?: unknown} | undefined)?.package === "string" ? (m.manifest as {package: string}).package : "";
  const family = intel?.malwareBazaar?.family || intel?.threatfox.find(t => t.family)?.family || intel?.malwareBazaar?.tags.find(t => !/^(?:apk|exe|pdf|signed|unsigned|dropped|32|64|elf)$/i.test(t));
  const hits = Boolean(intel?.malwareBazaar) || Boolean(intel?.urlhaus.length) || Boolean(intel?.threatfox.length);
  const suspect = report.assessment.risk === "high" || report.assessment.risk === "critical" || hits;
  if (!list.length && !(suspect && (cert || signer || bots.length || chats.length))) return null;

  const notes = (e: Endpoint) => {
    if (!intel) return [];
    const out: string[] = [], domain = registrableDomain(e.host), d = domain ? intel.domains.find(x => x.domain === domain) : undefined;
    if (intel.urlhaus.some(u => (u.kind === "host" ? u.target : hostOf(u.target)) === e.host)) out.push("tercatat URLhaus");
    const fox = intel.threatfox.find(t => t.term === e.host); if (fox) out.push(`tercatat ThreatFox${fox.family ? ` (${fox.family})` : ""}`);
    if (d?.ageDays !== undefined) out.push(`domain berumur ${d.ageDays} hari${d.registrar ? `, registrar ${d.registrar}` : ""}`);
    return out;
  };
  const app = report.kind === "apk" ? "aplikasi" : "program", hidden = list.some(concealed);
  const id = cert?.subject ? subject(cert.subject) : {}, debug = /Android Debug/i.test(cert?.subject || "");
  const person = [id.CN, id.O && id.O !== id.CN ? id.O : "", id.OU && !/^android$/i.test(id.OU) ? id.OU : ""].filter(Boolean).join(" · ");
  const place = [id.L, id.ST, id.C].filter((v, i, a) => v && a.indexOf(v) === i).join(", ");
  const email = id.emailAddress || id.E;
  return <section className={panel.panel} aria-label="Jejak pelaku">
    <div className={panel.heading}>
      <div className={panel.name}>{suspect ? <UserX size={17} strokeWidth={1.5}/> : <RadioTower size={17} strokeWidth={1.5}/>}<h3>{suspect ? "Jejak pelaku" : "Server yang dihubungi"}</h3>{suspect && <span className={`${panel.badge} ${panel.danger}`}>Data pelaku</span>}</div>
    </div>
    <p>{suspect ? `Alamat server dan identitas yang dipakai pembuat ${app} ini. Data ini berguna untuk laporan ke pihak berwenang, bank, atau Telegram. Identitas di sertifikat diisi sendiri oleh pembuatnya, jadi bisa palsu, tetapi tetap bisa menghubungkan file-file dari pelaku yang sama.` : `Alamat yang dihubungi ${app} ini. Belum ada tanda berbahaya, jadi ini belum tentu milik penipu.`}{hidden ? " Sebagian alamat sengaja disembunyikan di dalam kode." : ""}</p>
    {!!list.length && <div className={styles.group}><h4>{suspect ? "Server pelaku" : "Server"}</h4>{list.map(e => {
      const n = notes(e), tag = suspect ? TAG[e.kind] ?? "SERVER PELAKU" : "SERVER";
      return <Row key={`${e.kind}:${e.value}`} tag={tag} danger={suspect && e.kind !== "url"} label={`${KIND[e.kind] || e.kind} · ${where(e.source)}${e.via ? ` · ${e.via}` : ""}`} value={e.value} note={n.join(" · ") || undefined}/>;
    })}</div>}
    {suspect && <div className={styles.group}><h4><Fingerprint size={13}/>Identitas pelaku</h4>
      {person && <Row tag="NAMA DI SERTIFIKAT" danger label={debug ? "Sertifikat debug bawaan Android: pembuatnya tidak memakai identitas sendiri" : "Diisi sendiri oleh pembuat aplikasi, bisa palsu"} value={person}/>}
      {email && <Row tag="EMAIL PELAKU" danger label="Email di sertifikat penanda tangan" value={email}/>}
      {place && !debug && <Row tag="LOKASI DI SERTIFIKAT" label="Bisa palsu" value={place}/>}
      {signer && <Row tag="PENANDA TANGAN" danger label="Authenticode program Windows" value={signer}/>}
      {cert?.sha256 && <Row tag="SIDIK JARI PELAKU" danger label={`SHA-256 sertifikat${cert.validFrom ? `, dibuat ${cert.validFrom.slice(0, 10)}` : ""}: sama berarti pembuat sama`} value={cert.sha256}/>}
      {bots.map(b => <Row key={b} tag="BOT PELAKU" danger label="ID bot Telegram (token disamarkan)" value={b}/>)}
      {chats.map(c => <Row key={c} tag="CHAT PELAKU" danger label="chat_id Telegram penerima data curian" value={c}/>)}
      {pkg && <Row tag="NAMA PAKET" label="Identitas aplikasi di Android" value={pkg}/>}
      {family && <Row tag="KELUARGA MALWARE" danger label="Menurut abuse.ch" value={family}/>}
    </div>}
    <div className={panel.meta}><span>Ditemukan dari isi file tanpa menjalankannya</span><span>Alamat yang diunduh atau didekripsi saat {app} berjalan tidak terlihat</span></div>
  </section>;
}
