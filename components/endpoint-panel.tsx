import { useState } from "react";
import { Check, ChevronDown, Copy, Fingerprint, RadioTower, UserX } from "lucide-react";
import type { Report, SandboxContact } from "@/lib/types";
import type { Endpoint } from "@/lib/endpoints";
import { edgeNetwork, hostOf, registrableDomain } from "@/lib/hosts";
import panel from "./virus-total.module.css";
import styles from "./trace.module.css";
import { Collapsible, chevronClass } from "./collapsible";
import { EdgeLogo } from "./edge-logo";

const KIND: Record<string, string> = {telegram: "Bot Telegram", panel: "Panel web", ip: "Server IP langsung", ddns: "Domain dinamis (DDNS)", tunnel: "Tunnel", firebase: "Firebase", webhook: "Webhook", deaddrop: "Sumber konfigurasi jarak jauh (dead drop)", phishing: "Domain peniru merek", url: "URL", email: "Email"};
// Labels when the file is judged malicious; neutral wording otherwise, so legitimate developers are never called attackers.
const TAG: Record<string, string> = {telegram: "BOT PELAKU", email: "EMAIL PELAKU", deaddrop: "SUMBER KONFIG PELAKU", url: "URL TERKAIT"};
const SUSPECT_KIND: Record<string, string> = {deaddrop: "Sumber konfigurasi pelaku (dead drop)"};
type Config = {algorithm: string; via: string; keySource: string; plaintext: string};
const config = (v: unknown): v is Config => Boolean(v) && ["algorithm", "via", "keySource", "plaintext"].every(k => typeof (v as Record<string, unknown>)[k] === "string");
const SOURCE: Record<string, string> = {dex: "kode aplikasi", payload: "kode tersembunyi (payload)", resources: "resource", manifest: "manifest", exe: "isi program", dotnet: "string .NET"};
const where = (s: string) => s.startsWith("deobfuscated:") ? `disembunyikan (${s.slice(13)})` : s.startsWith("native:") ? `kode native (${s.slice(7)})` : SOURCE[s] || s;
const concealed = (e: Endpoint) => e.source.startsWith("deobfuscated:");
// Look-alike brand domain (lib/brands.ts) attached to an endpoint, validated because metadata is stored JSON.
const lookalike = (e: Endpoint) => e.brand && typeof e.brand.brand === "string" && typeof e.brand.reason === "string" ? e.brand : undefined;
const valid = (e: unknown): e is Endpoint => Boolean(e) && typeof (e as Endpoint).value === "string" && typeof (e as Endpoint).host === "string" && typeof (e as Endpoint).kind === "string" && typeof (e as Endpoint).source === "string";
// Strongest endpoints come first (lib/endpoints.ts sorts them); the rest stay behind "Lihat semua".
const VISIBLE = 2;
type Contacted = SandboxContact & {by: string[]};
const strings = (v: unknown) => Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
// "C=DE, ST=Frankfurt, O=..., CN=..., emailAddress=..." -> {C: "DE", ...}
const subject = (s: string) => Object.fromEntries(s.split(/,\s*(?=[A-Za-z.]+=)/).map(p => [p.slice(0, p.indexOf("=")), p.slice(p.indexOf("=") + 1)]).filter(([k, v]) => k && v));

function CopyValue({value}: {value: string}) {
  const [done, setDone] = useState(false);
  return <button type="button" className={styles.copy} aria-label={`Salin ${value}`} title="Salin" onClick={() => navigator.clipboard?.writeText(value).then(() => {setDone(true); setTimeout(() => setDone(false), 1400);}).catch(() => {})}>{done ? <Check size={12}/> : <Copy size={12}/>}</button>;
}
function Row({tag, label, value, note, danger, edge}: {tag: string; label: string; value: string; note?: string; danger?: boolean; edge?: string}) {
  // Notes are red only when they are bad news (known malicious host, newly registered domain, connection seen in a sandbox of a suspect file).
  const alarming = note ? /tercatat|domain baru|koneksi terpantau|konfigurasi malware/.test(note) : false;
  return <div className={styles.row}>
    <span className={`${styles.tag} ${danger ? styles.danger : edge ? styles.shared : ""}`}>{tag}</span>
    <div className={styles.body}><small>{label}</small><code>{value}</code>{note && <em className={alarming ? "" : styles.calm}>{note}</em>}</div>
    {edge && <EdgeLogo provider={edge} className={styles.edge}/>}
    <CopyValue value={value}/>
  </div>;
}

// Everything that points at the operator: C2/exfiltration endpoints (metadata.endpoints, with abuse.ch/RDAP hits inline),
// Telegram bot/chat ids, the signer identity the author typed into the certificate, its fingerprint, the package name and
// malware family. Addresses are plain text, never links.
export function EndpointPanel({report}: {report: Report}) {
  const [showAll, setShowAll] = useState(false), [showOthers, setShowOthers] = useState(false);
  const m = report.artifact.metadata as Record<string, unknown>, intel = report.artifact.threatIntel;
  const list = Array.isArray(m.endpoints) ? m.endpoints.filter(valid).slice(0, 25) : [];
  // Hosts/IPs the VirusTotal and Tria.ge sandboxes saw the file contact at runtime (noise-filtered server-side), merged
  // per host/IP with the sandboxes that saw them.
  const contact = (c: SandboxContact) => Boolean(c) && (typeof c.host === "string" || typeof c.ip === "string");
  const sandbox = report.artifact.sandbox, triage = report.artifact.triage, tReady = triage?.status === "reported";
  const contacted: Contacted[] = [];
  for (const [list, by] of [[sandbox?.status === "completed" && Array.isArray(sandbox.contacted) ? sandbox.contacted : [], "VirusTotal"], [tReady && Array.isArray(triage.contacted) ? triage.contacted : [], "Tria.ge"]] as const) {
    for (const c of list.filter(contact).slice(0, 20)) {
      const old = contacted.find(x => c.host ? x.host === c.host : x.ip === c.ip && !x.host);
      if (old) { Object.assign(old, {...c, ...old}); if (!old.by.includes(by)) old.by.push(by); } else contacted.push({...c, by: [by]});
    }
  }
  // C2 servers and exfiltration accounts from malware configs Tria.ge extracted (strongest server evidence).
  const tConfigs = tReady && Array.isArray(triage.configs) ? triage.configs.filter(c => c && typeof c.family === "string" && Array.isArray(c.c2)).slice(0, 6) : [];
  const c2s = tConfigs.flatMap(c => [...c.c2.filter(v => typeof v === "string").map(value => ({value, family: c.family, detail: ""})), ...(Array.isArray(c.credentials) ? c.credentials : []).filter(x => typeof x?.host === "string").map(x => ({value: x.host!, family: c.family, detail: [x.protocol?.toUpperCase(), x.port ? `port ${x.port}` : "", x.username ? `akun ${x.username}` : ""].filter(Boolean).join(" · ")}))]).map(x => ({...x, host: hostOf(x.value)})).filter((x, i, a) => x.host && a.findIndex(y => y.value === x.value) === i).slice(0, 12);
  const configs = Array.isArray(m.decryptedConfig) ? m.decryptedConfig.filter(config).slice(0, 6) : [];
  const campaign = (m.campaign ?? {}) as Record<string, unknown>, bots = strings(campaign.telegramBots), chats = strings(campaign.chatIds);
  const cert = (m.signing as {certificates?: {subject?: string; sha256?: string; validFrom?: string}[]} | undefined)?.certificates?.[0];
  const signer = (m.authenticode as {signer?: string} | undefined)?.signer;
  const pkg = typeof (m.manifest as {package?: unknown} | undefined)?.package === "string" ? (m.manifest as {package: string}).package : "";
  const family = intel?.malwareBazaar?.family || intel?.threatfox.find(t => t.family)?.family || intel?.malwareBazaar?.tags.find(t => !/^(?:apk|exe|pdf|signed|unsigned|dropped|32|64|elf)$/i.test(t));
  const malware = family || (tReady && Array.isArray(triage.family) ? triage.family.join(", ") : "");
  const hits = Boolean(intel?.malwareBazaar) || Boolean(intel?.urlhaus.length) || Boolean(intel?.threatfox.length);
  const suspect = report.assessment.risk === "high" || report.assessment.risk === "critical" || hits || tReady && ((triage.score ?? 0) >= 8 || tConfigs.some(c => c.c2.length));
  if (!list.length && !configs.length && !contacted.length && !c2s.length && !(suspect && (cert || signer || bots.length || chats.length))) return null;

  const notes = (e: Endpoint) => {
    if (!intel) return [];
    const out: string[] = [], domain = registrableDomain(e.host), d = domain ? intel.domains.find(x => x.domain === domain) : undefined;
    // A URL hit on a shared dead-drop platform (pastebin, Drive...) only marks that exact document.
    if (intel.urlhaus.some(u => u.kind === "url" && e.kind === "deaddrop" ? u.target === e.value : (u.kind === "host" ? u.target : hostOf(u.target)) === e.host)) out.push("tercatat URLhaus");
    const fox = intel.threatfox.find(t => t.term === e.host); if (fox) out.push(`tercatat ThreatFox${fox.family ? ` (${fox.family})` : ""}`);
    if (d?.ageDays !== undefined) out.push(d.ageDays < 180 ? `domain baru: berumur ${d.ageDays} hari${d.registrar ? `, registrar ${d.registrar}` : ""}` : `domain lama (${Math.round(d.ageDays / 365)} tahun)`);
    return out;
  };
  const app = report.kind === "apk" ? "aplikasi" : "program", hidden = list.some(concealed), phishing = list.some(e => e.kind === "phishing" && lookalike(e));
  // Plain URLs are context, not servers: they get their own neutral list below the attacker servers.
  const seenBy = (host: string) => contacted.find(c => c.host === host || c.ip === host)?.by;
  const seen = (e: Endpoint) => Boolean(seenBy(e.host)), inConfig = (host: string) => c2s.some(x => x.host === host);
  const watched = (by: string[]) => suspect ? `koneksi terpantau saat dijalankan (sandbox ${by.join(" dan ")})` : `terhubung saat diuji (sandbox ${by.join(" dan ")})`;
  const statics = list.filter(e => e.kind !== "url" || seen(e) || inConfig(e.host)), others = list.filter(e => e.kind === "url" && !seen(e) && !inConfig(e.host));
  const configOnly = c2s.filter(x => !list.some(e => e.host === x.host));
  const extra = contacted.filter(c => !list.some(e => e.host === c.host || e.host === c.ip) && !c2s.some(x => x.host === c.host || x.host === c.ip));
  const detail = (c: SandboxContact) => [c.host && c.ip ? `IP ${c.ip}${edgeNetwork(c.ip) ? ` (${edgeNetwork(c.ip)})` : ""}` : "", c.port ? `port ${c.port}${c.protocol ? `/${c.protocol}` : ""}` : "", c.url || ""].filter(Boolean).join(" · ");
  // A bare CDN edge IP (Cloudflare, Fastly) is shared by many sites and hides the real server: neutral "IP SHARING"
  // with the provider's logo instead of an attacker-server tag.
  const sharedRow = (key: string, value: string, edge: string, how: string, n: string[]) => <Row key={key} tag="IP SHARING" edge={edge} label={`IP bersama milik ${edge}, dipakai banyak situs sekaligus · ${how}`} value={value} note={[`Server aslinya tersembunyi di balik ${edge} dan nama domainnya tidak terekam, jadi IP ini tidak menunjuk ke pelaku`, ...n].join(" · ")}/>;
  const row = (e: Endpoint) => {
    const n = notes(e), by = seenBy(e.host), brand = lookalike(e); if (inConfig(e.host)) n.unshift("juga ada di konfigurasi malware (Tria.ge)"); if (by) n.unshift(watched(by));
    const at = `${where(e.source)}${e.via ? ` · ${e.via}` : ""}`, edge = edgeNetwork(e.host);
    if (edge) return sharedRow(`${e.kind}:${e.value}`, e.value, edge, at, n);
    // Look-alike brand domains: red "DOMAIN PENIRU" when the report is suspect or the match itself is strong (cheap TLD, free
    // hosting, punycode, lure word, or a newly registered domain per RDAP); otherwise the neutral "DOMAIN MIRIP MEREK".
    if (e.kind === "phishing" && brand) {const strong = suspect || brand.severity === "high" || n.some(x => x.startsWith("domain baru")); return <Row key={`${e.kind}:${e.value}`} tag={strong ? "DOMAIN PENIRU" : "DOMAIN MIRIP MEREK"} danger={strong} label={`Meniru ${brand.brand} · ${brand.reason} · ${at}`} value={e.value} note={n.join(" · ") || undefined}/>;}
    return <Row key={`${e.kind}:${e.value}`} tag={suspect ? TAG[e.kind] ?? "SERVER PELAKU" : e.kind === "deaddrop" ? "SUMBER KONFIG" : "SERVER"} danger={suspect} label={`${(suspect && SUSPECT_KIND[e.kind]) || KIND[e.kind] || e.kind}${brand ? ` · meniru ${brand.brand}` : ""} · ${at}`} value={e.value} note={n.join(" · ") || undefined}/>;
  };
  const extracted = (x: typeof c2s[number]) => {
    const by = seenBy(x.host), n = notes({value: x.value, host: x.host, kind: "panel", source: "triage"}); if (by) n.unshift(watched(by));
    return <Row key={`config:${x.value}`} tag="KONFIG MALWARE" danger={suspect} label={`Dari konfigurasi malware yang diekstrak sandbox Tria.ge · ${x.family}${x.detail ? ` · ${x.detail}` : ""}`} value={x.value} note={n.join(" · ") || undefined}/>;
  };
  const runtime = (c: Contacted) => {
    const value = c.host || c.ip!, d = detail(c), n = notes({value, host: value, kind: c.host ? "panel" : "ip", source: "sandbox"}), edge = c.host ? undefined : edgeNetwork(value);
    if (edge) return sharedRow(`sandbox:${value}`, value, edge, `terhubung saat dijalankan di sandbox ${c.by.join(" dan ")}${d ? ` · ${d}` : ""}`, n);
    return <Row key={`sandbox:${value}`} tag={suspect ? "KONEKSI TERPANTAU" : "KONEKSI SAAT DIUJI"} danger={suspect} label={`Terpantau terhubung saat dijalankan di sandbox ${c.by.join(" dan ")}${d ? ` · ${d}` : ""}`} value={value} note={n.join(" · ") || undefined}/>;
  };
  // Strongest first: extracted malware-config C2s, static endpoints confirmed by a config or sandbox, sandbox-only
  // contacts, the rest, and shared CDN edge IPs last.
  const confirmed = (e: Endpoint) => seen(e) || inConfig(e.host), shared = (host: string) => Boolean(edgeNetwork(host)) && !inConfig(host);
  const own = statics.filter(e => !shared(e.host)), ownExtra = extra.filter(c => c.host || !shared(c.ip!));
  const servers = [...configOnly.map(extracted), ...own.filter(confirmed).map(row), ...ownExtra.map(runtime), ...own.filter(e => !confirmed(e)).map(row), ...extra.filter(c => !ownExtra.includes(c)).map(runtime), ...statics.filter(e => shared(e.host)).map(row)];
  const id = cert?.subject ? subject(cert.subject) : {}, debug = /Android Debug/i.test(cert?.subject || "");
  // The public AOSP test/platform keys (android@android.com, Mountain View) ship with the Android source: anyone can sign
  // with them, so their name/email/location say nothing about the author.
  const publicKey = !debug && /android@android\.com/i.test(cert?.subject || ""), borrowed = debug || publicKey;
  const person = [id.CN, id.O && id.O !== id.CN ? id.O : "", id.OU && !/^android$/i.test(id.OU) ? id.OU : ""].filter(Boolean).join(" · ");
  const place = [id.L, id.ST, id.C].filter((v, i, a) => v && a.indexOf(v) === i).join(", ");
  const email = id.emailAddress || id.E;
  return <section className={panel.panel} aria-label="Jejak pelaku">
    <div className={panel.heading}>
      <div className={panel.name}>{suspect ? <UserX size={17} strokeWidth={1.5}/> : <RadioTower size={17} strokeWidth={1.5}/>}<h3>{suspect ? "Jejak pelaku" : "Server yang dihubungi"}</h3>{suspect && <span className={`${panel.badge} ${panel.danger}`}>Data pelaku</span>}</div>
    </div>
    <p>{suspect ? `Alamat server dan identitas yang dipakai pembuat ${app} ini. Data ini berguna untuk laporan ke pihak berwenang, bank, atau Telegram. Identitas di sertifikat diisi sendiri oleh pembuatnya, jadi bisa palsu, tetapi tetap bisa menghubungkan file-file dari pelaku yang sama.` : `Alamat yang dihubungi ${app} ini. Belum ada tanda berbahaya, jadi ini belum tentu milik penipu.`}{hidden ? " Sebagian alamat sengaja disembunyikan di dalam kode." : ""}{phishing ? " Ada alamat yang memakai nama merek resmi (bank, e-wallet, marketplace, kurir, atau instansi) padahal bukan domain resminya: jangan buka alamat tersebut dan jangan masukkan data apa pun." : ""}</p>
    {suspect && <div className={styles.group}><h4><Fingerprint size={13}/>Identitas pelaku</h4>
      {person && <Row tag="NAMA DI SERTIFIKAT" danger label={debug ? "Sertifikat debug bawaan Android: pembuatnya tidak memakai identitas sendiri" : publicKey ? "Kunci uji publik AOSP yang bisa dipakai siapa saja: pembuatnya tidak memakai identitas sendiri" : "Diisi sendiri oleh pembuat aplikasi, bisa palsu"} value={person}/>}
      {email && !borrowed && <Row tag="EMAIL PELAKU" danger label="Email di sertifikat penanda tangan" value={email}/>}
      {place && !borrowed && <Row tag="LOKASI DI SERTIFIKAT" label="Bisa palsu" value={place}/>}
      {signer && <Row tag="PENANDA TANGAN" danger label="Authenticode program Windows" value={signer}/>}
      {cert?.sha256 && <Row tag={borrowed ? "SIDIK JARI SERTIFIKAT" : "SIDIK JARI PELAKU"} danger={!borrowed} label={borrowed ? "Kunci umum yang dipakai banyak pembuat aplikasi, jadi tidak bisa menghubungkan file ke pelaku yang sama" : `SHA-256 sertifikat${cert.validFrom ? `, dibuat ${cert.validFrom.slice(0, 10)}` : ""}: sama berarti pembuat sama`} value={cert.sha256}/>}
      {bots.map(b => <Row key={b} tag="BOT PELAKU" danger label="ID bot Telegram (token disamarkan)" value={b}/>)}
      {chats.map(c => <Row key={c} tag="CHAT PELAKU" danger label="chat_id Telegram penerima data curian" value={c}/>)}
      {pkg && <Row tag="NAMA PAKET" label="Identitas aplikasi di Android" value={pkg}/>}
      {malware && <Row tag="KELUARGA MALWARE" danger label={family ? "Menurut abuse.ch" : "Menurut sandbox Tria.ge"} value={malware}/>}
    </div>}
    {!!servers.length && <div className={styles.group}><h4>{suspect ? "Server pelaku" : "Server"}<span className={styles.count}>{servers.length}</span></h4>{servers.slice(0, VISIBLE)}
      {servers.length > VISIBLE && <><Collapsible open={showAll}>{servers.slice(VISIBLE)}</Collapsible>
        <button type="button" className={styles.more} aria-expanded={showAll} onClick={() => setShowAll(!showAll)}>{showAll ? "Tampilkan lebih sedikit" : `Lihat semua (${servers.length})`}<ChevronDown size={13} className={chevronClass(showAll)}/></button></>}
    </div>}
    {!!configs.length && <div className={styles.group}><h4>Konfigurasi terenkripsi yang berhasil dibuka<span className={styles.count}>{configs.length}</span></h4>
      {configs.map(c => <Row key={`${c.via}:${c.plaintext}`} tag={`DIDEKRIPSI (${c.algorithm.toUpperCase()})`} danger={suspect} label={`Dibuka dengan kunci yang tertanam di ${app} (${c.keySource}) · ${c.via}`} value={c.plaintext}/>)}
    </div>}
    {!!others.length && <div className={styles.group}>
      <button type="button" className={styles.more} aria-expanded={showOthers} onClick={() => setShowOthers(!showOthers)}>URL lain di dalam file ({others.length})<ChevronDown size={13} className={chevronClass(showOthers)}/></button>
      <Collapsible open={showOthers}><p className={styles.hint}>Alamat yang tertulis di dalam file tetapi tidak menunjukkan tanda server pelaku, misalnya situs dokumentasi atau layanan umum.</p>{others.map(e => <Row key={e.value} tag="URL TERKAIT" label={`URL · ${where(e.source)}${e.via ? ` · ${e.via}` : ""}`} value={e.value} note={notes(e).join(" · ") || undefined}/>)}</Collapsible>
    </div>}
    <div className={panel.meta}><span>Ditemukan dari isi file tanpa menjalankannya{contacted.length || c2s.length ? `; alamat bertanda koneksi terpantau atau konfigurasi malware dicatat oleh sandbox ${[...new Set([...contacted.flatMap(c => c.by), ...c2s.length ? ["Tria.ge"] : []])].join(" dan ")} yang menjalankan file ini (bukan Kheronyx)` : ""}</span><span>{configs.length ? `Konfigurasi terenkripsi dibuka statis dengan kunci bawaan ${app}; alamat yang diunduh saat berjalan tidak terlihat` : `Alamat yang diunduh atau didekripsi saat ${app} berjalan tidak terlihat`}</span></div>
  </section>;
}
