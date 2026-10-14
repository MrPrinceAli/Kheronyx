import { Activity, ArrowUpRight, Loader2, RefreshCw, ShieldCheck } from "lucide-react";
import type { SandboxResult, VirusTotalResult } from "@/lib/types";
import styles from "./virus-total.module.css";

const statusText = {
  not_configured: "Belum aktif", not_found: "Belum tercatat", pending: "Menunggu hasil",
  rate_limited: "Kuota tercapai", error: "Belum tersedia", completed: "Hasil tersedia",
};

// VirusTotal sandbox behaviour tags in plain Indonesian; unknown tags fall back to title case.
const TAGS: Record<string, string> = {
  SENDS_SMS: "Mengirim SMS", OBFUSCATED: "Kode disamarkan", REFLECTION: "Memuat kode secara dinamis", DETECT_DEBUG_ENVIRONMENT: "Mendeteksi debugger/emulator",
  PERSISTENCE: "Bertahan setelah restart", TELEPHONY: "Mengakses fungsi telepon", CHECKS_GPS: "Memeriksa lokasi GPS", RUNTIME_MODULES: "Memuat modul saat berjalan",
  LONG_SLEEPS: "Menunda aktivitas (menghindari analisis)", DIRECT_CPU_CLOCK_ACCESS: "Membaca jam CPU langsung (anti-analisis)", CALLS_WMI: "Memakai WMI Windows",
  SELF_DELETE: "Menghapus dirinya sendiri", SPREADER: "Mencoba menyebar", IDLE: "Diam tanpa aktivitas", CHECKS_HOSTNAME: "Memeriksa nama perangkat",
  CHECKS_NETWORK_ADAPTERS: "Memeriksa adaptor jaringan", CHECKS_USB_BUS: "Memeriksa perangkat USB", CHECKS_DISK_SPACE: "Memeriksa kapasitas disk (anti-sandbox)",
  CHECKS_MEMORY_AVAILABLE: "Memeriksa memori (anti-sandbox)", CHECKS_CPU_NAME: "Memeriksa nama CPU", CHECKS_BIOS: "Memeriksa BIOS (anti-VM)", CHECKS_PROCESSES: "Memeriksa proses yang berjalan",
  INSTALLS_APPS: "Memasang aplikasi lain", ACCESS_CONTACTS: "Mengakses kontak", RECORDS_AUDIO: "Merekam suara", TAKES_SCREENSHOTS: "Mengambil tangkapan layar",
  MACRO_CREATE_FILE: "Makro membuat file", MACRO_RUN_FILE: "Makro menjalankan file", MACRO_DOWNLOAD_URL: "Makro mengunduh dari internet", MACRO_POWERSHELL: "Makro menjalankan PowerShell",
  MACRO_ENVIRON: "Makro membaca variabel sistem", MACRO_WMI: "Makro memakai WMI", MACRO_ANTI_ANALYSIS: "Makro menghindari analisis", MACRO_COPY_FILE: "Makro menyalin file", MACRO_HIDE_APP: "Makro menyembunyikan jendela",
};
const VERDICTS: Record<string, string> = {MALWARE: "Malware", STEALER: "Pencuri data", TROJAN: "Trojan", BANKER: "Trojan perbankan", RANSOM: "Ransomware", RAT: "Kendali jarak jauh (RAT)", SPREADER: "Penyebar", PHISHING: "Phishing", ADWARE: "Adware", CLEAN: "Bersih menurut sandbox", PUP: "Program tidak diinginkan"};
const title = (t: string) => t.toLowerCase().split("_").filter(Boolean).map(w => w[0].toUpperCase() + w.slice(1)).join(" ");
const tagText = (t: string) => TAGS[t] || (t.startsWith("MACRO_") ? `Makro: ${title(t.slice(6)).toLowerCase()}` : title(t));
// Short Indonesian names for common MITRE ATT&CK techniques (Enterprise + Mobile); others keep VirusTotal's description.
const MITRE: Record<string, string> = {
  T1406: "Menyamarkan kode atau file", T1409: "Mengambil data aplikasi tersimpan", T1412: "Membaca SMS", T1426: "Mengumpulkan info perangkat", T1430: "Melacak lokasi",
  T1429: "Merekam suara", T1512: "Mengambil foto/video", T1418: "Mencari aplikasi terpasang", T1448: "Mengirim SMS berbayar", T1447: "Menghapus data perangkat",
  T1402: "Menjalankan diri saat perangkat dinyalakan", T1407: "Mengunduh kode baru saat berjalan", T1417: "Merekam ketikan/input", T1411: "Memunculkan form login palsu", T1414: "Membaca clipboard",
  T1421: "Melihat koneksi jaringan", T1422: "Membaca konfigurasi jaringan", T1424: "Melihat daftar proses", T1432: "Mengakses daftar kontak", T1433: "Mengakses riwayat panggilan",
  T1636: "Mengambil data pribadi pengguna", T1582: "Mengendalikan SMS", T1616: "Mengendalikan panggilan", T1624: "Berjalan otomatis saat ada kejadian", T1628: "Menyembunyikan jejak", T1629: "Melemahkan pertahanan",
  T1633: "Menghindari sandbox/emulator", T1437: "Komunikasi lewat protokol aplikasi", T1521: "Saluran komunikasi terenkripsi",
  T1071: "Komunikasi lewat protokol aplikasi (HTTP/DNS)", T1573: "Saluran komunikasi terenkripsi", T1095: "Komunikasi tanpa protokol aplikasi", T1105: "Mengunduh file atau alat tambahan",
  T1041: "Mengirim data lewat server pengendali", T1055: "Menyusup ke proses lain", T1059: "Menjalankan perintah/skrip", T1547: "Berjalan otomatis saat startup", T1053: "Tugas terjadwal",
  T1543: "Membuat/mengubah layanan sistem", T1562: "Melemahkan pertahanan", T1070: "Menghapus jejak", T1036: "Menyamar sebagai file/program lain", T1027: "Menyamarkan file atau informasi",
  T1497: "Menghindari sandbox/mesin virtual", T1622: "Mendeteksi debugger", T1056: "Merekam ketikan (keylogging)", T1113: "Mengambil tangkapan layar", T1115: "Membaca clipboard",
  T1555: "Mencuri password tersimpan", T1552: "Mencari kredensial tidak terlindungi", T1003: "Mencuri kredensial sistem", T1005: "Mengambil data lokal", T1082: "Mengumpulkan info sistem",
  T1083: "Menjelajah file dan folder", T1057: "Melihat daftar proses", T1012: "Membaca registry", T1112: "Mengubah registry", T1518: "Mencari software terpasang",
  T1016: "Membaca konfigurasi jaringan", T1033: "Mencari pengguna yang aktif", T1614: "Mencari lokasi sistem", T1620: "Memuat kode langsung ke memori", T1129: "Memuat modul bersama",
  T1106: "Memanggil API sistem langsung", T1140: "Membuka isi yang disandikan", T1047: "Memakai WMI", T1486: "Mengenkripsi data (ransomware)", T1490: "Menghalangi pemulihan sistem",
};
const SEV: Record<string, string> = {high: "tinggi", medium: "sedang", low: "rendah"};

function SandboxSection({ sandbox }: { sandbox: SandboxResult }) {
  const c = sandbox.counts, ran = sandbox.status === "completed";
  const facts = c ? [[c.dns, "lookup DNS"], [c.ip, "koneksi IP"], [c.http, "permintaan HTTP"], [c.processes, "proses dibuat"], [c.filesDropped, "file dibuat"]].filter(([n]) => n) as [number, string][] : [];
  return <div className={styles.sandbox}>
    <h4><Activity size={13}/>Perilaku saat dijalankan (sandbox VirusTotal)</h4>
    {!ran ? <p>{sandbox.status === "empty" ? "Belum pernah dijalankan di sandbox VirusTotal." : sandbox.message || "Data sandbox VirusTotal belum tersedia."}</p> : <>
      <p>Dicatat oleh sandbox milik VirusTotal saat mereka menjalankan file ini, bukan oleh Kheronyx.{facts.length ? ` Tercatat ${facts.map(([n, t]) => `${n} ${t}`).join(", ")}.` : ""}{sandbox.contacted.length ? ` ${sandbox.contacted.length} alamat tidak umum terpantau dihubungi (lihat daftar server di atas).` : c?.dns || c?.ip ? " Semua koneksi yang terpantau mengarah ke layanan umum (Google, Microsoft, dan sejenisnya)." : ""}</p>
      {!!(sandbox.verdicts.length || sandbox.tags.length) && <div className={styles.detections}>
        {sandbox.verdicts.map(v => <span key={`v-${v}`} className={v === "CLEAN" ? undefined : styles.alert}><b>Kesimpulan sandbox</b>{VERDICTS[v] || title(v)}</span>)}
        {sandbox.tags.map(t => <span key={t} title={t}>{tagText(t)}</span>)}
      </div>}
      {!!sandbox.mitre.length && <ul className={styles.mitre}>{sandbox.mitre.map(m => <li key={m.id} title={m.description}><code>{m.id}</code><span>{MITRE[m.id.split(".")[0]] || m.description}</span>{m.severity && SEV[m.severity] && <small>{SEV[m.severity]}</small>}</li>)}</ul>}
      {!!sandbox.highlights?.length && <ul className={styles.highlights}>{sandbox.highlights.map(h => <li key={h}>{h}</li>)}</ul>}
    </>}
  </div>;
}

export function VirusTotalPanel({ result, sandbox, ready, busy, onRefresh }: {
  result?: VirusTotalResult; sandbox?: SandboxResult; ready: boolean; busy: boolean; onRefresh: () => void;
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
    {sandbox && <SandboxSection sandbox={sandbox}/>}
    <div className={styles.meta}><span>{result.source === "file_upload" ? "File dikirim untuk pemindaian" : "Reputasi berdasarkan SHA-256"}</span>{result.analysedAt && <span>Hasil {new Date(result.analysedAt).toLocaleString("id-ID", {dateStyle:"medium", timeStyle:"short"})}</span>}</div>
  </section>;
}
