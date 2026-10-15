import { Activity, ArrowUpRight, Bug, Loader2, Microscope } from "lucide-react";
import type { TriageResult } from "@/lib/types";
import panel from "./virus-total.module.css";
import styles from "./triage.module.css";

const statusText: Record<TriageResult["status"], string> = {pending: "Menunggu sandbox", running: "Sedang dijalankan", reported: "Hasil tersedia", failed: "Gagal", skipped: "Dilewati", rate_limited: "Kuota tercapai"};
// Plain Indonesian for common Triage signatures (by label, then by name pattern); others keep Triage's English name.
const SIGS: Record<string, string> = {
  accessibility_service_usage: "Memakai layanan Aksesibilitas (bisa membaca dan menekan layar)", accessibility_settings: "Meminta izin Aksesibilitas diaktifkan",
  queries_installed_applications: "Mencari aplikasi terpasang (target halaman login palsu)", reads_sms_message: "Membaca isi SMS", queries_phone_number: "Membaca nomor telepon",
  reads_operator_info: "Membaca info operator seluler", acquires_wake_lock: "Menjaga perangkat tetap aktif", foreground_persistence: "Berjalan terus di latar depan",
  requests_disable_battery_optimization: "Meminta pengecualian penghemat baterai (agar tetap berjalan)", registers_broadcast: "Memantau kejadian sistem saat berjalan",
  scheduled_task_mobile: "Menjadwalkan tugas otomatis", crypto_api: "Memakai fungsi enkripsi", checks_root_detection: "Memeriksa apakah perangkat di-root",
  clipboard_data: "Membaca isi clipboard", debugger_check: "Mendeteksi debugger", check_emulator_cpuinfo: "Memeriksa CPU (deteksi emulator)", check_emulator_memory: "Memeriksa memori (deteksi emulator)",
  browser_user_data_harvesting: "Mengambil data browser (password, cookie)", email_user_data_harvesting: "Mengambil data aplikasi email", access_outlook_profiles: "Mengakses profil Outlook",
  reg_checks_country_code: "Memeriksa lokasi/negara komputer", fw_startup_file: "Membuat file di folder Startup (berjalan otomatis)", uses_vbs_compiler: "Memakai compiler VBS untuk menjalankan kode",
  external_ip_lookup: "Mencari alamat IP publik korban", file_drive_discovery: "Mendaftar drive yang terhubung", powershell_modify_defender_setting: "Mengubah pengaturan Windows Defender lewat PowerShell",
  unsigned_apk: "APK tidak ditandatangani", unsigned_pe: "Program tidak ditandatangani", codesign_digest_mismatch: "Tanda tangan tidak cocok dengan isi file",
  browser_information_discovery: "Mengintai data browser", system_language_discovery: "Memeriksa bahasa sistem", checks_tcpip_hostname: "Membaca nama komputer dan domain",
};
const SIG_PATTERNS: [RegExp, string][] = [
  [/^Family: (.+)$/i, "Terdeteksi sebagai famili $1"], [/payload$/i, "Payload malware dikenali"], [/Removes its main activity from the application launcher/i, "Menyembunyikan ikon aplikasi"],
  [/Loads dropped Dex\/Jar/i, "Memuat kode DEX/JAR yang diunduh saat berjalan"], [/obfuscate APK/i, "Menyamarkan struktur APK"], [/Requests dangerous framework permissions/i, "Meminta izin berbahaya"],
  [/Suspicious use of (?:SetThreadContext|WriteProcessMemory)/i, "Menyusup ke proses lain"], [/Suspicious use of SetWindowsHookEx/i, "Memasang hook keyboard/mouse"], [/EnumeratesProcesses/i, "Melihat daftar proses"],
  [/Drops file in/i, "Membuat file di folder sistem"], [/Checks computer location/i, "Memeriksa lokasi komputer"], [/Declares broadcast receivers/i, "Memantau kejadian sistem (receiver)"],
];
const sigText = (s: {name: string; label?: string}) => (s.label && SIGS[s.label]) || SIG_PATTERNS.reduce<string | null>((hit, [re, text]) => hit ?? (re.test(s.name) ? s.name.replace(re, text) : null), null) || s.name;
const TAGS: Record<string, string> = {banker: "Trojan perbankan", rat: "Kendali jarak jauh (RAT)", infostealer: "Pencuri data", stealer: "Pencuri data", spyware: "Mata-mata", keylogger: "Perekam ketikan", trojan: "Trojan", persistence: "Bertahan di perangkat", defense_evasion: "Menghindari deteksi", evasion: "Menghindari analisis", discovery: "Mengintai sistem", collection: "Mengumpulkan data", credential_access: "Mengakses kredensial", execution: "Menjalankan kode", impact: "Merusak/mengunci data", privilege_escalation: "Menaikkan hak akses", stealth: "Bersembunyi", ransomware: "Ransomware", miner: "Penambang kripto", loader: "Pemuat malware", dropper: "Penyusup program lain", backdoor: "Pintu belakang", botnet: "Botnet", phishing: "Phishing"};
const tone = (score: number) => score >= 8 ? panel.danger : score >= 6 ? panel.caution : panel.clear;
const verdict = (score: number) => score >= 8 ? "berbahaya" : score >= 6 ? "mencurigakan" : score >= 2 ? "cenderung aman" : "tidak ada ancaman terdeteksi";
// Waiting results go stale if the worker never scheduled the next check (e.g. killed before submitting).
export const triageWaiting = (t?: TriageResult) => Boolean(t && (t.nextCheck || t.status === "pending" || t.status === "running") && Date.now() - Date.parse(t.submittedAt) < 40 * 60_000);
const SAMPLE = /^\d{6}-[a-z0-9]{6,16}$/;

export function TriagePanel({result}: {result?: TriageResult}) {
  if (!result) return null;
  const waiting = triageWaiting(result), stale = !waiting && (result.status === "pending" || result.status === "running");
  const link = result.sampleId && SAMPLE.test(result.sampleId) ? `https://tria.ge/${result.sampleId}` : undefined;
  const score = result.status === "reported" ? result.score : undefined;
  const configs = result.configs ?? [], sigs = (result.signatures ?? []).slice(0, 8), tags = (result.tags ?? []).filter(t => !t.startsWith("family:")).slice(0, 10);
  const badge = waiting ? "" : result.status === "reported" && score !== undefined ? tone(score) : result.status === "failed" || result.status === "rate_limited" || stale ? panel.caution : "";
  return <section className={panel.panel} aria-label="Sandbox Tria.ge">
    <div className={panel.heading}>
      <div className={panel.name}><Microscope size={17} strokeWidth={1.5}/><h3>Sandbox Tria.ge</h3><span className={`${panel.badge} ${badge}`}>{stale ? "Pemantauan terhenti" : statusText[result.status]}</span></div>
      {link && <div className={panel.actions}><a className={styles.link} href={link} target="_blank" rel="noopener noreferrer" aria-label="Lihat di tria.ge"><span>Lihat di tria.ge</span><ArrowUpRight size={15}/></a></div>}
    </div>
    {waiting ? <p className={styles.waiting}><Loader2 size={13} className="spin"/><span>{result.status === "rate_limited" ? result.message : "Menunggu sandbox…"} Hasil biasanya 3–10 menit, Anda boleh menutup halaman; laporan diperbarui otomatis.</span></p>
      : stale ? <p>Pemantauan sandbox terhenti sebelum hasil diterima.{link ? " Hasilnya dapat dilihat langsung di tria.ge." : ""}</p>
      : result.status !== "reported" ? <p>{result.message || "Sandbox Tria.ge belum memberikan hasil."}</p> : <>
      {score !== undefined && <div className={panel.score}><strong className={tone(score)}>{score}<span> / 10</span></strong><span>Skor Tria.ge: {verdict(score)}<br/><small>{result.family?.length ? `Famili: ${result.family.join(", ")}` : "Famili malware tidak dikenali"}</small></span></div>}
      <p>Dijalankan oleh sandbox publik Tria.ge, bukan oleh Kheronyx.{result.contacted?.length ? ` ${result.contacted.length} alamat tidak umum terpantau dihubungi (lihat daftar server di atas).` : ""}{result.message ? ` ${result.message}` : ""} Skor rendah atau tanpa koneksi bukan jaminan aman.</p>
      {!!(result.family?.length || tags.length) && <div className={panel.detections}>
        {result.family?.map(f => <span key={`f-${f}`} className={panel.alert}><b>Famili</b>{f}</span>)}
        {tags.map(t => <span key={t} title={t}>{TAGS[t] || t.replace(/_/g, " ")}</span>)}
      </div>}
      {!!configs.length && <div className={panel.sandbox}>
        <h4><Bug size={13}/>Konfigurasi malware yang diekstrak</h4>
        {configs.map((c, i) => <div key={`${c.family}-${i}`} className={styles.config}>
          <strong>{c.family}{c.version ? ` · versi ${c.version}` : ""}{c.botnet ? ` · botnet ${c.botnet}` : ""}{c.campaign ? ` · kampanye ${c.campaign}` : ""}</strong>
          {!!c.c2.length && <ul>{c.c2.map(v => <li key={v}><small>C2</small><code>{v}</code></li>)}</ul>}
          {!!c.credentials?.length && <ul>{c.credentials.map((x, j) => <li key={j}><small>{(x.protocol || "akun").toUpperCase()}</small><code>{[x.host, x.port ? `port ${x.port}` : "", x.username ? `user ${x.username}` : "", x.password ? `password ${x.password}` : ""].filter(Boolean).join(" · ")}</code></li>)}</ul>}
          {!!c.keys?.length && <ul>{c.keys.map((k, j) => <li key={j}><small>KUNCI</small><code>{[k.kind, k.key, k.value].filter(Boolean).join(" · ")}</code></li>)}</ul>}
          {!!c.mutex?.length && <ul>{c.mutex.map(m => <li key={m}><small>MUTEX</small><code>{m}</code></li>)}</ul>}
        </div>)}
        <p className={styles.note}>Alamat ditampilkan sebagai teks, jangan dibuka. Password dan kunci disamarkan.</p>
      </div>}
      {!!sigs.length && <div className={panel.sandbox}>
        <h4><Activity size={13}/>Perilaku yang ditandai</h4>
        <ul className={panel.mitre}>{sigs.map(s => <li key={s.label || s.name} title={s.description || s.name}><code>{s.score !== undefined ? `${s.score}/10` : "—"}</code><span>{sigText(s)}</span>{s.ttp?.[0] && <small>{s.ttp[0]}</small>}</li>)}</ul>
      </div>}
    </>}
    {result.reassessedAt && <p className={styles.updated}>Penilaian risiko di atas sudah diperbarui dengan bukti sandbox ini.</p>}
    <div className={panel.meta}>
      <span>{result.reused ? "Memakai analisis publik yang sudah ada (tanpa mengunggah ulang)" : result.sampleId ? "File dikirim ke Tria.ge atas persetujuan Anda" : "Sandbox pihak ketiga"}</span>
      <span>Sampel di Tria.ge dapat dilihat publik</span>
      {result.platforms?.length ? <span>{result.platforms.join(", ")}</span> : null}
      <span>Diperiksa {new Date(result.checkedAt).toLocaleString("id-ID", {dateStyle: "medium", timeStyle: "short"})}</span>
    </div>
  </section>;
}
