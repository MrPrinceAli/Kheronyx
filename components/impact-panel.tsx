import { Ban, Bot, CreditCard, Download, EyeOff, FileCode2, FileLock2, KeyRound, Landmark, MessageSquareWarning, Nfc, PhoneForwarded, Send, ShieldAlert, Smartphone, UserRound, VenetianMask, Wifi } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { Report } from "@/lib/types";
import styles from "./impact.module.css";

type Impact = {icon: LucideIcon; title: string; text: string; ids: string[]};
// Plain-language consequences for non-technical users, grouped from the analyzers' behavior ids.
const IMPACTS: Impact[] = [
  {icon: MessageSquareWarning, title: "Mencuri SMS dan kode OTP", text: "Bisa membaca semua SMS, termasuk kode OTP dari bank dan e-wallet. Penipu memakai kode itu untuk masuk ke akun Anda dan menguras saldo.", ids: ["sms_read", "otp_intercept", "sms_stealer", "notification_listener"]},
  {icon: Landmark, title: "Mengambil alih aplikasi bank", text: "Bisa \"melihat\" dan \"menekan\" layar seperti Anda, atau memunculkan halaman login palsu di atas aplikasi bank untuk mencuri PIN dan password.", ids: ["banking_trojan", "accessibility", "overlay", "keyboard"]},
  {icon: Send, title: "Mengirim SMS diam-diam", text: "Bisa mengirim SMS dari nomor Anda tanpa sepengetahuan Anda, misalnya menyebarkan link penipuan ke kontak atau menghabiskan pulsa.", ids: ["sms_send"]},
  {icon: PhoneForwarded, title: "Membelokkan panggilan telepon", text: "Bisa mengalihkan telepon masuk, termasuk telepon verifikasi dari bank, ke nomor milik penipu.", ids: ["call_forwarding"]},
  {icon: Nfc, title: "Menyalin kartu lewat NFC", text: "Bisa membaca kartu ATM atau e-money yang ditempelkan ke HP, lalu menyalurkannya ke penipu.", ids: ["nfc_relay"]},
  {icon: KeyRound, title: "Mencuri password dan akun", text: "Bisa mencuri password tersimpan di browser, sesi login aplikasi chat, ketikan keyboard, isi clipboard, atau dompet kripto.", ids: ["credential_theft", "keylogger", "net_credential_theft", "net_keylogger", "net_stealer", "net_wallet_theft", "net_clipper", "net_clipboard"]},
  {icon: UserRound, title: "Mengambil data pribadi", text: "Bisa mengambil daftar kontak, riwayat telepon, lokasi, identitas perangkat, foto, rekaman suara, atau isi layar Anda.", ids: ["contacts", "call_log", "device_identifiers", "location", "camera_mic", "screen_capture", "screen_clipboard", "net_screenshot"]},
  {icon: Wifi, title: "Mengirim data curian ke penipu", text: "Data yang diambil dikirim langsung ke penipu, misalnya lewat bot Telegram, email, atau server tersembunyi.", ids: ["exfil_telegram", "exfil_webhook", "exfil_panel", "exfil_ip", "exfil_tunnel", "exfil_firebase", "exfil_email"]},
  {icon: Bot, title: "Bisa dikendalikan dari jauh", text: "Penipu bisa memberi perintah ke perangkat Anda dari jarak jauh, atau menyusupkan kode ke program lain.", ids: ["net_rat", "injection", "net_injection", "c2_socket"]},
  {icon: Download, title: "Memasang program jahat lain", text: "Setelah terpasang, bisa mengunduh atau memasang aplikasi dan program jahat tambahan tanpa Anda sadari.", ids: ["dropper", "install_apps", "dynamic_code", "hidden_payload", "download_execute", "net_download_exec", "net_reflective_load", "shell_exec", "overlay_pe"]},
  {icon: FileCode2, title: "Menjalankan program/skrip saat dibuka", text: "Begitu dokumen dibuka, bisa langsung menjalankan skrip, membuka program lain, atau membawa program tersembunyi sebagai lampiran.", ids: ["pdf_autorun_js", "pdf_launch", "pdf_embedded_exe"]},
  {icon: CreditCard, title: "Halaman login/pembayaran palsu", text: "Membujuk Anda menekan tautan atau tombol yang membuka halaman palsu, lalu meminta password, data kartu, PIN, atau OTP Anda.", ids: ["pdf_phishing", "pdf_link_only", "pdf_submit_form"]},
  {icon: EyeOff, title: "Bersembunyi dan sulit dihapus", text: "Bisa menyembunyikan ikonnya, aktif sendiri saat perangkat dinyalakan, atau meminta hak admin supaya sulit di-uninstall.", ids: ["hidden_icon", "device_admin", "boot_persistence", "persistence", "net_persistence", "requires_admin"]},
  {icon: FileLock2, title: "Mengunci file untuk tebusan", text: "Pola ransomware: file Anda bisa dikunci dan cadangannya dihapus, lalu Anda diminta membayar tebusan.", ids: ["file_encryption", "shadow_delete"]},
  {icon: VenetianMask, title: "Menyamar sebagai pihak resmi", text: "Mengaku sebagai bank, kurir, undangan, atau instansi resmi supaya Anda percaya lalu memasangnya.", ids: ["brand_impersonation", "lure_keywords", "signature_mismatch"]},
  {icon: Ban, title: "Sengaja menghindari pemeriksaan", text: "Isinya disamarkan atau dikunci agar sulit diperiksa. Ini umum pada aplikasi jahat, meski kadang juga dipakai aplikasi resmi.", ids: ["packer", "packed", "obfuscated_strings", "anti_analysis", "native_anti_analysis", "net_anti_analysis", "net_obfuscator", "net_defense_evasion", "encrypted_payload", "no_imports", "pdf_locked"]},
];
const RANK: Record<string, number> = {low: 0, medium: 1, high: 2, critical: 3};

export function ImpactPanel({report}: {report: Report}) {
  const behaviors = (report.artifact.metadata.behaviors as {id: string; severity: string}[] | undefined) ?? [];
  // Only capabilities the app itself plausibly uses: low/library-only findings would scare without reason.
  const strength = new Map(behaviors.filter(b => RANK[b.severity] >= 1).map(b => [b.id, RANK[b.severity]]));
  const impacts = IMPACTS.map(impact => ({...impact, level: Math.max(-1, ...impact.ids.map(id => strength.get(id) ?? -1))})).filter(i => i.level >= 0).sort((a, b) => b.level - a.level);
  const urgent = report.assessment.risk === "high" || report.assessment.risk === "critical";
  if (!impacts.length && !urgent) return null;
  const isApk = report.kind === "apk";
  return <section className={styles.panel} aria-label="Dampak bagi perangkat Anda">
    <div className={styles.heading}><Smartphone size={17} strokeWidth={1.5}/><h3>Apa yang bisa dilakukan file ini ke {isApk ? "HP" : "perangkat"} Anda?</h3></div>
    <p className={styles.lead}>Penjelasan sederhana dari kemampuan yang ditemukan di dalam file. Ini kemampuan, belum tentu semuanya sudah terjadi.</p>
    {!!impacts.length && <div className={styles.grid}>{impacts.map(({icon: Icon, title, text, level}) => <div key={title} className={`${styles.item} ${level >= 2 ? styles.severe : ""}`}><span className={styles.icon}><Icon size={16} strokeWidth={1.6}/></span><div><strong>{title}</strong><p>{text}</p></div></div>)}</div>}
    {urgent && <div className={styles.help}>
      <strong><ShieldAlert size={15}/>Sudah terlanjur {isApk ? "memasang" : "membuka"}?</strong>
      <ol>
        {isApk ? <><li>Aktifkan mode pesawat atau matikan internet dan Wi-Fi.</li><li>Buka Setelan → Aplikasi, cabut izin admin perangkatnya jika ada, lalu uninstall aplikasi tersebut.</li></> : <><li>Putuskan perangkat dari internet.</li><li>Jalankan pemindaian antivirus penuh, atau minta bantuan teknisi tepercaya.</li></>}
        <li>Segera hubungi call center resmi bank atau e-wallet Anda untuk memblokir rekening atau kartu.</li>
        <li>Dari perangkat lain yang aman, ganti password email, bank, dan media sosial, lalu aktifkan verifikasi dua langkah.</li>
        <li>Laporkan ke <a href="https://aduankonten.id" target="_blank" rel="noopener noreferrer">aduankonten.id</a> dan peringatkan kontak Anda agar tidak membuka file yang sama.</li>
      </ol>
    </div>}
  </section>;
}
