// PDF behavior heuristics: auto-run JavaScript, /Launch and embedded programs, forms posting to outside servers,
// phishing lures (English + Indonesian) pointing at throwaway hosting/shorteners/form builders, and "one big button"
// documents. Inputs come from the raw token scan (lib/extract.ts pdfTokens, incl. inflated object streams) and pdf.js
// (text, link annotations, JS actions, attachments). Links are only classified by name; nothing is opened or resolved.
import type { Behavior } from "./behaviors";
import { impersonatedBrand, type Lookalike } from "./brands";
import { BENIGN, DDNS, TUNNEL, hostOf, ipv4, publicHost, publicIpv4, under } from "./hosts";
export type PdfLink = {url: string; page: number; cover?: number};
export type PdfFacts = {
  pages?: number; text: string; links: PdfLink[]; autoJs: string[]; js: string; acroForm: boolean; locked: boolean; parsed: boolean;
  attachments: {filename: string; size: number; head?: string}[];
};
const SHORTENER = ["bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "is.gd", "v.gd", "cutt.ly", "rebrand.ly", "s.id", "shorturl.at", "shorturl.asia", "ow.ly", "rb.gy", "tiny.cc", "t.ly", "buff.ly", "qrco.de", "short.io", "bl.ink", "lnkd.in", "shorte.st", "adf.ly", "x.gd", "urlz.fr", "clck.ru", "u.to", "tny.im", "lnk.bio", "linktr.ee", "heylink.me", "bit.do", "soo.gd", "tiny.one", "surl.li", "gg.gg"];
const FREE_HOST = ["vercel.app", "netlify.app", "pages.dev", "workers.dev", "github.io", "web.app", "firebaseapp.com", "glitch.me", "onrender.com", "herokuapp.com", "000webhostapp.com", "weebly.com", "weeblysite.com", "wixsite.com", "wixstudio.io", "blogspot.com", "webflow.io", "framer.website", "framer.app", "godaddysites.com", "square.site", "carrd.co", "notion.site", "r2.dev", "surge.sh", "replit.app", "repl.co", "fly.dev", "translate.goog", "sites.google.com", "storage.googleapis.com", "firebasestorage.googleapis.com", "blob.core.windows.net", "s3.amazonaws.com", "web.core.windows.net", "azureedge.net", "cprapid.com", "mybluehost.me", "atwebpages.com", "freewebhostmost.com", "yolasite.com", "jimdosite.com", "strikingly.com", "mystrikingly.com", "codepen.io", "jsfiddle.net", "backblazeb2.com", "digitaloceanspaces.com", "ipfs.io", "dweb.link", "cloudflare-ipfs.com", "nftstorage.link", "w3s.link", "fleek.co", "pinata.cloud", "4everland.link"];
const FORMS = ["forms.gle", "forms.office.com", "forms.cloud.microsoft", "jotform.com", "typeform.com", "formstack.com", "wufoo.com", "cognitoforms.com", "123formbuilder.com", "forms.zohopublic.com", "formspree.io", "getform.io", "tally.so", "paperform.co", "formsite.com", "surveyheart.com", "zfrmz.com"];
const SHARING = ["dropbox.com", "dropboxusercontent.com", "mediafire.com", "mega.nz", "wetransfer.com", "we.tl", "sendspace.com", "4shared.com", "files.fm", "gofile.io", "pixeldrain.com", "transfer.sh", "drive.google.com", "1drv.ms", "onedrive.live.com", "sharepoint.com", "box.com", "app.box.com", "cdn.discordapp.com", "filetransfer.io", "smash.gg", "terabox.com"];
// Cheap/abused TLDs common in phishing kits (a hint, never proof on its own).
const TLD = /\.(?:top|xyz|click|online|site|icu|buzz|cyou|sbs|cfd|rest|gq|tk|ml|cf|ga|zip|mov|lol|quest|bond|monster|country|kim|men|loan|win|bid|date|review|host|su|cam|beauty|hair|skin|makeup|boats|autos|yachts|mom|pics|lat|live|support|work|fit|info|best|today|digital)$/;
// Strong lures: credential/account actions or "open this document" calls to action (EN/ID plus a few common EU phrasings).
const STRONG: RegExp[] = [
  /\bverify (?:your )?(?:account|identity|email|mailbox|information|details)\b/, /\bconfirm (?:your )?(?:account|identity|password|details|information)\b/, /\bpassword (?:has |will )?(?:expire|expired|expiring)\b/,
  /\b(?:update|re-?validate|unlock|reactivate|restore) (?:your )?(?:account|payment|billing|mailbox|password)\b/, /\baccount (?:has been |will be |is )?(?:suspended|locked|limited|disabled|deactivated|on hold)\b/,
  /\bunusual (?:sign-?in|login|activity)\b/, /\b(?:sign|log) ?in to (?:view|access|download|open)\b/,
  /\b(?:view|open|access|review) (?:the |your |this )?(?:full |complete |secure |shared |encrypted |protected |attached )?(?:document|file|pdf|invoice|message|proposal|statement|attachment|fax|voicemail)s?\b/,
  /\bshared (?:a|the|an) (?:document|file|folder) with you\b/, /\byou(?: have)? (?:received|been sent) an? (?:secure |new |encrypted |shared )?(?:document|file|message|fax|voicemail)\b/,
  /\b(?:e-?sign(?:ature)?|signature) (?:request|required)\b/, /\bdocusign\b/, /\bclaim (?:your )?(?:prize|reward|refund|gift|bonus)\b/, /\btax refund\b/, /\byou(?: have)? won\b/,
  /\bverifikasi (?:akun|data|identitas|rekening)\b/, /\bkonfirmasi (?:akun|data|identitas|pembayaran|rekening)\b/, /\bakun (?:anda )?(?:akan )?(?:diblokir|dinonaktifkan|ditangguhkan|terkunci|dibekukan)\b/,
  /\bperbarui (?:data|akun|informasi)\b/, /\b(?:lihat|buka) (?:dokumen|file|berkas|tagihan|faktur)\b/, /\bmasukkan (?:pin|otp|kata sandi|password)\b/,
  /\bselamat,? anda (?:mendapatkan|memenangkan|terpilih)\b/, /\bklaim (?:hadiah|saldo|bonus|cashback)\b/, /\bundian berhadiah\b/, /\bpemenang undian\b/,
  /\b(?:dokument|vorschlag|rechnung) (?:anzeigen|öffnen|ansehen)\b/, /\bver (?:el )?documento\b/, /\bvisualizza(?:re)? (?:il )?documento\b/, /\b(?:voir|consulter) (?:le )?document\b/, /\bvisualizar (?:o )?documento\b/,
];
// Weak lures: payment topics and brands that scams imitate (count only together, or with a suspicious host).
const WEAK = /\b(?:invoice|payment|receipt|remittance|wire transfer|overdue|purchase order|quotation|tagihan|pembayaran|faktur|kuitansi|bukti transfer|rekening|hadiah|undian|bca|bri|bni|mandiri|bsi|cimb|danamon|permata|jenius|livin|brimo|dana|ovo|gopay|shopeepay|linkaja|paypal|netflix|dhl|fedex|usps|jne|j&t|kurir|paket|resi|pajak|djp|bpjs|pln|onedrive|sharepoint|office ?365|microsoft 365|adobe (?:acrobat|sign|document cloud)|dropbox|wallet|bank|click (?:here|below|the (?:button|link))|klik (?:di ?sini|tautan|link|tombol)|download (?:the |your )?(?:document|file|invoice)|unduh (?:dokumen|file|berkas))\b/g;
// Lure words inside link host names/paths ("account-bookings.vercel.app/#invoice"), matched without word boundaries.
const URL_WEAK = /secure|login|log-in|signin|sign-in|verif|account|update|billing|webmail|wallet|invoice|payment|receipt|booking|docusign|sharepoint|onedrive|office365|microsoft365/g;
const WATERMARK = ["tcpdf.org", "camscanner.com", "camscanner.net", "intsig.com", "tapscanner.com", "thegrizzlylabs.com", "smallpdf.com", "ilovepdf.com", "pdf24.org", "sejda.com", "pdfescape.com", "cutepdf.com", "pdfforge.org", "nitropdf.com", "foxit.com", "wondershare.com", "docscanner.app", "scanner-pro.com"];
const RISKY_FILE = /\.(?:exe|scr|com|pif|cpl|msi|msp|dll|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|lnk|jar|apk|reg|sh|iso|img|vhdx?|application|appref-ms|url|scf|chm|xll|one)$/i;
const ARCHIVE = /\.(?:zip|rar|7z|cab|gz|tgz|tar|ace|arj|xz|bz2|z)$/i;
const SUSPICIOUS_JS = /app\.launchURL|getURL|submitForm|exportDataObject|\blaunch\b|app\.openDoc|eval\s*\(|unescape|fromCharCode|spell\.|collab\.|media\.newPlayer|getIcon|util\.printf|app\.alert|SOAP\.|Net\.HTTP|XMLHttp|\\x[0-9a-f]{2}|%u[0-9a-f]{4}/i;
export function linkRisk(url: string): {strong?: string; sharing?: string; brand?: Lookalike} {
  const host = hostOf(url); if (!host) return {};
  const path = url.replace(/^[a-z][\w+.-]*:\/\/[^/?#]*/i, "");
  if (/^[a-z][\w+.-]*:\/\/[^/?#]*@/i.test(url)) return {strong: "URL berisi '@' (alamat asli disamarkan)"};
  if (ipv4(host)) return publicIpv4(host) ? {strong: "alamat IP langsung"} : {};
  // Look-alike domain of a bank/e-wallet/marketplace/courier/government brand (official domains never match).
  const brand = impersonatedBrand(host, path.replace(/[?#].*$/, "")); if (brand) return {strong: `domain meniru ${brand.brand}: ${brand.reason}`, brand};
  if (under(host, SHORTENER)) return {strong: "penyingkat URL (tujuan asli disembunyikan)"};
  if (under(host, FORMS) || /^docs\.google\.com$/.test(host) && /\/forms\//.test(url)) return {strong: "layanan pembuat formulir"};
  if (under(host, TUNNEL) || under(host, DDNS)) return {strong: "tunnel/DNS dinamis"};
  if (under(host, FREE_HOST) || /(?:^|\.)ipfs\./i.test(host) || /^\/ipfs\/[a-z0-9]{20,}/i.test(path)) return {strong: "hosting gratis/IPFS"};
  if (host.includes("xn--")) return {strong: "domain punycode (huruf mirip)"};
  if (TLD.test(host)) return {strong: `TLD .${host.split(".").pop()} yang sering dipakai situs phishing`};
  if (under(host, SHARING)) return {sharing: "layanan berbagi file"};
  return {};
}
const decode = (u: string) => {try {return decodeURIComponent(u);} catch {return u;}};
const safeRisk = (url: string): ReturnType<typeof linkRisk> => {try {return linkRisk(url);} catch {return {};}};
// External = http(s) to a public host outside the big-vendor allowlist.
export const externalLink = (url: string) => {const host = /^https?:\/\//i.test(url) ? hostOf(url) : ""; return Boolean(host) && (ipv4(host) ? publicIpv4(host) : publicHost(host)) && !under(host, BENIGN);};
export function pdfBehaviors(f: PdfFacts, raw: {launch: string[]; submit: string[]; openJs: string[]; uris: string[]; files: string[]; uriTokens: number}): Behavior[] {
  const out: Behavior[] = [], add = (id: string, name: string, severity: Behavior["severity"], evidence: string[]) => {const e = evidence.filter(Boolean).map(x => x.slice(0, 220)); if (e.length) out.push({id, name, severity, evidence: e.slice(0, 6)});};
  // Auto-run JavaScript: document-level (OpenAction, catalog /AA, named scripts) or page-open actions. Form-only scripts in a
  // fillable form (no suspicious API) are medium; anything else high.
  const auto = [...f.autoJs, ...f.parsed ? [] : raw.openJs];
  if (auto.length) {
    const bad = auto.find(s => SUSPICIOUS_JS.test(s));
    add("pdf_autorun_js", "JavaScript berjalan otomatis saat dokumen dibuka", bad || !f.acroForm ? "high" : "medium", [`${auto.length} skrip otomatis (OpenAction/AA/skrip dokumen): ${auto[0].replace(/\s+/g, " ").slice(0, 160)}`, bad ? `memakai fungsi berisiko: ${bad.match(SUSPICIOUS_JS)![0]}` : "", f.acroForm && !bad ? "dokumen berupa formulir; skrip bisa milik formulir resmi" : ""]);
  }
  if (raw.launch.length) add("pdf_launch", "Dokumen mencoba menjalankan program/file (/Launch)", "high", raw.launch.slice(0, 3));
  const files = [...f.attachments.map(x => ({name: x.filename, size: x.size, head: x.head})), ...raw.files.filter(n => !f.attachments.some(x => x.filename === n)).map(name => ({name, size: 0, head: undefined as string | undefined}))];
  const program = files.filter(x => RISKY_FILE.test(x.name) || x.head?.startsWith("MZ")), archive = files.filter(x => !program.includes(x) && (ARCHIVE.test(x.name) || /^(?:PK\x03\x04|Rar!|7z\xbc\xaf)/.test(x.head || "")));
  if (program.length || archive.length) add("pdf_embedded_exe", program.length ? "Program/skrip tersembunyi sebagai lampiran PDF" : "Arsip terlampir di dalam PDF", program.length ? "high" : "medium", [...program, ...archive].slice(0, 4).map(x => `lampiran "${x.name.slice(0, 80)}"${x.size ? ` (${x.size} byte)` : ""}${x.head?.startsWith("MZ") ? ", isinya program Windows (MZ)" : ""}`));
  const submits = raw.submit.filter(externalLink);
  if (submits.length) add("pdf_submit_form", "Formulir mengirim data ke server luar", "medium", submits.slice(0, 3).map(u => `data formulir dikirim ke ${u}`));
  // Links: pdf.js link annotations, or raw /URI strings when pdf.js could not parse the document.
  // Invisible (zero-area) links, PDF-generator/scanner-app watermarks and a footer link repeated on every page are not "buttons".
  const all = [...f.links, ...f.parsed ? [] : raw.uris.map(url => ({url, page: 0} as PdfLink))].filter(l => externalLink(l.url) && !under(hostOf(l.url), WATERMARK));
  const pagesOf = (url: string) => new Set(all.filter(l => l.url === url).map(l => l.page)).size, links = all.filter(l => !(l.cover !== undefined && l.cover < 0.001) && !((f.pages ?? 0) >= 2 && pagesOf(l.url) >= f.pages!));
  const unique = [...new Map(links.map(l => [l.url, l])).values()], risky = unique.map(l => ({...l, risk: safeRisk(l.url)}));
  // Look-alike brand links count wherever they sit (also invisible or repeated footer links): the address itself is the lure.
  // Visible ones are also "bad" links below (linkRisk marks them strong).
  const looks = [...new Map(all.map(l => [l.url, l])).values()].map(l => ({...l, brand: safeRisk(l.url).brand})).filter((l): l is PdfLink & {brand: Lookalike} => Boolean(l.brand)).slice(0, 20);
  const brands = [...new Set(looks.map(l => l.brand.brand))].slice(0, 3).join(", ");
  const body = f.text.replace(/\s+/g, " ").trim(), urls = unique.map(l => decode(l.url).toLowerCase()).join(" ").slice(0, 8000), lower = `${body} ${urls.replace(/[/?#=&._-]+/g, " ")}`.toLowerCase().slice(0, 40000);
  const strong = STRONG.map(re => lower.match(re)?.[0]).filter((x): x is string => Boolean(x)), weak = [...new Set([...lower.match(WEAK) || [], ...(urls.match(URL_WEAK) || []).map(w => w.replace(/-/g, ""))])];
  const short = (f.pages ?? 1) <= 3, cover = Math.max(0, ...unique.map(l => l.cover ?? 0)), chars = body.replace(/[^\p{L}\p{N}]/gu, "").length, linkOnly = unique.length > 0 && short && (chars < 200 || cover >= 0.3);
  // Strong lure + any outside link: medium (high with a throwaway host). Payment/brand words alone are everyday business
  // vocabulary, so they only count next to a throwaway host or in a link-only document.
  const bad = risky.filter(l => l.risk.strong || l.risk.sharing && strong.length), lure = strong.length > 0 || weak.length >= 2 && short && (bad.length > 0 || linkOnly), shown = (l: typeof risky[number]) => `${l.url.slice(0, 120)}${l.risk.strong || l.risk.sharing ? ` (${l.risk.strong || l.risk.sharing})` : ""}`;
  // A strong look-alike link (cheap TLD, free hosting, punycode, lure word) is phishing on its own; any look-alike raises it to high.
  if (lure && unique.length || looks.some(l => l.brand.severity === "high")) add("pdf_phishing", `Umpan phishing: dokumen membujuk membuka tautan login/pembayaran${brands ? ` (meniru ${brands})` : ""}`, bad.length || looks.length ? "high" : "medium", [
    strong.length || weak.length ? `kata umpan: ${[...strong, ...weak].slice(0, 6).join(", ")}` : "", looks.length ? `tautan ke domain peniru merek ${brands}: ${looks.slice(0, 3).map(l => l.url.slice(0, 120)).join(", ")}` : "",
    bad.length || !looks.length ? `tautan: ${(bad.length ? bad : risky).slice(0, 3).map(shown).join(", ")}` : "", bad.length ? "tautan mengarah ke layanan yang sering dipakai halaman phishing sekali pakai" : ""]);
  if (looks.length) add("brand_domain", `Domain meniru merek resmi (${brands})`, looks.some(l => l.brand.severity === "high") ? "high" : "medium", looks.slice(0, 4).map(l => `${l.url.slice(0, 120)} meniru ${l.brand.brand}: ${l.brand.reason}${l.page ? ` (halaman ${l.page})` : ""}`));
  // "One big button": little or no text, a few pages, and an outside link (often a page-sized link over an image).
  if (linkOnly) add("pdf_link_only", "Dokumen hanya berisi tombol/link ke luar", "medium", [
    chars < 200 ? `hampir tanpa teks (${chars} karakter) di ${f.pages ?? "?"} halaman` : "", cover >= 0.3 ? `satu tautan menutupi ${Math.round(Math.min(cover, 1) * 100)}% halaman (seluruh halaman menjadi tombol)` : "", `tautan: ${risky.slice(0, 2).map(shown).join(", ")}`]);
  if (f.locked) add("pdf_locked", "Dokumen dikunci kata sandi (isi tidak dapat diperiksa)", raw.uriTokens ? "medium" : "low", [raw.uriTokens ? `${raw.uriTokens} tautan terenkripsi di dalam dokumen: pola umum untuk lolos dari pemindai email (kata sandi dikirim terpisah)` : "isi dokumen terenkripsi; e-statement bank juga sering dikunci kata sandi"]);
  return out;
}
// Hosts behind the document's outside links (suspicious first), for metadata.campaign.hosts / threat-intel lookups.
export function pdfHosts(urls: string[], max = 10) {
  const ext = [...new Set(urls.filter(externalLink))], score = (u: string) => {const r = safeRisk(u); return r.brand ? -1 : r.strong ? 0 : r.sharing ? 1 : 2;};
  return [...new Set(ext.sort((a, b) => score(a) - score(b)).map(hostOf))].slice(0, max);
}
