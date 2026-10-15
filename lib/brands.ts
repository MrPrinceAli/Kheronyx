// Look-alike ("brand-impersonating") domains: hosts that carry the name of a bank, e-wallet, marketplace, courier, government
// service or global platform without being one of its official domains (shopping.lazadamy.top, klik-bca.site,
// jne-resi.vercel.app, tokopedla.com, punycode homoglyphs). Hosts are only compared by name; nothing is resolved or opened.
// Pure (imports only lib/hosts.ts), bounded and never throws: impersonatedBrand() returns null on anything unexpected.
import { DOMAIN, PLATFORM, ipv4, registrableDomain, under } from "./hosts";
export type Lookalike = {brand: string; reason: string; severity: "medium" | "high"};
// [display name, distinctive tokens (matched inside any label, also with hyphens removed), short/generic tokens (only as a
// whole token or glued to a lure/companion word), official registrable domains, flags]. Flags: "c" = the official name under
// any country TLD is official too (lazada.sg, google.de); "g" = government service (every *.go.id host is official); "s" =
// global platform whose SDKs ship many subsidiary/partner hosts (tiktokpangle.us, alibabachengdun.com), so a plain name match
// needs a warning sign too (cheap TLD, free hosting, lure word, young domain); typos and homoglyphs still count alone.
// Only domains known to be official are listed; a brand without certain domains is left out rather than guessed.
type Brand = {name: string; sub: string[]; word: string[]; domains: string[]; cc: boolean; gov: boolean; sdk: boolean; names: Set<string>};
const RAW: [string, string, string, string, string?][] = [
  // E-commerce
  ["Lazada", "lazada", "", "lazada.co.id lazada.com lazada.sg lazada.com.my lazada.co.th lazada.vn lazada.com.ph lazcdn.com", "c"],
  ["Shopee", "shopee", "", "shopee.co.id shopee.com shopee.sg shopee.com.my shopee.ph shopee.vn shopee.co.th shopee.tw shopee.com.br shopeemobile.com shopeepay.co.id", "c"],
  ["Tokopedia", "tokopedia tokped", "", "tokopedia.com tokopedia.net tokopedia.link"],
  ["Bukalapak", "bukalapak", "", "bukalapak.com"],
  ["Blibli", "blibli", "", "blibli.com"],
  ["TikTok", "tiktok", "", "tiktok.com tiktokv.com tiktokcdn.com tiktokcdn-us.com tiktokcdn-eu.com tiktokshop.com tiktokglobalshop.com tiktokpangle.us tiktokpangle-cdn-us.com byteoversea.com ibytedtos.com", "cs"],
  ["Alibaba/AliExpress", "alibaba aliexpress", "", "alibaba.com alibaba-inc.com alibabacloud.com alibabagroup.com aliyun.com aliyuncs.com alicdn.com alipay.com aliexpress.com aliexpress.us aliexpress.ru 1688.com alibaba.net alibabachengdun.com", "cs"],
  // Banks
  ["BCA", "klikbca mybca bcamobile bankbca bcasyariah", "bca", "bca.co.id klikbca.com bcasyariah.co.id bcadigital.co.id"],
  ["BRI", "bankbri", "bri brimo", "bri.co.id"],
  ["BNI", "bankbni bnimobile bnidirect", "bni", "bni.co.id"],
  ["Bank Mandiri", "bankmandiri livinmandiri mandirilivin livinbymandiri mandirionline", "mandiri livin", "bankmandiri.co.id"],
  ["BTN", "bankbtn btnmobile", "btn", "btn.co.id"],
  ["BSI", "bankbsi bsimobile", "bsi", "bankbsi.co.id"],
  ["CIMB Niaga", "cimbniaga octomobile octoclicks", "cimb octo", "cimbniaga.co.id cimb.com"],
  ["Permata", "permatabank permatamobile", "permata", "permatabank.com permatabank.co.id"],
  ["Danamon", "danamon", "", "danamon.co.id"],
  ["OCBC", "ocbcnisp", "ocbc", "ocbc.id ocbcnisp.com ocbc.com", "c"],
  ["Maybank", "maybank", "", "maybank.co.id maybank.com maybank2u.com maybank2u.com.my maybank2u.com.sg", "c"],
  ["Bank Jago", "bankjago", "jago", "jago.com"],
  ["SeaBank", "seabank", "", "seabank.co.id", "c"],
  ["Bank Neo Commerce", "bankneo", "", "bankneocommerce.co.id"],
  ["Jenius/BTPN", "", "jenius btpn", "jenius.com btpn.com"],
  // E-wallets / fintech
  ["DANA", "", "dana", "dana.id"],
  ["OVO", "", "ovo", "ovo.id"],
  ["GoPay/Gojek", "gojek gopay", "", "gojek.com go-jek.com gopay.co.id gojekapi.com"],
  ["LinkAja", "linkaja", "", "linkaja.id"],
  ["Flip", "", "flip", "flip.id"],
  ["Akulaku", "akulaku", "", "akulaku.com"],
  ["Kredivo", "kredivo", "", "kredivo.com kredivo.id"],
  // Couriers
  ["JNE", "", "jne", "jne.co.id"],
  ["J&T Express", "jntexpress", "jnt", "jet.co.id"],
  ["SiCepat", "sicepat", "", "sicepat.com"],
  ["AnterAja", "anteraja", "", "anteraja.id"],
  ["Pos Indonesia", "posindonesia", "", "posindonesia.co.id"],
  ["Ninja Xpress", "ninjaxpress ninjavan", "", "ninjaxpress.co ninjavan.co"],
  ["Lion Parcel", "lionparcel", "", "lionparcel.com"],
  ["TIKI", "", "tiki", "tiki.id"],
  ["Wahana", "wahanaexpress", "wahana", "wahana.com"],
  // Government / utilities / telco
  ["PLN", "plnmobile", "pln", "pln.co.id"],
  ["BPJS", "bpjskesehatan bpjsketenagakerjaan bpjstk", "bpjs", "bpjs-kesehatan.go.id bpjsketenagakerjaan.go.id", "g"],
  ["DJP (Pajak)", "djponline", "djp pajak", "pajak.go.id", "g"],
  ["Dukcapil", "dukcapil", "", "kemendagri.go.id", "g"],
  ["Kominfo/Komdigi", "kominfo komdigi", "", "kominfo.go.id komdigi.go.id", "g"],
  ["Samsat", "esamsat", "samsat", "", "g"],
  ["Polri (tilang)", "etilang", "polri tilang", "polri.go.id", "g"],
  ["Kemenkes/SatuSehat", "kemenkes satusehat", "kemkes", "kemkes.go.id", "g"],
  ["Pegadaian", "pegadaian", "", "pegadaian.co.id"],
  ["Telkomsel", "telkomsel", "", "telkomsel.com"],
  ["IndiHome", "indihome", "", "indihome.co.id"],
  ["XL Axiata", "myxl xlaxiata", "", "xl.co.id"],
  ["Indosat", "indosat", "", "indosatooredoo.com indosat.com ioh.co.id"],
  // Global platforms
  ["WhatsApp", "whatsapp", "", "whatsapp.com whatsapp.net wa.me", "s"],
  ["Telegram", "telegram", "", "telegram.org telegram.me t.me telegra.ph telesco.pe telegram.dog tdesktop.com", "s"],
  ["Facebook/Meta", "facebook", "", "facebook.com facebook.net facebookmail.com fb.com fb.me fbcdn.net fbsbx.com meta.com messenger.com", "cs"],
  ["Instagram", "instagram", "", "instagram.com cdninstagram.com ig.me instagr.am", "cs"],
  ["Google", "google", "", "google.com googleapis.com gstatic.com googleusercontent.com googlevideo.com google-analytics.com googletagmanager.com googletagservices.com googlesyndication.com googleadservices.com googleblog.com googlesource.com googlecode.com googledrive.com googlemail.com googlegroups.com googlehosted.com googledomains.com googleoptimize.com googlezip.net googlecloudcommunity.com withgoogle.com google.dev goo.gl g.co youtube.com android.com", "cs"],
  ["Microsoft", "microsoft office365 hotmail", "outlook", "microsoft.com microsoftonline.com microsoftonline-p.com microsoft365.com microsoftstore.com microsoftazuread-sso.com msauth.net msftauth.net msftconnecttest.com live.com outlook.com office.com office365.com office.net sharepoint.com onedrive.com windows.net windows.com azure.com msn.com bing.com skype.com xbox.com hotmail.com", "cs"],
  ["Apple/iCloud", "icloud appleid", "apple", "apple.com icloud.com icloud-content.com me.com mac.com apple-cloudkit.com apple-mapkit.com apple-dns.net cdn-apple.com mzstatic.com aaplimg.com itunes.com apple.news", "cs"],
  ["PayPal", "paypal", "", "paypal.com paypal.me paypalobjects.com paypal-community.com", "c"],
  ["Netflix", "netflix", "", "netflix.com netflix.net nflxext.com nflximg.net nflximg.com nflxvideo.net nflxso.net", "c"],
  ["Steam", "steampowered steamcommunity", "steam", "steampowered.com steamcommunity.com steamstatic.com steamcontent.com steamusercontent.com steamgames.com steamchina.com steam-chat.com steamdeck.com"],
  ["Binance", "binance", "", "binance.com binance.org binance.us bnbstatic.com binance.vision"],
];
const BRANDS: Brand[] = RAW.map(([name, sub, word, domains, flags = ""]) => {const d = domains.split(" ").filter(Boolean); return {name, sub: sub.split(" ").filter(Boolean), word: word.split(" ").filter(Boolean), domains: d, cc: flags.includes("c"), gov: flags.includes("g"), sdk: flags.includes("s"), names: new Set(d.map(x => x.split(".")[0]))};});
const TOKENS = new Set(BRANDS.flatMap(b => [...b.sub, ...b.word])), OFFICIAL = BRANDS.flatMap(b => b.domains);
// CDN/edge infrastructure and unrelated businesses that share a brand-like name (Czech GoPay, Japanese PayPay, Vietnamese Tiki).
const IGNORE = ["akamaized.net", "akamaihd.net", "akamai.net", "akamaiedge.net", "edgekey.net", "edgesuite.net", "fastly.net", "fastlylb.net", "azureedge.net", "msecnd.net", "cloudflare.net", "alicdn.com", "alikunlun.com", "slatic.net", "susercontent.com", "gopay.cz", "gopay.com", "paypay.ne.jp", "tiki.vn"];
// Registries that need company/government paperwork: brand subsidiaries and partners live there, scammers rarely can
// (.scloud: Microsoft's air-gapped sovereign cloud, e.g. login.microsoftonline.microsoft.scloud in MSAL).
const RESTRICTED = new Set(["co.id", "go.id", "ac.id", "or.id", "mil.id", "sch.id", "net.id", "ponpes.id", "desa.id", "gov.uk", "ac.uk", "gov", "edu", "mil", "int", "scloud"]);
// Free hosting, serverless tenants, tunnels and dynamic DNS: anyone picks the subdomain. Cloud storage/compute tenants and
// project/blog hosts where brands run official pages (google.github.io, android-developers.blogspot.com, *.appspot.com)
// name brand assets legitimately, so a brand there needs another warning sign (lure word, punycode, young domain).
const TENANT = ["page.link", "amazonaws.com", "cloudfront.net", "azurewebsites.net", "blob.core.windows.net", "web.core.windows.net", "digitaloceanspaces.com", "backblazeb2.com", "github.io", "gitlab.io", "blogspot.com", "appspot.com", "wordpress.com"];
const FREE = [...PLATFORM.filter(d => !TENANT.includes(d)), "weeblysite.com", "wixstudio.io", "webflow.io", "framer.website", "framer.app", "godaddysites.com", "square.site", "carrd.co", "notion.site", "r2.dev", "surge.sh", "replit.app", "replit.dev", "fly.dev", "mybluehost.me", "cprapid.com", "freewebhostmost.com", "yolasite.com", "jimdosite.com", "strikingly.com", "mystrikingly.com", "my.canva.site", "zohosites.com"].sort((a, b) => b.length - a.length);
// Cheap/abused TLDs (and free Indonesian individual suffixes) common in phishing kits.
const RISKY_TLD = new Set("top xyz cc icu shop online site click buzz vip live club info tk ml ga cf gq work rest monster cyou sbs lol bond cfd store pw ws su fun bid win loan men date kim quest cam lat mom support help today best fit".split(" "));
const RISKY_SUFFIX = ["my.id", "biz.id"], ABUSED_CC = new Set(["tk", "ml", "ga", "cf", "gq", "cc", "pw", "ws", "su"]);
// Lure words (credential/payment/delivery) and neutral companions ("bca-mobile", "bri-id", "mybca") that make a short brand token
// a brand reference rather than a coincidence.
const RISK = new Set("login signin logon masuk verif verifikasi verify verification akun account klaim claim hadiah promo bonus tagihan resi otp update aktivasi blokir reward rewards undian cashback refund secure konfirmasi bayar pembayaran payment billing saldo voucher kupon poin gratis".split(" "));
const LURE = [...RISK].filter(w => w.length >= 5);
// API paths are full of "update", "account", "payment": only credential/prize/delivery words count there, and only to raise
// the severity of a host that already imitates a brand.
const PATH_RISK = new Set([...RISK].filter(w => !["update", "secure", "account", "billing", "payment", "voucher", "poin", "saldo", "bonus", "gratis", "masuk", "promo", "reward", "rewards"].includes(w)));
const GLUE = new Set([...RISK, ..."mobile mbanking ebanking ibank klik my online app apps apk bank web net pay card kartu care cs help support service layanan center official resmi express cek tracking track paket kurir digital info indonesia indo".split(" ")]);
const COMPANION = new Set([...GLUE, "id", "ind", "co", "m"]);
// Real words/services one typo away from a brand (Telegraf, PayPay, goggles).
const TYPO_SAFE = new Set(["paypay", "telegraf", "telegraph", "goggle", "goggles", "googly", "tiktak", "shopper"]);
const NO_TYPO = new Set(["telegram", "tokped"]);
const CONFUSABLE: Record<string, string> = {"а": "a", "в": "b", "е": "e", "ѕ": "s", "і": "i", "ї": "i", "ј": "j", "к": "k", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ɡ": "g", "ı": "i", "ł": "l", "ø": "o", "đ": "d", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x"};
// RFC 3492 decoding of one "xn--" label ("" when invalid); bounded by the 63-character label limit.
export function punycode(label: string) {
  const s = label.slice(4).toLowerCase(), d = s.lastIndexOf("-"), out: number[] = d > 0 ? [...s.slice(0, d)].map(c => c.charCodeAt(0)) : [];
  if (s.length > 59 || out.some(c => c > 127)) return "";
  let n = 128, i = 0, bias = 72, p = d > 0 ? d + 1 : 0;
  while (p < s.length) {
    const old = i; let w = 1;
    for (let k = 36; ; k += 36) {
      if (p >= s.length) return "";
      const c = s.charCodeAt(p++), digit = c >= 48 && c <= 57 ? c - 22 : c >= 97 && c <= 122 ? c - 97 : 36; if (digit > 35) return "";
      i += digit * w; const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias; if (digit < t) break; w *= 36 - t; if (w > 1e9 || i > 1e9) return "";
    }
    const len = out.length + 1; let delta = old === 0 ? Math.floor((i - old) / 700) : (i - old) >> 1, k = 0;
    delta += Math.floor(delta / len); while (delta > 455) {delta = Math.floor(delta / 35); k += 36;}
    bias = k + Math.floor(36 * delta / (delta + 38)); n += Math.floor(i / len); i %= len; if (n > 0x10ffff || out.length > 63) return "";
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}
// ASCII skeleton of a decoded IDN label: confusable Cyrillic/Greek letters mapped, accents stripped.
const skeleton = (s: string) => [...s.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase()].map(c => CONFUSABLE[c] ?? c).join("").replace(/[^a-z0-9-]/g, "");
// Visual look-alikes inside plain ASCII labels ("rn" for "m", "vv" for "w", 0/1 for o/l).
const homoglyph = (s: string) => s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/0/g, "o").replace(/1/g, "l");
// Damerau edit distance exactly 1 (substitution, insertion, deletion or adjacent swap).
function oneEdit(a: string, b: string) {
  if (a === b || Math.abs(a.length - b.length) > 1) return false;
  let i = 0; while (i < a.length && i < b.length && a[i] === b[i]) i++;
  if (a.length === b.length) return a.slice(i + 1) === b.slice(i + 1) || a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(i + 2) === b.slice(i + 2);
  return a.length > b.length ? a.slice(i + 1) === b.slice(i) : a.slice(i) === b.slice(i + 1);
}
// "cekresi", "loginverif": a remainder made only of lure/companion words (bounded DP).
function glue(s: string): boolean {
  if (!s) return true; if (s.length > 30) return false;
  const ok = [true]; for (let i = 1; i <= s.length; i++) {ok[i] = false; for (let j = Math.max(0, i - 12); j < i && !ok[i]; j++) ok[i] = ok[j] && GLUE.has(s.slice(j, i));}
  return ok[s.length];
}
// Short/generic token as a whole token ("bri-id", "pln-tagihan", "bri24") or glued to lure/companion words ("mybca", "loginbca").
function wordHit(label: string, tok: string): "" | "plain" | "companion" {
  const parts = label.split(/[^a-z]+/).filter(Boolean), digits = /\d/.test(label);
  if (parts.includes(tok)) return parts.some(p => p !== tok && (COMPANION.has(p) || TOKENS.has(p) || glue(p))) || digits ? "companion" : "plain";
  for (const p of parts) {const i = p.indexOf(tok); if (i >= 0 && p !== tok && glue(p.slice(0, i)) && glue(p.slice(i + tok.length))) return "companion";}
  return "";
}
type Hit = {brand: Brand; tok: string; how: string; needs: boolean};
function match(label: string, needs: boolean, typo: boolean): Hit | null {
  const puny = label.startsWith("xn--") ? punycode(label) : "", base = puny ? skeleton(puny) : label, glyph = homoglyph(base);
  if (!base) return null;
  const how = puny ? `domain punycode berhuruf mirip ("${puny.slice(0, 40)}")` : "";
  for (const form of glyph !== base ? [base, glyph] : [base]) {
    const flat = form.replace(/-/g, ""), why = how || (form !== label ? `huruf mirip ("${label}")` : "");
    for (const brand of BRANDS) {
      const s = brand.sub.find(t => form.includes(t) || flat.includes(t)); if (s) return {brand, tok: s, how: why, needs: needs || brand.sdk && !why};
      for (const w of brand.word) {const h = wordHit(form, w); if (h) return {brand, tok: w, how: why, needs: needs || h === "plain" && !why};}
    }
  }
  if (!typo) return null;
  for (const part of new Set([base, glyph, ...base.split("-")])) {
    if (part.length < 6 || TYPO_SAFE.has(part)) continue;
    for (const brand of BRANDS) for (const t of brand.sub) if (t.length >= 6 && !NO_TYPO.has(t) && /^[a-z]+$/.test(t) && part[0] === t[0] && oneEdit(part, t) && !brand.names.has(part)) return {brand, tok: t, how: how || `salah ketik dari "${t}" ("${part}")`, needs};
  }
  return null;
}
const ccSuffix = (s: string) => /^[a-z]{2}$/.test(s) && !ABUSED_CC.has(s) || /^(?:com?|net|org|ne|or)\.[a-z]{2}$/.test(s);
const official = (host: string, primary: string, suffix: string) => under(host, OFFICIAL) || BRANDS.some(b => b.gov && host.endsWith(".go.id") || b.cc && b.names.has(primary) && ccSuffix(suffix));
const cache = new Map<string, Lookalike | null>();
// Brand impersonated by `host` (optionally with the URL path and the RDAP age of its domain), or null.
export function impersonatedBrand(host: string, path = "", ageDays?: number): Lookalike | null {
  try {
    const key = `${host}\0${path.slice(0, 200)}\0${ageDays ?? ""}`, hit = cache.get(key); if (hit !== undefined) return hit;
    const r = detect(String(host).toLowerCase().replace(/\.$/, ""), String(path).slice(0, 300).toLowerCase(), ageDays);
    if (cache.size > 4000) cache.clear(); cache.set(key, r); return r;
  } catch { return null; }
}
function detect(host: string, path: string, ageDays?: number): Lookalike | null {
  if (host.length > 253 || ipv4(host) || !DOMAIN.test(host) || under(host, IGNORE)) return null;
  const labels = host.split("."), zone = FREE.find(d => host.endsWith(`.${d}`)), cloud = zone ? undefined : TENANT.find(d => host.endsWith(`.${d}`));
  let primary: string[], extra: string[];
  if (zone || cloud) {const tenant = host.slice(0, -(zone || cloud)!.length - 1).split("."); primary = zone ? tenant : []; extra = zone ? [] : tenant;}
  else {
    const reg = registrableDomain(host); if (!reg) return null;
    const n = reg.split(".").length, suffix = reg.slice(reg.indexOf(".") + 1);
    if (RESTRICTED.has(suffix) || RESTRICTED.has(labels[labels.length - 1]) || official(host, labels[labels.length - n], suffix)) return null;
    primary = [labels[labels.length - n]]; extra = labels.slice(0, labels.length - n).filter(l => l !== "www");
  }
  const tld = labels[labels.length - 1], risky = RISKY_TLD.has(tld) || under(host, RISKY_SUFFIX), puny = host.includes("xn--");
  // Lure words: whole tokens of the path; inside host labels also glued ("loginbca", "bcalogin", "shopeepromo").
  const words = [...primary, ...extra].join("-").split(/[^a-z]+/), named = [...new Set(words.flatMap(w => RISK.has(w) ? [w] : LURE.filter(r => w.includes(r))))];
  const lure = [...new Set([...named, ...path.split(/[^a-z]+/).filter(w => PATH_RISK.has(w) || /^(?:verif|login|signin|aktivasi|konfirm)/.test(w))])].slice(0, 3);
  const young = ageDays !== undefined && ageDays >= 0 && ageDays < 180, context = Boolean(zone) || risky || puny || named.length > 0 || young;
  let found: Hit | null = null;
  for (const typo of [false, true]) {
    for (const [list, needs] of [[primary, false], [extra, true]] as const) for (const l of list) {const h = match(l, needs, typo); if (h && (!h.needs || context)) {found = h; break;}}
    if (found) break;
  }
  if (!found) return null;
  const {brand, tok, how} = found, domains = brand.domains.slice(0, 2).join(", ");
  const signals = [risky ? `TLD .${tld} yang sering dipakai situs phishing` : "", zone ? `hosting gratis/tunnel ${zone}` : "", puny && !how.startsWith("domain punycode") ? "domain punycode (huruf mirip)" : "", lure.length ? `kata umpan "${lure.join(", ")}"` : "", young ? `domain baru (${ageDays} hari)` : ""].filter(Boolean);
  const reason = [how || `nama domain memuat "${tok}"`, ...signals, domains ? `bukan domain resmi (${domains})` : "bukan domain resmi"].join("; ").slice(0, 240);
  return {brand: brand.name, reason, severity: risky || zone || puny || lure.length || young ? "high" : "medium"};
}
