import { test } from "node:test";
import assert from "node:assert/strict";
import { domainToASCII, domainToUnicode } from "node:url";
import { impersonatedBrand, punycode } from "../lib/brands";
import { EndpointCollector, endpointHosts } from "../lib/endpoints";
import { Signals, evaluate, manifestModel } from "../lib/behaviors";
import { extractFile } from "../lib/extract";
import { linkRisk } from "../lib/pdf-behaviors";

const collect = (strings: string[], source = "dex") => {const c = new EndpointCollector(); c.add(strings, source); return c.finish();};
type Behavior = {id: string; severity: string; evidence: string[]};
const behaviors = (a: Awaited<ReturnType<typeof extractFile>>) => (a.metadata.behaviors as Behavior[] | undefined) ?? [];
const sev = (list: Behavior[], id: string) => list.find(b => b.id === id)?.severity;

test("look-alike brand domains are detected with brand, reason and severity", () => {
  const cases: [string, string, string][] = [
    ["shopping.lazadamy.top", "Lazada", "high"], ["shopee-promo.xyz", "Shopee", "high"], ["tokopedla.com", "Tokopedia", "medium"],
    ["klik-bca.site", "BCA", "high"], ["bri-id.online", "BRI", "high"], ["jne-resi.vercel.app", "JNE", "high"], ["dana-klaim.web.app", "DANA", "high"],
    ["bca-mobile.com", "BCA", "medium"], ["bri24.com", "BRI", "medium"], ["pln-tagihan.com", "PLN", "high"], ["loginbca.com", "BCA", "high"],
    ["lazadda.com", "Lazada", "medium"], ["shopeee.net", "Shopee", "medium"], ["sh0pee.com", "Shopee", "medium"], ["rnandiri.com", "Bank Mandiri", "medium"],
    ["bca-login.github.io", "BCA", "high"], ["mandiri.top", "Bank Mandiri", "high"], ["bpjs-kesehatan.cfd", "BPJS", "high"],
    ["facebook-login.xyz", "Facebook/Meta", "high"], ["google-verify.com", "Google", "high"], ["gooogle.com", "Google", "medium"], ["paypal-resolution.com", "PayPal", "medium"],
  ];
  for (const [host, brand, severity] of cases) {
    const r = impersonatedBrand(host); assert.ok(r, host); assert.equal(r.brand, brand, host); assert.equal(r.severity, severity, host); assert.match(r.reason, /bukan domain resmi/, host);
  }
  assert.match(impersonatedBrand("shopping.lazadamy.top")!.reason, /memuat "lazada".*TLD \.top/);
  assert.match(impersonatedBrand("tokopedla.com")!.reason, /salah ketik dari "tokopedia"/);
  // A lure word in the path or a young domain (RDAP) makes a plain look-alike high.
  assert.equal(impersonatedBrand("tokopedla.com", "/login")?.severity, "high");
  // SDK API paths ("update", "account") neither create a match nor raise one.
  assert.equal(impersonatedBrand("googlemobileadssdk.page.link", "/admob-android-update-manifest"), null); assert.equal(impersonatedBrand("tokopedla.com", "/api/update")?.severity, "medium");
  assert.equal(impersonatedBrand("tokopedla.com", "", 12)?.severity, "high"); assert.match(impersonatedBrand("tokopedla.com", "", 12)!.reason, /domain baru \(12 hari\)/);
});

test("punycode homoglyph hosts are decoded and matched", () => {
  const host = domainToASCII("shоpee-promo.com"); // Cyrillic "о"
  assert.match(host, /^xn--/); assert.equal(punycode(host.split(".")[0]), domainToUnicode(host).split(".")[0]);
  const r = impersonatedBrand(host); assert.equal(r?.brand, "Shopee"); assert.equal(r?.severity, "high"); assert.match(r!.reason, /punycode/);
  assert.equal(impersonatedBrand(domainToASCII("tokopеdia.com"))?.brand, "Tokopedia");
  assert.equal(impersonatedBrand(domainToASCII("münchen.de")), null);
  assert.equal(punycode("xn--!!"), ""); assert.equal(punycode("xn--zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"), punycode("xn--zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")); // never throws
});

test("official brand domains, partners/CDNs and coincidental substrings are not look-alikes", () => {
  for (const host of ["lazada.co.id", "sellercenter.lazada.co.id", "lazada.sg", "lazada.com.my", "shopee.co.id", "cf.shopee.co.id", "shopee.tw", "shopeemobile.com", "tokopedia.net", "ecs7.tokopedia.net", "tokopedia.com",
    "klikbca.com", "bri.co.id", "bankmandiri.co.id", "axa-mandiri.co.id", "brimob.polri.go.id", "dana.id", "alicdn.com", "g.alicdn.com", "susercontent.com", "google.de", "googlesamples.github.io", "google.github.io",
    "android-developers.blogspot.com", "paypal.me", "api.whatsapp.com", "telegra.ph", "t.me", "steamcommunity.com", "outlook.office365.com", "login.microsoftonline.com", "login.microsoftonline.us", "login.microsoftonline.microsoft.scloud",
    "abcade.com", "brick.com", "danang.vn", "pos.com", "fabric.io", "ovoid.com", "living.com", "pineapple.com", "outlookindia.com", "koperasi-mandiri.com", "pajakku.com", "finance.yahoo.com",
    "googlemobileadssdk.page.link", "lf-static.tiktokpangle-cdn-us.com", "umdc.alibabachengdun.com", "test-baichuan-sdk.alibaba.net", "tiktok-sdk-mirror.com",
    "paypay.ne.jp", "gopay.cz", "tiki.vn", "dana.com", "bca.com", "example.com", "github.com", "kheronyx.vercel.app", "103.146.158.229", "not a host", ""]) assert.equal(impersonatedBrand(host), null, host);
});

test("endpoints: a look-alike URL becomes kind phishing (not a neutral url) and leads the threat-intel hosts", () => {
  const list = collect(["https://cdn.example-sdk.io/v1/config.json", "https://shopping.lazadamy.top", "https://www.lazada.co.id/products/x", "https://shopee.co.id/flash-sale", "https://jne-resi.vercel.app/cek?resi=1"]);
  const lazada = list.find(e => e.host === "shopping.lazadamy.top");
  assert.equal(lazada?.kind, "phishing"); assert.equal(lazada?.brand?.brand, "Lazada"); assert.equal(lazada?.brand?.severity, "high");
  assert.equal(list.find(e => e.host === "jne-resi.vercel.app")?.kind, "phishing");
  assert.ok(list.every(e => !/lazada\.co\.id|shopee\.co\.id/.test(e.host) || e.kind !== "phishing"));
  const hosts = endpointHosts(list); assert.deepEqual(hosts.slice(0, 2).sort(), ["jne-resi.vercel.app", "shopping.lazadamy.top"]);
  // Native libraries only contribute server-like kinds; a look-alike host still counts.
  assert.equal(collect(["see https://bca-mobile.top/login"], "native:libx.so")[0]?.kind, "phishing");
  // A bare DDNS host that imitates a brand keeps its kind and carries the brand.
  const ddns = collect(["bri-mobile.ddns.net:7771"])[0]; assert.equal(ddns?.kind, "ddns"); assert.equal(ddns?.brand?.brand, "BRI");
});

test("behavior brand_domain: high is malicious context, medium alone is gated like other everyday findings", () => {
  const overlay = manifestModel([{tag: "manifest", attributes: {package: "x.y"}}, {tag: "uses-permission", attributes: {name: "android.permission.SYSTEM_ALERT_WINDOW"}}] as never);
  const high = evaluate(new Signals(), overlay, [], {endpoints: collect(["https://klik-bca.site/login"])});
  const b = high.find(x => x.id === "brand_domain"); assert.equal(b?.severity, "high"); assert.match(b!.name, /Domain meniru merek resmi \(BCA\)/); assert.match(b!.evidence[0], /klik-bca\.site\/login meniru BCA/);
  assert.equal(sev(high, "overlay"), "medium"); // not gated down next to a strong look-alike domain
  const medium = evaluate(new Signals(), overlay, [], {endpoints: collect(["https://tokopedla.com/"])});
  assert.equal(sev(medium, "brand_domain"), "low"); assert.equal(sev(medium, "overlay"), "low");
  assert.equal(evaluate(new Signals(), overlay, [], {endpoints: collect(["https://www.tokopedia.com/"])}).find(x => x.id === "brand_domain"), undefined);
});

// ---- minimal PE with a string in .data (nothing is executed) ----
function exe(strings: string[]) {
  const data = Buffer.alloc(0x400); Buffer.from(strings.join("\0"), "latin1").copy(data);
  const h = Buffer.alloc(0x400), opt = 0x40 + 24; h.write("MZ", 0, "latin1"); h.writeUInt32LE(0x40, 60); h.write("PE\0\0", 0x40, "latin1"); h.writeUInt16LE(0x14c, 0x44); h.writeUInt16LE(1, 0x46); h.writeUInt16LE(224, 0x54); h.writeUInt16LE(0x102, 0x56);
  h.writeUInt16LE(0x10b, opt); h.writeUInt32LE(0x400, opt + 60); h.writeUInt32LE(16, opt + 92);
  const q = opt + 224; h.write(".data", q, "latin1"); h.writeUInt32LE(0x1000, q + 8); h.writeUInt32LE(0x1000, q + 12); h.writeUInt32LE(0x400, q + 16); h.writeUInt32LE(0x400, q + 20); h.writeUInt32LE(0xc0000040, q + 36);
  return Buffer.concat([h, data]);
}
test("EXE: a look-alike URL in the program becomes a phishing endpoint and brand_domain", async () => {
  const a = await extractFile(exe(["Silakan cek paket Anda di https://jne-resi.vercel.app/cek sekarang", "https://www.microsoft.com/en-us/"]), "kurir.exe");
  const eps = a.metadata.endpoints as {kind: string; host: string; brand?: {brand: string}}[];
  assert.equal(eps.find(e => e.host === "jne-resi.vercel.app")?.kind, "phishing");
  assert.equal(sev(behaviors(a), "brand_domain"), "high"); assert.equal((a.metadata.campaign as {hosts: string[]}).hosts[0], "jne-resi.vercel.app");
});

// ---- hand-built PDF with link annotations ----
const esc = (s: string) => s.replace(/[\\()]/g, m => `\\${m}`);
function pdf(text: string[], links: string[]) {
  const lines = text.map((t, i) => `BT /F1 10 Tf 20 ${760 - i * 14} Td (${esc(t)}) Tj ET`).join("\n");
  const objects = ["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R${links.length ? ` /Annots [${links.map((_, i) => `${6 + i} 0 R`).join(" ")}]` : ""} >>`,
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", `<< /Length ${lines.length} >>\nstream\n${lines}\nendstream`,
    ...links.map((url, i) => `<< /Type /Annot /Subtype /Link /Rect [200 ${400 - i * 50} 400 ${440 - i * 50}] /Border [0 0 0] /A << /S /URI /URI (${esc(url)}) >> >>`)];
  let out = "%PDF-1.4\n"; const offsets: number[] = [];
  objects.forEach((o, i) => {offsets.push(Buffer.byteLength(out, "latin1")); out += `${i + 1} 0 obj\n${o}\nendobj\n`;});
  const xref = Buffer.byteLength(out, "latin1");
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.map(o => `${String(o).padStart(10, "0")} 00000 n \n`).join("")}trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return Buffer.from(out, "latin1");
}
const prose = ["Laporan kegiatan bulanan komunitas pecinta tanaman hias di wilayah kami.", "Terima kasih kepada semua anggota yang sudah hadir pada pertemuan terakhir di taman kota.", "Dokumentasi foto kegiatan dan catatan rapat tersedia di tautan berikut ini.", "Pertemuan berikutnya membahas jadwal pameran dan pembagian tugas panitia."];
test("PDF: a look-alike link raises pdf_phishing to high and names the brand; official links do not", async () => {
  const a = await extractFile(pdf(prose, ["https://shopee-promo.xyz/klaim", "https://www.jogjaprov.go.id/"]), "laporan.pdf");
  const p = behaviors(a).find(b => b.id === "pdf_phishing"); assert.equal(p?.severity, "high"); assert.ok(a.indicators.some(i => /^Umpan phishing.*\(meniru Shopee\)$/.test(i.name))); assert.match(p!.evidence.join(" "), /shopee-promo\.xyz/);
  assert.equal(sev(behaviors(a), "brand_domain"), "high"); assert.equal((a.metadata.campaign as {hosts: string[]}).hosts[0], "shopee-promo.xyz");
  assert.match(linkRisk("https://tokopedla.com/").strong || "", /meniru Tokopedia/); assert.equal(linkRisk("https://www.tokopedia.com/").brand, undefined);
  // A plain typo look-alike without lure text is only noted (gated low), not called phishing.
  const typo = await extractFile(pdf(prose, ["https://tokopedla.com/"]), "typo.pdf");
  assert.equal(sev(behaviors(typo), "pdf_phishing"), undefined); assert.equal(sev(behaviors(typo), "brand_domain"), "low");
  const ok = await extractFile(pdf(prose, ["https://shopee.co.id/", "https://www.lazada.co.id/", "https://www.klikbca.com/"]), "katalog.pdf");
  assert.ok(behaviors(ok).every(b => b.id !== "pdf_phishing" && b.id !== "brand_domain"), behaviors(ok).map(b => b.id).join(","));
});
