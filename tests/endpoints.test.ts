import { test } from "node:test";
import assert from "node:assert/strict";
import AdmZip from "adm-zip";
import { extractFile } from "../lib/extract";
import { EndpointCollector, endpointHosts, type Endpoint } from "../lib/endpoints";
import { decodeHidden } from "../lib/deobfuscate";
import { edgeNetwork, endpointOnly, publicIpv4 } from "../lib/hosts";
import { threatIntelTargets } from "../lib/threat-intel";

const TOKEN = "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", b64 = (s: string) => Buffer.from(s).toString("base64");
const values = (list: Endpoint[]) => list.map(e => e.value);
const collect = (strings: string[], source = "dex", opts: Parameters<EndpointCollector["add"]>[2] = {}) => {const c = new EndpointCollector(); c.add(strings, source, opts); return c.finish();};
type Behavior = {id: string; severity: string; evidence: string[]};

// ---- fixture builders: DEX with real code items, binary manifest, minimal PE ----
const uleb = (n: number) => {const out: number[] = []; do {let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; out.push(b);} while (n); return out;};
type Method = {name: string; code: number[]};
class Dex {
  strings: string[] = []; types: number[] = []; methods: [number, number][] = []; classes: {cls: number; sup: number; methods: [number, Method][]}[] = [];
  s(x: string) {let i = this.strings.indexOf(x); if (i < 0) i = this.strings.push(x) - 1; return i;}
  t(x: string) {const si = this.s(x); let i = this.types.indexOf(si); if (i < 0) i = this.types.push(si) - 1; return i;}
  m(c: string, n: string) {const k: [number, number] = [this.t(c), this.s(n)]; let i = this.methods.findIndex(x => x[0] === k[0] && x[1] === k[1]); if (i < 0) i = this.methods.push(k) - 1; return i;}
  cls(name: string, sup: string, methods: Method[] = []) {const cls = this.t(name), s = this.t(sup); this.classes.push({cls, sup: s, methods: methods.map(x => [this.m(name, x.name), x] as [number, Method])}); return this;}
  build() {
    // String ids must be sorted for real DEX, but the parser only needs consistent indexes.
    const oStr = 0x70, oType = oStr + this.strings.length * 4, oMethod = oType + this.types.length * 4, oClass = oMethod + this.methods.length * 8, oData = oClass + this.classes.length * 32;
    const data: number[] = [], strOff: number[] = [], pad = () => {while ((oData + data.length) % 4) data.push(0);};
    for (const s of this.strings) {strOff.push(oData + data.length); data.push(...uleb(s.length), ...Buffer.from(s, "utf8"), 0);}
    const codeOff = new Map<Method, number>();
    for (const c of this.classes) for (const [, m] of c.methods) {pad(); codeOff.set(m, oData + data.length); const h = Buffer.alloc(16); h.writeUInt16LE(16, 0); h.writeUInt32LE(m.code.length, 12); data.push(...h); for (const u of m.code) data.push(u & 0xff, u >> 8 & 0xff);}
    const classData = this.classes.map(c => {
      if (!c.methods.length) return 0; const at = oData + data.length, sorted = [...c.methods].sort((a, b) => a[0] - b[0]); let prev = 0;
      data.push(0, 0, ...uleb(sorted.length), 0); for (const [idx, m] of sorted) {data.push(...uleb(idx - prev), 1, ...uleb(codeOff.get(m)!)); prev = idx;}
      return at;
    });
    const b = Buffer.alloc(oData + data.length);
    b.write("dex\n035\0", 0, "latin1"); b.writeUInt32LE(b.length, 0x20); b.writeUInt32LE(0x70, 0x24); b.writeUInt32LE(0x12345678, 0x28);
    b.writeUInt32LE(this.strings.length, 0x38); b.writeUInt32LE(oStr, 0x3c); b.writeUInt32LE(this.types.length, 0x40); b.writeUInt32LE(oType, 0x44);
    b.writeUInt32LE(this.methods.length, 0x58); b.writeUInt32LE(oMethod, 0x5c); b.writeUInt32LE(this.classes.length, 0x60); b.writeUInt32LE(oClass, 0x64);
    strOff.forEach((o, i) => b.writeUInt32LE(o, oStr + i * 4)); this.types.forEach((s, i) => b.writeUInt32LE(s, oType + i * 4));
    this.methods.forEach(([c, n], i) => {b.writeUInt16LE(c, oMethod + i * 8); b.writeUInt32LE(n, oMethod + i * 8 + 4);});
    this.classes.forEach((c, i) => {const q = oClass + i * 32; b.writeUInt32LE(c.cls, q); b.writeUInt32LE(c.sup, q + 8); b.writeUInt32LE(0xffffffff, q + 12); b.writeUInt32LE(0xffffffff, q + 16); b.writeUInt32LE(classData[i], q + 24);});
    Buffer.from(data).copy(b, oData); return b;
  }
}
const str = (r: number, s: number) => [r << 8 | 0x1a, s], invokeDirect = (m: number, regs: number[]) => [(regs.length << 4) << 8 | 0x70, m, regs[0] | (regs[1] ?? 0) << 4], ret = () => [0x0e];
function manifest(elements: [string, Record<string, string>][]) {
  const strings: string[] = []; const idx = (s: string) => {let i = strings.indexOf(s); if (i < 0) i = strings.push(s) - 1; return i;};
  const chunks = elements.map(([tag, attrs]) => {
    const entries = Object.entries(attrs), c = Buffer.alloc(36 + entries.length * 20);
    c.writeUInt16LE(0x102, 0); c.writeUInt16LE(16, 2); c.writeUInt32LE(c.length, 4); c.writeUInt32LE(0xffffffff, 12); c.writeUInt32LE(0xffffffff, 16); c.writeUInt32LE(idx(tag), 20);
    c.writeUInt16LE(20, 24); c.writeUInt16LE(20, 26); c.writeUInt16LE(entries.length, 28);
    entries.forEach(([k, v], i) => {const a = 36 + i * 20; c.writeUInt32LE(0xffffffff, a); c.writeUInt32LE(idx(k), a + 4); c.writeUInt32LE(idx(v), a + 8); c.writeUInt16LE(8, a + 12); c[a + 15] = 3; c.writeUInt32LE(idx(v), a + 16);});
    return c;
  });
  const bodies = strings.map(s => {const u = Buffer.from(s, "utf8"); return Buffer.concat([Buffer.from([s.length, u.length]), u, Buffer.from([0])]);});
  let data = Buffer.concat(bodies); data = Buffer.concat([data, Buffer.alloc((4 - data.length % 4) % 4)]);
  const pool = Buffer.alloc(28 + strings.length * 4); let off = 0;
  pool.writeUInt16LE(1, 0); pool.writeUInt16LE(28, 2); pool.writeUInt32LE(28 + strings.length * 4 + data.length, 4); pool.writeUInt32LE(strings.length, 8); pool.writeUInt32LE(256, 16); pool.writeUInt32LE(28 + strings.length * 4, 20);
  bodies.forEach((b, i) => {pool.writeUInt32LE(off, 28 + i * 4); off += b.length;});
  const body = Buffer.concat([pool, data, ...chunks]), head = Buffer.alloc(8); head.writeUInt16LE(3, 0); head.writeUInt16LE(8, 2); head.writeUInt32LE(8 + body.length, 4);
  return Buffer.concat([head, body]);
}
function buildPe(imports: [string, string[]][], tail: string) {
  const optSize = 224, opt = 0x40 + 24, sec = opt + optSize, raw = 0x200, va = 0x1000, b = Buffer.alloc(0x600);
  b.write("MZ", 0, "latin1"); b.writeUInt32LE(0x40, 60); b.write("PE\0\0", 0x40, "latin1"); b.writeUInt16LE(0x14c, 0x44); b.writeUInt16LE(1, 0x46); b.writeUInt16LE(optSize, 0x54);
  b.writeUInt16LE(0x10b, opt); b.writeUInt32LE(0x200, opt + 60); b.writeUInt32LE(16, opt + 92);
  b.write(".idata", sec, "latin1"); b.writeUInt32LE(0x400, sec + 8); b.writeUInt32LE(va, sec + 12); b.writeUInt32LE(0x400, sec + 16); b.writeUInt32LE(raw, sec + 20); b.writeUInt32LE(0xc0000040, sec + 36);
  let cursor = (imports.length + 1) * 20; const rva = (o: number) => va + o, at = (o: number) => raw + o;
  imports.forEach(([dll, fns], i) => {
    const ilt = cursor; cursor += (fns.length + 1) * 4; const name = cursor; b.write(`${dll}\0`, at(name), "latin1"); cursor += dll.length + 2;
    fns.forEach((f, j) => {b.writeUInt32LE(rva(cursor), at(ilt + j * 4)); b.write(`\0\0${f}\0`, at(cursor), "latin1"); cursor += f.length + 4;});
    b.writeUInt32LE(rva(ilt), at(i * 20)); b.writeUInt32LE(rva(name), at(i * 20 + 12)); b.writeUInt32LE(rva(ilt), at(i * 20 + 16));
  });
  b.writeUInt32LE(va, opt + 104); b.writeUInt32LE((imports.length + 1) * 20, opt + 108);
  return Buffer.concat([b, Buffer.from(tail, "latin1")]);
}

test("IP filter: resolvers, OIDs, versions, private/reserved ranges and placeholders are never endpoints", () => {
  const noise = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222", "0.0.0.0", "255.255.255.255", "127.0.0.1:8080", "10.0.2.2:4444", "192.168.1.10:80", "172.20.1.1:443", "100.64.3.3:22", "224.0.0.251:5353",
    "1.3.14.3.2.26", "2.16.840.1.101.3.4", "1.3.6.1", "1.2.840.113549", "362.0.0.27", "FBAV/362.0.0.27.109", "Chrome/99.0.4844.88", "4.0.0.1", "version 5.1.2.3", "Build/RP1A.200720.012", "01.02.03.04", "123.123.123.123:12345", "1.2.3.4:80", "45.77.12.3:99999"];
  assert.deepEqual(collect(noise, "dex", {context: true}), []);
  assert.deepEqual(collect(noise, "native:libx.so"), []);
  for (const ip of ["8.8.8.8", "10.1.1.1", "1.1.1.1", "203.0.113.5", "300.1.1.1"]) assert.equal(publicIpv4(ip), false, ip);
  assert.equal(publicIpv4("103.146.158.229"), true);
  // Bare public IP: only with context (port, URL, deobfuscation, socket-linked call site). Native libraries embed dotted
  // version numbers (libvlc "6.7.8.5"), so a native bare IP needs a port like any other string.
  assert.deepEqual(collect(["45.77.12.3"]), []);
  assert.deepEqual(collect(["45.77.12.3", "6.7.8.5"], "native:libc2.so"), []);
  assert.deepEqual(values(collect(["45.77.12.3:4444"], "native:libc2.so")), ["45.77.12.3:4444"]);
  assert.deepEqual(values(collect(["45.77.12.3:4444", "tcp://51.15.2.9:7771", "connect 91.200.1.5:1177 now"])).sort(), ["45.77.12.3:4444", "91.200.1.5:1177", "tcp://51.15.2.9:7771"]);
  assert.deepEqual(collect(["http://10.0.0.1/gate.php", "http://8.8.8.8/x"]), []);
});
test("localized sample hosts are not endpoints", () => {
  assert.deepEqual(collect(["https://exemple.duckdns.org:8123", "https://eksempel.duckdns.org:8123", "https://esimerkki.duckdns.org:8123", "http://yourdomain.ddns.net:9000"], "resources"), []);
  assert.deepEqual(values(collect(["https://victim-panel.duckdns.org:8123"], "resources")), ["https://victim-panel.duckdns.org:8123"]);
});
test("deobfuscation keeps base64/hex-hidden public IPs (and IP:port) but not resolvers", () => {
  assert.deepEqual(decodeHidden(b64("103.146.158.229")), {value: "103.146.158.229", technique: "base64"});
  assert.deepEqual(decodeHidden(Buffer.from("45.77.12.3:4444").toString("hex")), {value: "45.77.12.3:4444", technique: "hex"});
  assert.equal(decodeHidden(b64("8.8.8.8:53:53")), null); assert.equal(decodeHidden(b64("192.168.10.100")), null);
  assert.equal(endpointOnly("c2.example.net:7771"), true); assert.equal(endpointOnly("1.3.14.3"), false); assert.equal(endpointOnly("8.8.8.8"), false);
  // Collector decoding for sources that are not deobfuscated elsewhere (resources, EXE/.NET strings).
  const found = collect([b64("103.146.158.229"), b64("rat.duckdns.org:5552"), b64("Hello world this is text")], "resources", {decode: true, via: "resources.arsc"});
  assert.deepEqual(found.map(e => [e.kind, e.value, e.source, e.via]), [["ddns", "rat.duckdns.org:5552", "deobfuscated:base64", "resources.arsc"], ["ip", "103.146.158.229", "deobfuscated:base64", "resources.arsc"]]);
});
test("DDNS and tunnel hosts are recognised with or without scheme; provider sites are not", () => {
  const found = collect(["myrat.ddns.net:7771", "host=c2.hopto.org", "wss://abc123.ngrok-free.app/ws", "x7.trycloudflare.com", "https://serveo.net", "www.duckdns.org", "https://www.noip.com/sign-up", "a.duckdns.org.evil", "pf-12.portmap.host:39521"]);
  const kinds = Object.fromEntries(found.map(e => [e.value, e.kind]));
  assert.deepEqual(kinds, {"myrat.ddns.net:7771": "ddns", "c2.hopto.org": "ddns", "wss://abc123.ngrok-free.app/ws": "tunnel", "x7.trycloudflare.com": "tunnel", "pf-12.portmap.host:39521": "ddns"});
  assert.equal(found.find(e => e.value === "myrat.ddns.net:7771")!.port, 7771);
});
test("panel/telegram/webhook/firebase/email classification, secrets redacted, benign SDK hosts excluded", () => {
  const found = collect([
    "https://www.happyapis.com/data_20/index_20.php?id=1&key=secret", `https://api.telegram.org/bot123456789:${TOKEN}/sendMessage?chat_id=-1001234567890`, `token 987654321:${TOKEN}`,
    "https://discord.com/api/webhooks/1234567890/abcdefghijklmnopqrstuvwxyz", "https://scam-1.firebaseio.com", "https://gate.example-shop.xyz/bot%s/sendMessage",
    "smtp.mailtrap.io:2525", "drop.box.2024@gmail.com", "https://www.google.com/search", "http://schemas.android.com/apk/res/android", "https://firebasestorage.googleapis.com/v0", "https://github.com/square/okhttp",
    "https://user:pass@shop-promo.top/landing",
  ]);
  const by = (v: string) => found.find(e => e.value.startsWith(v));
  assert.equal(by("https://www.happyapis.com")?.kind, "panel"); assert.equal(by("https://www.happyapis.com")?.value, "https://www.happyapis.com/data_20/index_20.php?…");
  assert.equal(by("https://api.telegram.org")?.kind, "telegram"); assert.equal(by("bot 987654321")?.value, "bot 987654321:…Dsaw");
  assert.equal(by("https://gate.example-shop.xyz")?.kind, "telegram", "Bot API relayed through the attacker's proxy");
  assert.equal(by("https://discord.com")?.kind, "webhook"); assert.equal(by("https://scam-1.firebaseio.com")?.kind, "firebase");
  assert.equal(by("smtp.mailtrap.io")?.kind, "email"); assert.equal(by("drop.box.2024@gmail.com")?.kind, "email", "addresses only count next to SMTP evidence");
  assert.equal(by("https://shop-promo.top")?.value, "https://shop-promo.top/landing", "userinfo stripped");
  assert.ok(!found.some(e => /google|android\.com|github/.test(e.host)));
  const json = JSON.stringify(found); assert.ok(!json.includes(TOKEN) && !json.includes(TOKEN.slice(0, 30)) && !json.includes("abcdefghijklmnop") && !json.includes("secret"));
  assert.deepEqual(collect(["drop.box.2024@gmail.com", "support@company.co.id"]), [], "no SMTP evidence: no e-mail endpoints");
  // Campaign hosts: shared platforms (Telegram/Discord) and big mail providers are not looked up.
  assert.deepEqual(endpointHosts(found).sort(), ["gate.example-shop.xyz", "scam-1.firebaseio.com", "shop-promo.top", "smtp.mailtrap.io", "www.happyapis.com"]);
});
test("dedupe and caps: one entry per value, strongest source wins, ≤25 endpoints and ≤8 plain URLs", () => {
  const c = new EndpointCollector();
  c.add(["45.77.12.3:4444", "45.77.12.3:4444", "connect 45.77.12.3"], "dex");
  c.hidden([{value: "45.77.12.3:4444", technique: "XOR 0x21", where: "Lid/rat/Conn;->run"}, {value: "45.77.12.3", technique: "base64"}]);
  c.add(Array.from({length: 60}, (_, i) => `https://cdn-${i}.shop-assets.xyz/a${i}`), "dex");
  c.add(Array.from({length: 40}, (_, i) => `81.4.${i}.9:${2000 + i}`), "dex");
  const list = c.finish();
  assert.ok(list.length <= 25); assert.ok(list.filter(e => e.kind === "url").length <= 8);
  const ip = list.filter(e => e.host === "45.77.12.3");
  assert.deepEqual(ip.map(e => [e.value, e.source, e.via]), [["45.77.12.3:4444", "deobfuscated:XOR 0x21", "id.rat.Conn.run"]], "bare duplicate dropped, hidden source kept");
  assert.equal(list[0].value, "45.77.12.3:4444", "hidden ip:port sorts first");
  assert.equal(new Set(list.map(e => e.value)).size, list.length);
});
test("APK: base64-hidden C2 IP, DDNS and socket-linked bare IP reach metadata.endpoints, c2_socket and threat-intel targets", async () => {
  const d = new Dex(), C = "Lid/rat/Conn;", sock = d.m("Ljava/net/Socket;", "<init>"), ip = d.s("91.200.1.5"), lone = d.s("51.15.2.9");
  d.s(b64("103.146.158.229")); d.s("myrat.ddns.net:7771"); d.s(`https://api.telegram.org/bot123456789:${TOKEN}/sendMessage`); d.s("8.8.8.8"); d.s("1.3.6.1.4.1.311"); d.s("https://www.happyapis.com/data_20/index_20.php");
  d.cls(C, "Ljava/lang/Object;", [{name: "run", code: [...str(0, ip), ...invokeDirect(sock, [1, 0]), ...ret()]}]);
  d.cls("Lid/rat/Main;", "Landroid/app/Activity;", [{name: "onCreate", code: [...str(0, lone), ...ret()]}]);
  const zip = new AdmZip();
  zip.addFile("AndroidManifest.xml", manifest([["manifest", {package: "id.rat"}], ["uses-permission", {name: "android.permission.RECEIVE_SMS"}], ["uses-permission", {name: "android.permission.INTERNET"}], ["application", {name: "id.rat.App"}],
    ["meta-data", {name: "srv", value: b64("pf-12.portmap.host:39521")}], ["activity", {name: "id.rat.Main"}], ["action", {name: "android.intent.action.MAIN"}], ["category", {name: "android.intent.category.LAUNCHER"}]]));
  zip.addFile("classes.dex", d.build());
  const r = await extractFile(zip.toBuffer(), "kurir.apk"), eps = r.metadata.endpoints as Endpoint[], get = (v: string) => eps.find(e => e.value === v);
  assert.equal(r.incomplete, false);
  assert.deepEqual([get("103.146.158.229")?.kind, get("103.146.158.229")?.source], ["ip", "deobfuscated:base64"]);
  assert.deepEqual([get("91.200.1.5")?.kind, get("91.200.1.5")?.via], ["ip", "id.rat.Conn.run"], "bare IP loaded by socket code");
  assert.equal(get("51.15.2.9"), undefined, "bare IP without network context is not reported");
  assert.equal(get("myrat.ddns.net:7771")?.kind, "ddns"); assert.deepEqual([get("pf-12.portmap.host:39521")?.kind, get("pf-12.portmap.host:39521")?.source], ["ddns", "deobfuscated:base64"]);
  assert.equal(get("https://www.happyapis.com/data_20/index_20.php")?.kind, "panel");
  assert.ok(!eps.some(e => /^(?:8\.8\.8\.8|1\.3\.6\.1)/.test(e.value))); assert.ok(!JSON.stringify(r).includes(TOKEN));
  const behaviors = r.metadata.behaviors as Behavior[], c2 = behaviors.find(b => b.id === "c2_socket");
  assert.equal(c2?.severity, "high"); assert.ok(c2!.evidence.some(e => e.includes("103.146.158.229 (disamarkan: base64)")));
  assert.ok(behaviors.find(b => b.id === "exfil_ip")!.evidence.some(e => e.includes("91.200.1.5")));
  const hosts = (r.metadata.campaign as {hosts: string[]}).hosts;
  for (const h of ["103.146.158.229", "91.200.1.5", "myrat.ddns.net", "pf-12.portmap.host", "www.happyapis.com"]) assert.ok(hosts.includes(h), h);
  const targets = threatIntelTargets(r);
  for (const h of ["103.146.158.229", "91.200.1.5", "myrat.ddns.net"]) assert.ok(targets.hosts.includes(h), h);
  assert.ok(targets.domains.includes("happyapis.com")); assert.ok(!targets.domains.some(x => /ddns|portmap|^\d/.test(x)), "RDAP skips IPs and DDNS zones");
});
test("EXE: ASCII/UTF-16 strings yield ip:port, whole-string IPs (with socket imports) and panels", async () => {
  const wide = (s: string) => Buffer.from(s, "utf16le").toString("latin1");
  const tail = `\x00185.22.33.44:7777\x00\x0091.200.1.5\x00http://evil-panel.xyz/gate.php\x00 8.8.8.8 \x00\x00${wide("rat.duckdns.org:5552")}\x00\x00${b64("103.146.158.229")}\x00`;
  const r = await extractFile(buildPe([["WS2_32.dll", ["connect", "send"]], ["KERNEL32.dll", ["Sleep"]]], tail), "tool.exe"), eps = r.metadata.endpoints as Endpoint[];
  assert.deepEqual(eps.map(e => [e.kind, e.value, e.source]).sort(), [["ddns", "rat.duckdns.org:5552", "exe"], ["ip", "103.146.158.229", "deobfuscated:base64"], ["ip", "185.22.33.44:7777", "exe"], ["ip", "91.200.1.5", "exe"], ["panel", "http://evil-panel.xyz/gate.php", "exe"]]);
  const ids = (r.metadata.behaviors as Behavior[]).map(b => b.id); assert.ok(ids.includes("c2_socket") && ids.includes("exfil_ip"));
  assert.ok(threatIntelTargets(r).hosts.includes("185.22.33.44"));
  // Without socket/HTTP imports a lone dotted quad is not an endpoint.
  const quiet = await extractFile(buildPe([["KERNEL32.dll", ["Sleep"]]], "\x0091.200.1.5\x00"), "tool.exe");
  assert.equal(quiet.metadata.endpoints, undefined);
});
test("library identifiers (WebRTC header-extension URIs, CRLs, bug links) and native doc URLs are not endpoints", () => {
  const strings = ["http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time", "http://crl.globalsign.net/root-r2.crl", "http://www2.public-trust.com/crl/ct/ctroot.crl", "https://crbug.com/1053756", "http://ocsp.digicert.com", "https://docs.some-sdk.dev/guide"];
  assert.deepEqual(collect(strings, "native:libjingle_peerconnection_so.so"), []);
  assert.deepEqual(collect(strings.slice(0, 5), "dex"), []);
  assert.deepEqual(values(collect(["http://45.77.12.3:8080/gate.php"], "native:libc2.so")), ["http://45.77.12.3:8080/gate.php"]);
});

test("CDN edge IPs are recognised as shared, ordinary servers are not",()=>{
  assert.equal(edgeNetwork("104.21.64.137"),"Cloudflare");
  assert.equal(edgeNetwork("172.67.151.52"),"Cloudflare");
  assert.equal(edgeNetwork("151.101.195.52"),"Fastly");
  for(const ip of ["103.146.158.229","44.210.57.23","104.32.0.1","8.8.8.8"]) assert.equal(edgeNetwork(ip),undefined,ip);
  assert.equal(edgeNetwork("cloudflare.com"),undefined);
});
