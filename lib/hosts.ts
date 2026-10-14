// Pure host/IP helpers shared by extraction (lib/endpoints.ts, lib/deobfuscate.ts), reputation lookups
// (lib/threat-intel.ts) and the report UI. No imports, no I/O: safe in client components.
// Vendor/platform infrastructure nearly every app references: looked up nowhere (noise, wasted quota).
export const BENIGN = ["google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "google-analytics.com", "doubleclick.net", "googlesyndication.com", "googleadservices.com", "app-measurement.com", "crashlytics.com", "youtube.com", "android.com", "w3.org", "apache.org", "xmlpull.org", "xml.org", "json-schema.org", "purl.org", "adobe.com", "microsoft.com", "windows.com", "windowsupdate.com", "live.com", "office.com", "apple.com", "icloud.com", "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com", "whatsapp.net", "amazon.com", "cloudflare.com", "mozilla.org", "digicert.com", "verisign.com", "globalsign.com", "sectigo.com", "letsencrypt.org", "unity3d.com", "schema.org", "wikipedia.org", "yahoo.com", "twitter.com", "x.com", "linkedin.com", "paypal.com", "line.me", "tiktok.com", "goo.gle", "ipify.org", "jsdelivr.net", "example.com", "example.org", "example.net"];
// Shared services where the host says nothing about the sample: specific payload URLs are checked, the host/domain is not.
export const SHARED = ["github.com", "githubusercontent.com", "telegram.org", "t.me", "discord.com", "discordapp.com", "discord.gg", "slack.com", "dropbox.com", "dropboxusercontent.com", "drive.google.com", "pastebin.com", "bit.ly", "goo.gl", "tinyurl.com", "t.co"];
// Free dynamic-DNS zones (customer picks the subdomain): typical for RAT/C2 servers on home or VPS connections.
export const DDNS = ["ddns.net", "hopto.org", "zapto.org", "sytes.net", "servebeer.com", "serveftp.com", "servehttp.com", "servegame.com", "serveirc.com", "servemp3.com", "servepics.com", "servequake.com", "serveblog.net", "myftp.biz", "myftp.org", "redirectme.net", "bounceme.net", "myvnc.com", "no-ip.org", "no-ip.biz", "no-ip.info", "no-ip.net", "noip.me", "ddns.me", "gotdns.ch", "webhop.me", "3utilities.com", "onthewifi.com", "duckdns.org", "dynu.net", "freeddns.org", "mywire.org", "webredirect.org", "ddnsfree.com", "ddnsgeek.com", "giize.com", "gleeze.com", "kozow.com", "loseyourip.com", "ooguy.com", "theworkpc.com", "casacam.net", "accesscam.org", "camdvr.org", "freedynamicdns.net", "freedynamicdns.org", "mooo.com", "chickenkiller.com", "strangled.net", "us.to", "ydns.eu", "dyndns.org", "dyndns.info", "dyndns.biz", "homeip.net", "dynv6.net", "publicvm.com", "linkpc.net", "dynamic-dns.net", "myddns.me", "ddnsking.com", "duia.us", "portmap.io", "portmap.host"];
// Tunnels and throwaway request collectors that expose a machine without a server of its own.
export const TUNNEL = ["ngrok.io", "ngrok.app", "ngrok-free.app", "ngrok.dev", "ngrok-free.dev", "trycloudflare.com", "loca.lt", "localtunnel.me", "serveo.net", "serveousercontent.com", "pinggy.link", "pinggy.online", "pinggy.io", "localhost.run", "lhr.life", "lhr.rocks", "bore.pub", "tunnelto.dev", "loclx.io", "devtunnels.ms", "ply.gg", "joinmc.link", "tunnelmole.net", "telebit.io", "loophole.site", "webhook.site", "pipedream.net", "requestbin.net", "beeceptor.com"];
// Tenant platforms: the registrable part belongs to the platform, so RDAP age is meaningless (hosts are still checked).
export const PLATFORM = ["github.io", "firebaseio.com", "firebasedatabase.app", "cloudfunctions.net", "firebaseapp.com", "web.app", "appspot.com", "herokuapp.com", "vercel.app", "netlify.app", "pages.dev", "workers.dev", "000webhostapp.com", "blogspot.com", "glitch.me", "repl.co", "onrender.com", "azurewebsites.net", "cloudfront.net", "amazonaws.com", "atwebpages.com", "weebly.com", "wixsite.com", ...DDNS, ...TUNNEL];
const MULTI = new Set(["co.id", "go.id", "ac.id", "or.id", "my.id", "web.id", "sch.id", "biz.id", "net.id", "mil.id", "ponpes.id", "desa.id", "co.uk", "org.uk", "ac.uk", "gov.uk", "com.br", "com.au", "net.au", "org.au", "co.jp", "co.in", "com.my", "com.sg", "com.cn", "com.hk", "com.tw", "co.kr", "com.vn", "com.ph", "co.th", "com.tr", "com.mx", "com.ar", "co.za", "co.nz", "com.pk", "com.ng", "com.sa", "com.eg"]);
const NON_PUBLIC = /\.(?:local|localhost|lan|internal|intranet|home|corp|test|example|invalid|onion|arpa|json|xml|txt|html?|php|jsp?|png|jpe?g|gif|apk|dex|so|java|kt|class|properties|log|dat|bin|db|smali|jar)$/;
export const DOMAIN = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;
// Public DNS resolvers/connectivity probes apps embed for "am I online?" checks; never a C2.
const RESOLVERS = new Set(["1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "9.9.9.10", "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6", "64.6.64.6", "64.6.65.6", "94.140.14.14", "94.140.15.15", "76.76.2.0", "76.76.10.0", "185.228.168.9", "114.114.114.114", "114.114.115.115", "223.5.5.5", "223.6.6.6", "180.76.76.76", "119.29.29.29", "77.88.8.8", "77.88.8.1"]);

export const under = (host: string, list: readonly string[]) => list.some(d => host === d || host.endsWith(`.${d}`));
export const ipv4 = (host: string) => /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/.test(host);
export function privateIp(ip: string) {
  const [a, b, c] = ip.split(".").map(Number);
  return a === 0 || a === 10 || a === 127 || a >= 224 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168 || a === 100 && b >= 64 && b <= 127 || a === 192 && b === 0 || a === 198 && (b === 18 || b === 19) || a === 198 && b === 51 && c === 100 || a === 203 && b === 0 && c === 113;
}
export const resolverIp = (ip: string) => RESOLVERS.has(ip) || /^208\.67\.(?:222|220)\./.test(ip);
// Documentation/sample placeholders ("123.123.123.123", "1.2.3.4", "12.34.56.78") are never real servers.
export const placeholderIp = (ip: string) => /^(\d+)\.\1\.\1\.\1$/.test(ip) || ["1.2.3.4", "4.3.2.1", "12.34.56.78", "11.22.33.44", "123.45.67.89", "98.76.54.32"].includes(ip);
// Routable unicast IPv4 (no leading zeros) that is not a well-known public resolver or a placeholder.
export const publicIpv4 = (ip: string) => ipv4(ip) && !privateIp(ip) && !resolverIp(ip) && !placeholderIp(ip);
export const validPort = (p: string | number | undefined) => p !== undefined && p !== "" && Number.isInteger(Number(p)) && Number(p) >= 1 && Number(p) <= 65535;
export function hostOf(value: string) {
  try { return new URL(/^[a-z][\w+.-]*:\/\//i.test(value) ? value : `http://${value}`).hostname.toLowerCase().replace(/\.$/, ""); } catch { return ""; }
}
// Public, non-benign hostname or IPv4 worth a reputation lookup (IPv6 and private/reserved ranges are skipped).
export function publicHost(host: string) {
  if (ipv4(host)) return !privateIp(host);
  return DOMAIN.test(host) && !NON_PUBLIC.test(host) && !under(host, BENIGN);
}
// Approximate eTLD+1 (small multi-part suffix list); null for IPs, platform tenants and bare suffixes.
export function registrableDomain(host: string) {
  if (ipv4(host) || !DOMAIN.test(host) || under(host, PLATFORM)) return null;
  const labels = host.split("."), n = labels.length >= 3 && MULTI.has(labels.slice(-2).join(".")) ? 3 : 2, domain = labels.slice(-n).join(".");
  return labels.length < n || MULTI.has(domain) ? null : domain;
}
const esc = (d: string) => d.replace(/[.-]/g, m => `\\${m}`);
// Customer hostname inside a DDNS/tunnel zone (needs a label of its own; the provider's www/apex is not an endpoint).
const ZONES = `(?<![\\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:${[...DDNS, ...TUNNEL].map(esc).join("|")}))(?::(\\d{1,5}))?(?![\\w-]|\\.[a-z0-9])`;
export const DDNS_HOST = new RegExp(ZONES, "gi"), DDNS_HINT = new RegExp(ZONES, "i");
export const zoneOf = (host: string) => under(host, TUNNEL) ? "tunnel" : under(host, DDNS) ? "ddns" : "";
export const customerHost = (host: string) => Boolean(zoneOf(host)) && !DDNS.includes(host) && !TUNNEL.includes(host) && !host.startsWith("www.");
// A decoded value that is nothing but an endpoint ("103.146.158.229", "1.2.3.4:4444", "c2.example.net:7771"); lets
// deobfuscation keep digit-only results that the usual "readable text" test drops.
export function endpointOnly(s: string) {
  if (s.length < 7 || s.length > 260) return false;
  const m = s.match(/^((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?$/); if (m) return publicIpv4(m[1]) && (m[2] === undefined || validPort(m[2])) && (Boolean(m[2]) || Number(m[1].split(".")[0]) > 2);
  const h = s.match(/^([a-z0-9.-]+\.[a-z]{2,63}):(\d{1,5})$/i); return Boolean(h) && DOMAIN.test(h![1].toLowerCase()) && validPort(h![2]);
}
