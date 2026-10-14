import { libraryClass, type DexCode } from "./dex";
// Behavior catalog for Android scam/banking-trojan/SMS-stealer patterns. Inputs are parser-derived facts (DEX method/field
// references, subclassed framework classes, manifest permissions/components, strings); nothing is executed.
export type Severity = "low" | "medium" | "high" | "critical";
export type Behavior = {id: string; name: string; severity: Severity; evidence: string[]};
export type Component = {tag: string; name: string; permission: string; actions: string[]; categories: string[]};
export type Manifest = {parsed: boolean; package: string; application: string; permissions: string[]; components: Component[]};
type Tag = {tag: string; attributes: Record<string, string>};
const RANK: Record<Severity, number> = {low: 0, medium: 1, high: 2, critical: 3};
const LABEL: Record<Severity, string> = {low: "rendah", medium: "sedang", high: "tinggi", critical: "kritis"};
// [key, class descriptor, members]. Fields (CONTENT_URI) are matched the same way as methods.
const APIS: [string, string, string][] = [
  ["smsSend", "Landroid/telephony/SmsManager;", "sendTextMessage|sendMultipartTextMessage|sendDataMessage"],
  ["smsSend", "Landroid/telephony/gsm/SmsManager;", "sendTextMessage|sendMultipartTextMessage|sendDataMessage"],
  ["smsRead", "Landroid/telephony/SmsMessage;", "createFromPdu|getMessageBody|getDisplayMessageBody|getOriginatingAddress"],
  ["smsRead", "Landroid/telephony/gsm/SmsMessage;", "createFromPdu|getMessageBody|getDisplayMessageBody"],
  ["smsRead", "Landroid/provider/Telephony$Sms$Intents;", "getMessagesFromIntent"],
  ["smsRead", "Landroid/provider/Telephony$Sms;", "CONTENT_URI"], ["smsRead", "Landroid/provider/Telephony$Sms$Inbox;", "CONTENT_URI"],
  ["a11yAct", "Landroid/accessibilityservice/AccessibilityService;", "performGlobalAction|dispatchGesture|getRootInActiveWindow|takeScreenshot"],
  ["a11yNode", "Landroid/view/accessibility/AccessibilityNodeInfo;", "performAction|findAccessibilityNodeInfosByViewId|findAccessibilityNodeInfosByText"],
  ["overlay", "Landroid/provider/Settings;", "canDrawOverlays"],
  ["addView", "Landroid/view/WindowManager;", "addView"], ["addView", "Landroid/view/ViewManager;", "addView"],
  ["notif", "Landroid/service/notification/NotificationListenerService;", "cancelNotification|cancelAllNotifications|getActiveNotifications"],
  ["admin", "Landroid/app/admin/DevicePolicyManager;", "lockNow|resetPassword|resetPasswordWithToken|wipeData|setCameraDisabled"],
  ["dexLoad", "Ldalvik/system/DexClassLoader;", "<init>"], ["dexLoad", "Ldalvik/system/InMemoryDexClassLoader;", "<init>"],
  ["dexLoad", "Ldalvik/system/PathClassLoader;", "<init>"], ["dexLoad", "Ldalvik/system/DexFile;", "loadDex|<init>"], ["dexLoad", "Ljava/lang/System;", "load"],
  ["exec", "Ljava/lang/Runtime;", "exec"], ["exec", "Ljava/lang/ProcessBuilder;", "start"],
  ["hideIcon", "Landroid/content/pm/PackageManager;", "setComponentEnabledSetting"],
  ["install", "Landroid/content/pm/PackageInstaller;", "createSession"], ["install", "Landroid/content/pm/PackageInstaller$Session;", "commit|openWrite"],
  ["projection", "Landroid/media/projection/MediaProjectionManager;", "createScreenCaptureIntent|getMediaProjection"], ["projection", "Landroid/media/projection/MediaProjection;", "createVirtualDisplay"],
  ["contacts", "Landroid/provider/ContactsContract$Contacts;", "CONTENT_URI"], ["contacts", "Landroid/provider/ContactsContract$CommonDataKinds$Phone;", "CONTENT_URI"],
  ["contacts", "Landroid/provider/ContactsContract$Data;", "CONTENT_URI"],
  ["callLog", "Landroid/provider/CallLog$Calls;", "CONTENT_URI"],
  ["deviceId", "Landroid/telephony/TelephonyManager;", "getDeviceId|getImei|getMeid|getLine1Number|getSimSerialNumber|getSubscriberId"],
  ["ussd", "Landroid/telephony/TelephonyManager;", "sendUssdRequest"],
  ["record", "Landroid/media/MediaRecorder;", "setAudioSource|setVideoSource"], ["record", "Landroid/media/AudioRecord;", "startRecording"],
  ["record", "Landroid/hardware/Camera;", "open|takePicture"], ["record", "Landroid/hardware/camera2/CameraManager;", "openCamera"],
  ["location", "Landroid/location/LocationManager;", "requestLocationUpdates|getLastKnownLocation|getCurrentLocation"],
  ["location", "Lcom/google/android/gms/location/FusedLocationProviderClient;", "getLastLocation|requestLocationUpdates|getCurrentLocation"],
  ["smtp", "Ljavax/mail/Transport;", "send"],
  // Network sinks: never a behavior on their own, only used to link SMS access to sending code (same class/package).
  ["net", "Ljava/net/URL;", "openConnection|openStream"], ["net", "Ljava/net/HttpURLConnection;", "connect|getOutputStream|setRequestMethod|getResponseCode"],
  ["net", "Ljavax/net/ssl/HttpsURLConnection;", "connect|getOutputStream|setRequestMethod|getResponseCode"], ["net", "Ljava/net/URLConnection;", "connect|getOutputStream|getInputStream"],
  ["net", "Lokhttp3/OkHttpClient;", "newCall|newWebSocket"], ["net", "Lokhttp3/Call;", "execute|enqueue"], ["net", "Lokhttp3/Request$Builder;", "url|post"],
  ["net", "Lcom/android/volley/RequestQueue;", "add"], ["net", "Lcom/android/volley/toolbox/Volley;", "newRequestQueue"], ["net", "Lretrofit2/Retrofit$Builder;", "baseUrl"],
  ["net", "Ljava/net/Socket;", "<init>|connect"], ["net", "Lorg/java_websocket/client/WebSocketClient;", "connect|send"], ["net", "Lio/socket/client/Socket;", "emit|connect"],
  ["net", "Lcom/google/firebase/database/DatabaseReference;", "setValue|push|updateChildren"], ["net", "Lcom/loopj/android/http/AsyncHttpClient;", "post|get"],
];
const CLASS = new Map<string, [string, Set<string>][]>();
for (const [key, cls, members] of APIS) CLASS.set(cls, [...CLASS.get(cls) || [], [key, new Set(members.split("|"))]]);
const SUPERS: Record<string, string> = {
  "Landroid/accessibilityservice/AccessibilityService;": "a11y", "Landroid/service/notification/NotificationListenerService;": "notif",
  "Landroid/app/admin/DeviceAdminReceiver;": "admin", "Landroid/nfc/cardemulation/HostApduService;": "nfc",
  "Landroid/inputmethodservice/InputMethodService;": "ime", "Landroid/content/BroadcastReceiver;": "receiver",
};
const RECEIVER = "Landroid/content/BroadcastReceiver;";
// What parseDex should record call sites / const-string sites for.
const refRules = (ref: string) => {const i = ref.indexOf(";->"); const rules = i > 0 ? CLASS.get(ref.slice(0, i + 1)) : undefined; return rules ? rules.filter(([, ms]) => ms.has(ref.slice(i + 3))).map(([k]) => [k, `${simple(ref.slice(0, i + 1))}.${ref.slice(i + 3)}`]) : [];};
export const trackedRef = (ref: string) => refRules(ref).length > 0;
const EXFIL = /api\.telegram\.org|(?<![\d])\d{6,12}:AA[\w-]{30,40}|discord(?:app)?\.com\/api\/webhooks|hooks\.slack\.com|firebaseio\.com|firebasedatabase\.app|ngrok|trycloudflare|webhook\.site|pipedream|\b(?:https?|wss?|tcp):\/\/(?:\d{1,3}\.){3}\d{1,3}|https?:\/\/[^\s"'<>]+\.php\b|\bsmtp\.[a-z0-9-]+\./i;
export const trackedString = (s: string) => s.length <= 1200 && EXFIL.test(s);
// Recovered (deobfuscated) values worth reporting; STRONG ones are reported even when hidden inside library code.
export const revealable = (s: string) => /:\/\/|api\.telegram|(?<![\d])\d{6,12}:AA[\w-]{30,40}|discord|hooks\.slack|chat_id|content:\/\/(?:sms|contacts|call_log)|\bsmtp\.|SMS_RECEIVED|\b(?:\d{1,3}\.){3}\d{1,3}\b|\.php\b|firebaseio|ngrok|trycloudflare|webhook/i.test(s);
const STRONG = /api\.telegram|(?<![\d])\d{6,12}:AA[\w-]{30,40}|discord(?:app)?\.com\/api\/webhooks|hooks\.slack|ngrok|trycloudflare|webhook\.site|pipedream/i;
// Strings: one cheap prefilter, then the specific category patterns. Token/webhook secrets are redacted before storage.
const TOKEN = /(?<![\d])(\d{6,12}):(AA[\w-]{30,40})(?![\w-])/;
const STRINGS: [string, RegExp][] = [
  ["telegram", /api\.telegram\.org|(?<![\d])\d{6,12}:AA[\w-]{30,40}(?![\w-])/i],
  ["discord", /discord(?:app)?\.com\/api\/webhooks\//i], ["slack", /hooks\.slack\.com\/services\//i],
  ["firebase", /https?:\/\/[a-z0-9-]+\.(?:firebaseio\.com|firebasedatabase\.app)/i],
  ["ipUrl", /\b(?:https?|wss?|tcp):\/\/(?!(?:127|10|0)\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}\b/i],
  ["php", /https?:\/\/[^\s"'<>]+\.php\b/i],
  ["tunnel", /ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|webhook\.site|pipedream\.net|000webhostapp\.com|requestbin|beeceptor\.com|serveo\.net|\.loca\.lt\b/i],
  ["smtp", /\bsmtp\.[a-z0-9-]+\.[a-z]{2,}|mail\.smtp\.host/i],
  ["smsUri", /content:\/\/sms|android\.provider\.Telephony\.(?:SMS_RECEIVED|SMS_DELIVER)/i],
  ["contactsUri", /content:\/\/(?:com\.android\.)?contacts/i], ["callLogUri", /content:\/\/call_log/i],
  ["ussd", /(?:^|tel:)\*{1,2}(?:21|61|62|67|002|004)\*|%2321%23|^\*#(?:21|62|67)#/i], ["actionCall", /^android\.intent\.action\.CALL$/],
  ["overlaySettings", /MANAGE_OVERLAY_PERMISSION/], ["a11ySettings", /ACCESSIBILITY_SETTINGS|enabled_accessibility_services/],
  ["notifSettings", /enabled_notification_listeners|NOTIFICATION_LISTENER_SETTINGS/], ["adminAdd", /android\.app\.action\.ADD_DEVICE_ADMIN/],
  ["apkMime", /application\/vnd\.android\.package-archive/],
  ["otp", /\b(?:otp|kode verifikasi|kode otp|verification code|one[- ]time password|kode rahasia|kode keamanan|jangan berikan kode)\b/i],
  ["root", /^(?:\/system\/(?:x?bin|sbin)\/su|Superuser\.apk|com\.topjohnwu\.magisk)$/],
  ["lure", /\b(?:undangan|pernikahan|kurir|paket|resi|tagihan|bpjs|pajak|tilang|mandiri|brimo|livin|gopay|shopeepay|kode verifikasi|m-?banking|jne|sicepat)\b|\b(?:PLN|BRI|BCA|BNI|DANA|OVO|OTP|DJP|J&T)\b/],
];
// Lure words are case-insensitive; short bank/e-wallet acronyms only count in upper case (avoids "dana", "bri" in identifiers).
const LURE_WORDS = /\b(?:undangan|pernikahan|kurir|paket|resi|tagihan|bpjs|pajak|tilang|mandiri|brimo|livin|gopay|shopeepay|kode verifikasi|m-?banking|jne|sicepat)\b/i;
const PREFILTER = new RegExp(STRINGS.map(([, r]) => r.source).join("|"), "i");
const INDONESIAN = /\b(?:yang|dan|anda|untuk|silakan|silahkan|mohon|klik|izinkan|aplikasi|tidak|dengan|kami|berhasil|gagal|masukkan|nomor|segera|selamat)\b/i;
const URL = /\b(?:https?|wss?):\/\/[^\s"'<>\\]{3,300}/gi;
const NOISE = /^https?:\/\/(?:[\w-]+\.)*(?:schemas\.android\.com|w3\.org|xmlpull\.org|apache\.org|xml\.org|json-schema\.org|ns\.adobe\.com|purl\.org|schemas\.microsoft\.com|example\.(?:com|org))(?:[\/:?#]|$)|%[sd]|\{\w*\}/i;
export function redactSecrets(s: string) {
  return s.replace(/(?<![\d])(\d{6,12}):([\w-]{30,45})(?![\w-])/g, (_, id: string, key: string) => `${id}:…${key.slice(-4)}`)
    .replace(/(discord(?:app)?\.com\/api\/webhooks\/\d+\/)[\w-]+/gi, "$1…").replace(/(hooks\.slack\.com\/services\/[\w]+\/[\w]+\/)[\w]+/gi, "$1…");
}
const put = (m: Map<string, Set<string>>, k: string, v: string, max = 8) => {let s = m.get(k); if (!s) m.set(k, s = new Set()); if (s.size < max) s.add(v);};
const simple = (descriptor: string) => descriptor.replace(/^L|;$/g, "").split("/").pop() || descriptor;
const dotted = (descriptor: string) => descriptor.replace(/^L|;$/g, "").replace(/\//g, ".").slice(0, 160);
const owner = (ref: string) => ref.slice(0, ref.indexOf(";->") + 1);
export const member = (ref: string) => {const i = ref.indexOf(";->"); return i < 0 ? ref.slice(0, 160) : `${dotted(ref.slice(0, i + 1))}.${ref.slice(i + 3, i + 63)}`;};
const pkg = (descriptor: string) => descriptor.slice(0, descriptor.lastIndexOf("/") + 1);
type Calls = {app: Set<string>; lib: Set<string>; unknown: boolean};
export type HiddenString = {value: string; technique: string; where: string; lib: boolean};
export class Signals {
  apis = new Map<string, Set<string>>(); subclasses = new Map<string, Set<string>>(); libSubclasses = new Map<string, Set<string>>(); hits = new Map<string, Set<string>>();
  bots = new Set<string>(); chats = new Set<string>(); urls = new Set<string>(); idText = new Set<string>(); text = new Set<string>();
  // Bytecode facts: callers per catalog entry, app classes per API key (for linking), superclass map across all DEX files.
  calls = new Map<string, Calls>(); codeClasses = new Map<string, Set<string>>(); parents = new Map<string, string>(); hidden: HiddenString[] = [];
  codeGaps = false; library: (descriptor: string) => boolean = libraryClass; private rootOf: (c: string) => string = () => "";
  private call(entry: string) {let c = this.calls.get(entry); if (!c) this.calls.set(entry, c = {app: new Set(), lib: new Set(), unknown: false}); return c;}
  // Method/field refs; with `code` (bytecode decoded completely) callers become known for this DEX, otherwise unknown.
  refs(list: string[], code?: DexCode) {
    for (const r of list) for (const [key, entry] of refRules(r)) {put(this.apis, key, entry); if (!code?.complete) this.call(entry).unknown = true; else this.call(entry);}
  }
  sites(code: DexCode) {
    for (const s of code.sites) for (const [key, entry] of refRules(s.ref)) {
      const c = this.call(entry);
      for (const x of s.app) {if (c.app.size < 6) c.app.add(x); put(this.codeClasses, key, owner(x), 400);}
      for (const x of s.lib) if (c.lib.size < 3) c.lib.add(x);
    }
    for (const s of code.strings) for (const x of s.app) put(this.codeClasses, "exfil", owner(x), 400);
    for (const r of code.recovered) this.reveal(r);
  }
  // Deobfuscated strings: kept only when they look like endpoints/secrets, then scanned by the normal string rules.
  reveal(h: {value: string; technique: string; where?: string; lib?: boolean}) {
    if (!revealable(h.value) || h.lib && !STRONG.test(h.value)) return;
    const value = h.value.slice(0, 600);
    if (this.hidden.length < 40 && !this.hidden.some(x => x.value === value)) this.hidden.push({value, technique: h.technique, where: h.where || "", lib: Boolean(h.lib)});
    this.strings([value], `(disamarkan: ${h.technique}) `);
    if (h.where?.includes(";->") && !h.lib && trackedString(value)) put(this.codeClasses, "exfil", owner(h.where), 400);
  }
  classes(list: {name: string; superclass: string}[]) {for (const c of list) if (c.superclass && c.superclass !== "Ljava/lang/Object;" && this.parents.size < 400000) this.parents.set(c.name, c.superclass);}
  // Resolves (in)direct subclasses of framework classes across all DEX files, depth-capped and memoized.
  resolve() {
    const memo = new Map<string, string>();
    const root = (c: string) => {
      const path: string[] = []; let x = c, r = "";
      for (let d = 0; d < 16; d++) {if (d && SUPERS[x]) {r = x; break;} const m = memo.get(x); if (m !== undefined) {r = m; break;} const s = this.parents.get(x); if (!s) break; path.push(x); x = s;}
      for (const p of path) memo.set(p, r); return r;
    };
    this.subclasses.clear(); this.libSubclasses.clear();
    for (const [c, s] of this.parents) {
      if (SUPERS[c]) continue; const r = root(c), key = r && SUPERS[r]; if (!key || key === "receiver") continue;
      put(this.library(c) ? this.libSubclasses : this.subclasses, key, s === r ? dotted(c) : `${dotted(c)} (turunan tidak langsung via ${dotted(s)})`, 5);
    }
    this.rootOf = root;
  }
  // Compact per-API caller summary for metadata (network sinks omitted).
  callSites(max = 25) {
    const out: {api: string; app: string[]; library: string[]; libraryOnly?: boolean}[] = [];
    for (const [key, set] of this.apis) if (key !== "net") for (const e of set) {
      const c = this.calls.get(e); if (!c || out.length >= max || !c.app.size && !c.lib.size && !this.libOnly(e)) continue;
      out.push({api: e, app: [...c.app].slice(0, 3).map(member), library: [...c.lib].slice(0, 2).map(member), ...this.libOnly(e) ? {libraryOnly: true} : {}});
    }
    return out;
  }
  libOnly(entry: string) {const c = this.calls.get(entry); return !this.codeGaps && Boolean(c) && !c!.unknown && c!.app.size === 0;}
  callers(keys: string[]) {return [...new Set(keys.flatMap(k => [...this.apis.get(k) || []]).flatMap(e => [...this.calls.get(e)?.app || []]).map(member))];}
  // App classes calling `key` APIs that are (indirect) BroadcastReceivers.
  receivers(key: string) {return [...this.codeClasses.get(key) || []].filter(c => this.rootOf(c) === RECEIVER);}
  libraryEvidence(evidence: string[]) {
    const out: string[] = [];
    for (const [entry, c] of this.calls) if (out.length < 3 && this.libOnly(entry) && evidence.some(e => e.includes(entry))) out.push(`${entry} ← ${c.lib.size ? [...c.lib].slice(0, 2).map(member).join(", ") : "tidak ada pemanggilan langsung"}`);
    return out.join("; ");
  }
  // SMS-reading app code linked to a sending sink (network API, SMS send, SMTP, exfil string) in the same class/package.
  smsLink() {
    const sms = [...this.codeClasses.get("smsRead") || []]; if (!sms.length) return "";
    const label: Record<string, string> = {net: "koneksi jaringan", smsSend: "pengiriman SMS", smtp: "email SMTP", exfil: "alamat exfiltrasi (string)"}, sinks = new Map<string, string>(), pkgs = new Map<string, string>();
    for (const k of ["exfil", "net", "smtp", "smsSend"]) for (const c of this.codeClasses.get(k) || []) {if (!sinks.has(c)) sinks.set(c, k); if (!pkgs.has(pkg(c))) pkgs.set(pkg(c), c);}
    for (const c of sms) {const k = sinks.get(c); if (k) return `${dotted(c)} membaca SMS dan memakai ${label[k]} di kelas yang sama`;}
    for (const c of sms) {const d = pkgs.get(pkg(c)); if (d) return `${dotted(c)} membaca SMS; ${dotted(d)} di paket yang sama memakai ${label[sinks.get(d)!]}`;}
    return "";
  }
  strings(list: Iterable<string>, source = "") {
    for (const raw of list) {
      if (raw.length < 3 || raw.charCodeAt(raw.length - 1) === 59 && /^\[*L[\w$/-]+;$/.test(raw)) continue;
      let s = raw.length > 1200 ? raw.slice(0, 1200) : raw;
      const b64 = s.length < 2048 && s.match(/aHR0c[A-Za-z0-9+/]{8,}={0,2}/)?.[0];
      if (b64) {const d = Buffer.from(b64, "base64").toString("latin1"); if (/^[\x20-\x7e]+$/.test(d)) s = `${s} [base64: ${d}]`;}
      if (s.includes("://")) for (const u of s.match(URL) || []) if (this.urls.size < 3000 && !NOISE.test(u)) this.urls.add(redactSecrets(u.replace(/[).,;]+$/, "")));
      if (/\s/.test(s) && s.length >= 12 && s.length <= 220 && /^[^\x00-\x1f]*$/.test(s) && /[a-z]{3}/i.test(s)) {if (INDONESIAN.test(s)) {if (this.idText.size < 80) this.idText.add(s);} else if (this.text.size < 40 && !/[{}<>;=]/.test(s)) this.text.add(s);}
      if (!PREFILTER.test(s)) continue;
      for (const [cat, re] of STRINGS) if (cat === "lure" ? re.test(s) || LURE_WORDS.test(s) : re.test(s)) put(this.hits, cat, `${source}${redactSecrets(s).slice(0, 160)}`, 12);
      const t = s.match(TOKEN); if (t && this.bots.size < 10) this.bots.add(`${t[1]}:…${t[2].slice(-4)}`);
      const chat = s.match(/chat_id["'=:\s]+(-?\d{5,15})/i)?.[1] || (/^-100\d{8,13}$/.test(s) ? s : ""); if (chat && this.chats.size < 10) this.chats.add(chat);
    }
  }
  // Evidence ordering for Artifact.strings: matched/suspicious strings first, then Indonesian UI text, then other prose.
  samples() {return [...[...this.hits.values()].flatMap(s => [...s]), ...this.idText, ...this.text];}
  rankedUrls() {
    const score = (u: string) => /telegram|discord|slack|ngrok|trycloudflare|webhook|pipedream|000webhost/i.test(u) ? 0 : /:\/\/(?:\d{1,3}\.){3}\d{1,3}|\.php\b|firebaseio|firebasedatabase/i.test(u) ? 1 : /google|gstatic|android\.com|facebook|firebase|crashlytics|github/i.test(u) ? 3 : 2;
    return [...this.urls].sort((a, b) => score(a) - score(b));
  }
}
export function manifestModel(tags: Tag[] | null): Manifest {
  const m: Manifest = {parsed: Boolean(tags), package: "", application: "", permissions: [], components: []};
  for (const t of tags || []) {
    const a = t.attributes, last = m.components[m.components.length - 1];
    if (t.tag === "manifest") m.package = a.package || "";
    else if (t.tag === "application") m.application = a.name || "";
    else if (t.tag.startsWith("uses-permission") && a.name) m.permissions.push(a.name);
    else if (/^(activity|activity-alias|service|receiver|provider)$/.test(t.tag)) m.components.push({tag: t.tag, name: a.name || a.targetActivity || "", permission: a.permission || "", actions: [], categories: []});
    else if (t.tag === "action" && last && a.name) {if (last.actions.length < 30) last.actions.push(a.name);}
    else if (t.tag === "category" && last && a.name) {if (last.categories.length < 30) last.categories.push(a.name);}
  }
  return m;
}
export const hasLauncher = (m: Manifest) => m.components.some(c => /^activity/.test(c.tag) && c.actions.includes("android.intent.action.MAIN") && c.categories.some(x => /LAUNCHER|LEANBACK_LAUNCHER/.test(x)));
const join = (label: string, xs: string[], n = 5) => xs.length ? `${label}: ${xs.slice(0, n).join(", ").slice(0, 220)}${xs.length > n ? ` (+${xs.length - n})` : ""}` : "";
// Two passes when bytecode attribution is available: `strict` ignores APIs called only from known library code and
// library-only subclasses; behaviors that exist only in the lenient pass are kept as low-severity "library only".
const COMBOS = new Set(["sms_stealer", "banking_trojan", "dropper", "otp_intercept"]);
export function evaluate(sig: Signals, m: Manifest, extra: Behavior[] = [], context: {certSha256?: string} = {}): Behavior[] {
  sig.resolve();
  const strict = rules(sig, m, extra, context, true);
  if (![...sig.apis.values()].some(set => [...set].some(e => sig.libOnly(e))) && !sig.libSubclasses.size && !sig.hidden.some(h => h.lib)) return strict;
  const loose = rules(sig, m, extra, context, false);
  for (const b of loose) {
    const kept = strict.find(x => x.id === b.id), lib = sig.libraryEvidence(b.evidence);
    if (!kept && !COMBOS.has(b.id)) strict.push({id: b.id, name: `${b.name} (tidak dipanggil kode aplikasi)`, severity: "low", evidence: ["API hanya dipanggil kode library pihak ketiga atau tidak dipanggil sama sekali", lib ? `library: ${lib}` : "", ...b.evidence].filter(Boolean).slice(0, 6)});
    else if (kept && RANK[b.severity] > RANK[kept.severity] && lib) kept.evidence = [...kept.evidence, `keparahan diturunkan: sebagian API hanya dipanggil library (${lib})`].slice(0, 7);
  }
  return strict.sort((a, b) => RANK[b.severity] - RANK[a.severity]);
}
function rules(sig: Signals, m: Manifest, extra: Behavior[], context: {certSha256?: string}, strict: boolean): Behavior[] {
  const out: Behavior[] = extra.map(b => ({...b})), has = (id: string) => out.find(b => b.id === id);
  const api = (...keys: string[]) => keys.flatMap(k => [...sig.apis.get(k) || []]).filter(e => !strict || !sig.libOnly(e));
  const calls = (...keys: string[]) => strict ? join("dipanggil oleh", sig.callers(keys), 3) : "";
  const str = (...cats: string[]) => cats.flatMap(k => [...sig.hits.get(k) || []]);
  const sub = (k: string) => [...sig.subclasses.get(k) || [], ...strict ? [] : sig.libSubclasses.get(k) || []];
  const perm = (...names: string[]) => m.permissions.map(p => p.split(".").pop() || p).filter(p => names.includes(p));
  const comp = (test: (c: Component) => boolean) => m.components.filter(test).map(c => `${c.tag} ${c.name.slice(0, 90)}`);
  const action = (re: RegExp) => comp(c => c.actions.some(a => re.test(a)));
  const add = (id: string, name: string, severity: Severity, evidence: string[]) => {const e = evidence.filter(Boolean); if (e.length) out.push({id, name, severity, evidence: e.slice(0, 7)}); return e.length > 0;};
  const declared = new Set(m.components.map(c => c.name));
  const smsPerm = perm("RECEIVE_SMS", "READ_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH"), smsApi = api("smsRead"), smsRecv = action(/SMS_RECEIVED|SMS_DELIVER|WAP_PUSH_RECEIVED/), smsStr = str("smsUri");
  // BroadcastReceiver subclasses (direct or indirect) whose own code parses SMS; undeclared ones are registered at runtime.
  const smsCode = sig.receivers("smsRead").map(c => {const d = dotted(c); return declared.has(d) ? d : `${d} (tidak ada di manifest: didaftarkan saat runtime)`;});
  add("sms_read", "Membaca atau mencegat SMS", smsRecv.length || smsCode.length || smsApi.length && smsPerm.length ? "high" : "medium", [join("izin", smsPerm), join("API", smsApi), calls("smsRead"), join("penerima SMS", smsRecv, 3), join("receiver SMS di kode", smsCode, 2), join("string", smsStr, 3)]);
  const sendPerm = perm("SEND_SMS"), sendApi = api("smsSend");
  add("sms_send", "Mengirim SMS tanpa interaksi pengguna", sendApi.length && sendPerm.length ? "high" : "medium", [join("izin", sendPerm), join("API", sendApi), sendApi.length ? calls("smsSend") : ""]);
  const a11yDecl = [...sub("a11y"), ...comp(c => c.permission.endsWith("BIND_ACCESSIBILITY_SERVICE") || c.actions.includes("android.accessibilityservice.AccessibilityService"))], a11yAct = api("a11yAct");
  if (a11yDecl.length || a11yAct.length) add("accessibility", "Penyalahgunaan layanan aksesibilitas", a11yAct.length ? "high" : "medium", [join("layanan aksesibilitas", a11yDecl, 3), join("API", [...a11yAct, ...api("a11yNode")]), a11yAct.length ? calls("a11yAct", "a11yNode") : "", join("string", str("a11ySettings"), 2)]);
  const overlayPerm = perm("SYSTEM_ALERT_WINDOW"), overlayApi = api("overlay"), overlayStr = str("overlaySettings");
  // Settings strings/addView alone are common in frameworks (e.g. dev tooling), so they only support a permission or API hit.
  if (overlayPerm.length || overlayApi.length && overlayStr.length) add("overlay", "Menampilkan overlay di atas aplikasi lain", "medium", [join("izin", overlayPerm), join("API", [...overlayApi, ...api("addView")]), join("string", overlayStr, 2)]);
  const notifDecl = [...sub("notif"), ...comp(c => c.permission.endsWith("BIND_NOTIFICATION_LISTENER_SERVICE"))], notifApi = api("notif");
  if (notifDecl.length) add("notification_listener", "Membaca notifikasi aplikasi lain", notifApi.some(x => /cancel/.test(x)) ? "high" : "medium", [join("listener", notifDecl, 3), join("API", notifApi), notifApi.length ? calls("notif") : "", join("string", str("notifSettings"), 2)]);
  const adminDecl = [...sub("admin"), ...comp(c => c.permission.endsWith("BIND_DEVICE_ADMIN") || c.actions.includes("android.app.action.DEVICE_ADMIN_ENABLED"))], adminApi = api("admin");
  if (adminDecl.length || adminApi.length || str("adminAdd").length) add("device_admin", "Meminta hak admin perangkat", adminApi.some(x => /lockNow|resetPassword|wipeData/.test(x)) ? "high" : "medium", [join("receiver admin", adminDecl, 3), join("API", adminApi), adminApi.length ? calls("admin") : "", join("string", str("adminAdd"), 1)]);
  const ime = [...sub("ime"), ...comp(c => c.permission.endsWith("BIND_INPUT_METHOD"))];
  if (ime.length) add("keyboard", "Keyboard kustom (dapat merekam ketikan)", comp(c => c.permission.endsWith("BIND_INPUT_METHOD")).length ? "medium" : "low", [join("keyboard (InputMethodService)", ime, 3)]);
  const otp = str("otp");
  if (otp.length && (has("sms_read") || has("notification_listener") || has("accessibility"))) add("otp_intercept", "Penyadapan kode OTP", "high", [join("string OTP", otp, 3), `sumber: ${["sms_read", "notification_listener", "accessibility"].filter(has).join(", ")}`]);
  const loaders = api("dexLoad"), dexLoaders = loaders.filter(x => /DexClassLoader|InMemoryDex|DexFile/.test(x));
  add("dynamic_code", "Memuat kode secara dinamis", has("hidden_payload") && loaders.length ? "high" : dexLoaders.length ? "medium" : "low", [join("API", [...dexLoaders, ...loaders.filter(x => !dexLoaders.includes(x))]), loaders.length ? calls("dexLoad") : ""]);
  add("shell_exec", "Menjalankan perintah shell / cek root", "low", [join("API", api("exec")), join("string", str("root"), 3)]);
  const launcher = hasLauncher(m), hideApi = api("hideIcon"), risky = ["sms_read", "sms_send", "accessibility", "notification_listener", "device_admin"].some(has);
  if (m.parsed && !launcher || hideApi.length && risky) add("hidden_icon", "Menyembunyikan ikon aplikasi", "medium", [m.parsed && !launcher ? "Tidak ada activity MAIN/LAUNCHER di manifest" : "", risky ? join("API", hideApi) : "", risky && hideApi.length ? calls("hideIcon") : ""]);
  add("install_apps", "Memasang APK lain", api("install").length ? "medium" : "low", [join("izin", perm("REQUEST_INSTALL_PACKAGES", "INSTALL_PACKAGES")), join("API", api("install")), join("string", str("apkMime"), 1)]);
  add("screen_capture", "Merekam atau menyiarkan layar", "medium", [join("API", api("projection")), join("izin", perm("FOREGROUND_SERVICE_MEDIA_PROJECTION"))]);
  add("contacts", "Mengambil daftar kontak", api("contacts").length || str("contactsUri").length ? "medium" : "low", [join("izin", perm("READ_CONTACTS")), join("API", api("contacts")), join("string", str("contactsUri"), 2)]);
  add("call_log", "Mengambil riwayat panggilan", api("callLog").length || str("callLogUri").length ? "medium" : "low", [join("izin", perm("READ_CALL_LOG")), join("API", api("callLog")), join("string", str("callLogUri"), 2)]);
  const ids = api("deviceId");
  add("device_identifiers", "Mengambil identitas perangkat/SIM", ids.some(x => /Line1Number|SimSerial|Subscriber/.test(x)) ? "medium" : "low", [join("API", ids), ids.length ? join("izin", perm("READ_PHONE_STATE", "READ_PHONE_NUMBERS")) : ""]);
  const ussd = str("ussd"), callPerm = perm("CALL_PHONE");
  if (ussd.length || api("ussd").length) add("call_forwarding", "Pengalihan panggilan / kode USSD", ussd.length && (callPerm.length || str("actionCall").length) ? "high" : "medium", [join("kode", ussd, 3), join("API", api("ussd")), join("izin", callPerm)]);
  add("boot_persistence", "Berjalan otomatis setelah perangkat menyala", "low", [join("izin", perm("RECEIVE_BOOT_COMPLETED")), join("receiver", action(/BOOT_COMPLETED|QUICKBOOT_POWERON/), 3)]);
  const rec = api("record"); if (rec.length) add("camera_mic", "Merekam kamera/mikrofon", "low", [join("API", rec), join("izin", perm("CAMERA", "RECORD_AUDIO"))]);
  const loc = api("location"); if (loc.length) add("location", "Melacak lokasi", perm("ACCESS_BACKGROUND_LOCATION").length ? "medium" : "low", [join("API", loc), join("izin", perm("ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION"))]);
  const nfc = [...sub("nfc"), ...comp(c => c.permission.endsWith("BIND_NFC_SERVICE"))]; if (nfc.length) add("nfc_relay", "Emulasi kartu NFC (potensi relay kartu)", "medium", [join("layanan HCE", nfc, 3)]);
  // Strings recovered from simple obfuscation (base64/hex/reversed/arrays/XOR/StringBuilder).
  const secret = sig.hidden.filter(h => !strict || !h.lib);
  add("obfuscated_strings", "String disamarkan berisi alamat/rahasia", secret.some(h => STRONG.test(h.value)) ? "high" : "medium", secret.slice(0, 6).map(h => `${redactSecrets(h.value).slice(0, 110)} (disamarkan: ${h.technique})${h.where ? ` di ${member(h.where)}` : ""}`));
  // Exfiltration channels.
  const bots = [...sig.bots], chats = [...sig.chats];
  add("exfil_telegram", "Mengirim data ke bot Telegram", "high", [join("bot (token disamarkan)", bots), join("chat_id", chats), join("string", str("telegram"), 2)]);
  add("exfil_webhook", "Mengirim data ke webhook Discord/Slack", "high", [join("webhook", str("discord", "slack"), 3)]);
  add("exfil_firebase", "Menggunakan Firebase Realtime Database", "low", [join("URL", str("firebase"), 3)]);
  add("exfil_ip", "Server dengan alamat IP langsung", "medium", [join("URL", str("ipUrl"), 3)]);
  add("exfil_panel", "Endpoint panel web (PHP)", "medium", [join("URL", str("php"), 3)]);
  add("exfil_tunnel", "Layanan tunnel/webhook sementara", "high", [join("URL", str("tunnel"), 3)]);
  add("exfil_email", "Mengirim data lewat email (SMTP)", "medium", [join("API", api("smtp")), join("string", str("smtp"), 2)]);
  add("lure_keywords", "Kata kunci umpan penipuan (konteks Indonesia)", "low", [join("string", str("lure"), 6)]);
  // Combined patterns.
  const exfil = out.filter(b => b.id.startsWith("exfil_")), strong = exfil.filter(b => /telegram|webhook|tunnel/.test(b.id));
  const hidden = has("hidden_icon"), activities = m.components.filter(c => /^activity/.test(c.tag)).length, minimalUi = m.parsed && activities <= 1;
  const campaign = [context.certSha256 ? `sertifikat SHA-256 ${context.certSha256}` : "", bots.length ? `bot Telegram ${bots.slice(0, 3).join(", ")}` : ""].filter(Boolean).join("; ");
  // Bytecode link: the class that reads SMS (or a class in its package) also sends data out.
  const link = strict && has("sms_read") ? sig.smsLink() : "";
  if (has("sms_read") && (exfil.length || perm("INTERNET").length || link)) add("sms_stealer", "Pola pencuri SMS/OTP (SMS + pengiriman ke server)", strong.length && (hidden || minimalUi || link) ? "critical" : "high", [
    `SMS: ${has("sms_read")!.evidence.slice(0, 2).join("; ")}`, `kanal: ${exfil.length ? exfil.map(b => b.name).join(", ") : link ? "kode jaringan/SMS" : "izin INTERNET"}`, link ? `rantai kode: ${link}`.slice(0, 200) : "",
    hidden ? "ikon peluncur disembunyikan/tidak ada" : "", minimalUi ? `UI minim (${activities} activity)` : "", has("otp_intercept") ? "teks OTP ditemukan" : "", campaign]);
  const a11y = has("accessibility");
  if (a11y && (has("overlay") || has("notification_listener") || has("sms_read"))) add("banking_trojan", "Pola trojan perbankan (aksesibilitas + overlay/penyadapan)", a11y.severity === "high" && has("overlay") && exfil.length ? "critical" : "high", [`kombinasi: ${["accessibility", "overlay", "notification_listener", "sms_read", "device_admin"].filter(has).join(" + ")}`, a11y.evidence[0], campaign]);
  if ((hidden || has("boot_persistence") && minimalUi) && (has("install_apps") || has("hidden_payload") || has("dynamic_code"))) add("dropper", "Pola dropper tersembunyi", "high", [`kombinasi: ${["hidden_icon", "install_apps", "hidden_payload", "dynamic_code", "boot_persistence"].filter(has).join(" + ")}`, campaign]);
  return out.sort((a, b) => RANK[b.severity] - RANK[a.severity]);
}
export const behaviorIndicator = (b: Behavior) => ({name: b.name, evidence: `Tingkat ${LABEL[b.severity]}: ${b.evidence.join("; ")}`.slice(0, 600)});
export const behaviorMetadata = (list: Behavior[]) => list.map(b => ({id: b.id, severity: b.severity, evidence: b.evidence.map(e => e.slice(0, 160))}));
