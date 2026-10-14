// Measures how well the static extractor flags real samples. Nothing is ever executed: files are only read
// and parsed by lib/extract.ts (no AI, no VirusTotal), exactly as the server does before the AI step.
//
//   Fetch real samples from MalwareBazaar (free Auth-Key from https://auth.abuse.ch):
//     ABUSE_CH_AUTH_KEY=... npx tsx scripts/eval-corpus.ts fetch --tag SMSspy --limit 40
//     ABUSE_CH_AUTH_KEY=... npx tsx scripts/eval-corpus.ts fetch --signature AgentTesla --type exe --limit 15
//   Legitimate F-Droid apps as a false-positive control set:
//     npx tsx scripts/eval-corpus.ts fetch-fdroid [--packages a,b] [--max-mb 90]
//   Evaluate a folder (put known-good apps in .corpus/benign to measure false alarms):
//     npx tsx scripts/eval-corpus.ts run .corpus/SMSspy [--json report.json]
//
// Samples live in .corpus/ (git-ignored). MalwareBazaar zips are encrypted with the password "infected";
// they are unpacked with bsdtar straight into that folder and keep a non-executable .apk/.exe/.pdf name.
import { execFileSync } from "node:child_process";
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { join, extname } from "node:path";
import { extractFile } from "../lib/extract";

const API = "https://mb-api.abuse.ch/api/v1/";
const SUPPORTED = new Set([".apk", ".exe", ".pdf", ".png", ".jpg"]);
const RANK: Record<string, number> = {none: 0, rejected: 0, low: 1, medium: 2, high: 3, critical: 4};
const arg = (name: string, fallback?: string) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : fallback; };

async function query(form: Record<string, string>) {
  const key = process.env.ABUSE_CH_AUTH_KEY; if (!key) throw new Error("Set ABUSE_CH_AUTH_KEY (free at https://auth.abuse.ch).");
  const response = await fetch(API, {method: "POST", headers: {"Auth-Key": key}, body: new URLSearchParams(form)});
  if (!response.ok) throw new Error(`MalwareBazaar HTTP ${response.status}`);
  return response;
}

async function fetchSamples() {
  // --signature uses the family name (get_siginfo); huge tags like AgentTesla time out as tag queries.
  const signature = arg("signature"), tag = signature ?? arg("tag", "SMSspy")!, limit = Number(arg("limit", "30")), type = arg("type", "apk")!;
  const dir = join(".corpus", tag.replace(/[^\w.-]/g, "_")); mkdirSync(dir, {recursive: true});
  const info = await (await query(signature ? {query: "get_siginfo", signature, limit: String(Math.min(1000, limit * 4))} : {query: "get_taginfo", tag, limit: String(Math.min(1000, limit * 3))})).json();
  if (info.query_status !== "ok") throw new Error(`MalwareBazaar: ${info.query_status}`);
  const picks = (info.data as {sha256_hash: string; file_type: string; signature: string | null}[]).filter(s => s.file_type === type).slice(0, limit);
  for (const sample of picks) {
    const target = join(dir, `${sample.sha256_hash}.${type}`);
    try { statSync(target); continue; } catch {}
    const zip = Buffer.from(await (await query({query: "get_file", sha256_hash: sample.sha256_hash})).arrayBuffer());
    const zipPath = join(dir, `${sample.sha256_hash}.zip`); writeFileSync(zipPath, zip);
    const unpacked = join(dir, `.tmp-${sample.sha256_hash}`); mkdirSync(unpacked, {recursive: true});
    try {
      execFileSync("bsdtar", ["-xf", zipPath, "-C", unpacked, "--passphrase", "infected"], {stdio: "ignore"});
      const [inner] = readdirSync(unpacked); if (!inner) throw new Error("empty archive");
      writeFileSync(target, readFileSync(join(unpacked, inner))); chmodSync(target, 0o444);
      console.log(`saved ${target} (${sample.signature ?? "unknown family"})`);
    } catch (error) { console.log(`skip ${sample.sha256_hash}: ${error instanceof Error ? error.message : error}`); }
    finally { rmSync(unpacked, {recursive: true, force: true}); rmSync(zipPath, {force: true}); }
  }
}

// Legitimate open-source apps from F-Droid as a false-positive control set. The defaults deliberately include
// apps whose permissions look like malware: SMS/dialer/contacts, a keyboard, app stores that install APKs,
// VPN/Tor, a password manager with autofill, and Telegram FOSS (Telegram API strings).
const FDROID_DEFAULT = ["org.fossify.messages", "org.fossify.phone", "org.fossify.contacts", "org.fossify.gallery", "helium314.keyboard", "org.telegram.messenger", "com.aurora.store", "org.fdroid.fdroid", "com.wireguard.android", "org.torproject.android", "com.kunzisoft.keepass.libre", "eu.faircode.email", "de.danoeh.antennapod", "org.schabi.newpipe", "com.termux", "org.wikipedia", "com.nextcloud.client", "org.tasks", "im.vector.app", "org.videolan.vlc", "net.thunderbird.android", "com.github.libretube", "org.localsend.localsend_app", "io.homeassistant.companion.android.minimal"];
async function fetchFdroid() {
  const packages = (arg("packages")?.split(",") ?? FDROID_DEFAULT).map(p => p.trim()).filter(Boolean), maxMb = Number(arg("max-mb", "90"));
  const dir = join(".corpus", "benign-fdroid"); mkdirSync(dir, {recursive: true});
  for (const name of packages) {
    try {
      const info = await (await fetch(`https://f-droid.org/api/v1/packages/${name}`)).json() as {suggestedVersionCode?: number};
      if (!info.suggestedVersionCode) { console.log(`skip ${name}: not on F-Droid`); continue; }
      const target = join(dir, `${name}_${info.suggestedVersionCode}.apk`); try { statSync(target); continue; } catch {}
      const response = await fetch(`https://f-droid.org/repo/${name}_${info.suggestedVersionCode}.apk`);
      if (!response.ok) { console.log(`skip ${name}: HTTP ${response.status}`); continue; }
      const size = Number(response.headers.get("content-length") || 0); if (size > maxMb * 1048576) { await response.body?.cancel(); console.log(`skip ${name}: ${Math.round(size / 1048576)} MB`); continue; }
      writeFileSync(target, Buffer.from(await response.arrayBuffer())); chmodSync(target, 0o444); console.log(`saved ${target}`);
    } catch (error) { console.log(`skip ${name}: ${error instanceof Error ? error.message : error}`); }
  }
}

async function evaluate() {
  const dir = process.argv[3]; if (!dir) throw new Error("Usage: run <folder> [--json out.json]");
  const files = readdirSync(dir).filter(f => SUPPORTED.has(extname(f).toLowerCase()));
  const rows: {file: string; mb: number; ms: number; level: string; incomplete: boolean; top: string[]}[] = [];
  const counts = new Map<string, number>();
  for (const file of files) {
    const buffer = readFileSync(join(dir, file)), started = performance.now();
    try {
      const a = await extractFile(buffer, file);
      const behaviors = (a.metadata.behaviors as {id: string; severity: string}[] | undefined) ?? [];
      const level = behaviors.reduce((max, b) => RANK[b.severity] > RANK[max] ? b.severity : max, "none" as string);
      for (const b of behaviors) counts.set(b.id, (counts.get(b.id) ?? 0) + 1);
      rows.push({file, mb: +(buffer.length / 1048576).toFixed(1), ms: Math.round(performance.now() - started), level, incomplete: a.incomplete, top: a.indicators.slice(0, 3).map(i => i.name)});
    } catch (error) { rows.push({file, mb: +(buffer.length / 1048576).toFixed(1), ms: Math.round(performance.now() - started), level: "rejected", incomplete: true, top: [error instanceof Error ? error.message : String(error)]}); }
    const row = rows.at(-1)!; console.log(`${row.level.padEnd(8)} ${String(row.ms).padStart(6)} ms ${String(row.mb).padStart(6)} MB  ${file.slice(0, 16)}…  ${row.top.join(" | ").slice(0, 110)}`);
  }
  const share = (test: (r: typeof rows[number]) => boolean) => `${rows.filter(test).length}/${rows.length} (${Math.round(rows.filter(test).length / Math.max(1, rows.length) * 100)}%)`;
  console.log(`\nSamples: ${rows.length}`);
  console.log(`High or critical: ${share(r => r.level === "high" || r.level === "critical")}`);
  console.log(`Medium or above:  ${share(r => RANK[r.level] >= 2)}`);
  console.log(`Nothing flagged:  ${share(r => r.level === "none")}`);
  console.log(`Incomplete parse: ${share(r => r.incomplete)}`);
  console.log(`Slowest: ${Math.max(0, ...rows.map(r => r.ms))} ms, average: ${Math.round(rows.reduce((s, r) => s + r.ms, 0) / Math.max(1, rows.length))} ms`);
  console.log(`Most common behaviors: ${[...counts].sort((x, y) => y[1] - x[1]).slice(0, 12).map(([id, n]) => `${id}×${n}`).join(", ")}`);
  const out = arg("json"); if (out) writeFileSync(out, JSON.stringify(rows, null, 2));
}

// CommonJS entry (no top-level await): pdf.js only resolves its dynamic import correctly outside tsx's ESM mode.
const command = process.argv[2];
(command === "fetch" ? fetchSamples() : command === "fetch-fdroid" ? fetchFdroid() : command === "run" ? evaluate() : Promise.reject(new Error("Commands: fetch | fetch-fdroid | run"))).catch(error => { console.error(error instanceof Error ? error.message : error); process.exitCode = 1; });
