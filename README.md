<div align="center">

<img src="public/icon.svg" width="96" alt="Kheronyx eye logo"/>

# Kheronyx

### 👁️ Revealing the hidden depth.

**AI-assisted static file intelligence for unmasking scam APKs, malicious EXEs and weaponized PDFs. It never runs the file.**

<a href="https://kheronyx.vercel.app"><img src="https://img.shields.io/badge/live-kheronyx.vercel.app-111?style=for-the-badge&logo=vercel&logoColor=white" alt="Live site"/></a>

<img src="https://img.shields.io/badge/Next.js-16-000?style=flat-square&logo=nextdotjs" alt="Next.js 16"/>
<img src="https://img.shields.io/badge/React-19-149ECA?style=flat-square&logo=react&logoColor=white" alt="React 19"/>
<img src="https://img.shields.io/badge/TypeScript-5-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript"/>
<img src="https://img.shields.io/badge/WebGL-shader-990000?style=flat-square&logo=webgl&logoColor=white" alt="WebGL"/>
<img src="https://img.shields.io/badge/Supabase-Postgres%20%2B%20pg__cron-3FCF8E?style=flat-square&logo=supabase&logoColor=white" alt="Supabase"/>
<img src="https://img.shields.io/badge/Vercel-Blob%20%2B%20Functions-000?style=flat-square&logo=vercel" alt="Vercel"/>
<br/>
<img src="https://img.shields.io/badge/tests-116%20passing-2ea44f?style=flat-square&logo=checkmarx&logoColor=white" alt="116 tests passing"/>
<img src="https://img.shields.io/badge/false%20alarms%20on%20F--Droid-0%2F19-2ea44f?style=flat-square&logo=android&logoColor=white" alt="0 of 19 legitimate apps falsely flagged"/>
<img src="https://img.shields.io/badge/VirusTotal-integrated-394EFF?style=flat-square&logo=virustotal&logoColor=white" alt="VirusTotal"/>
<img src="https://img.shields.io/badge/abuse.ch-threat%20intel-c0392b?style=flat-square" alt="abuse.ch"/>
<img src="https://img.shields.io/badge/Tria.ge-researcher%20sandbox-1f8a5b?style=flat-square" alt="Tria.ge researcher sandbox"/>
<img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT license"/>
<img src="https://img.shields.io/badge/made%20in-Indonesia%20🇮🇩-red?style=flat-square" alt="Made in Indonesia"/>

<br/><br/>

<img src="docs/screenshots/landing.png" alt="Kheronyx landing page" width="880"/>

</div>

---

## 🧭 Why Kheronyx?

In Indonesia, scams arrive as harmless-looking files: *"Undangan Pernikahan.apk"*, *"Cek Resi Paket.apk"*, *"Tagihan PLN.pdf"*. Once installed, these apps quietly read your SMS, grab your banking OTP and forward it to a Telegram bot.

Kheronyx lets anyone **look inside a file before opening it**. It takes the file apart byte by byte, checks it against global threat intelligence, and has an AI explain the risk in plain Bahasa Indonesia: **Aman · Waspada · Bahaya · Sangat bahaya**.

> [!IMPORTANT]
> Kheronyx performs **static analysis only**. Uploaded files are parsed, never executed. A clean result is never a guarantee of safety, and the app says so in every report.

## ✨ Highlights

| | |
|---|---|
| 🔬 **Deep static dissection** | Dalvik bytecode, binary XML manifests, signing blocks, ELF/PE/.NET metadata and PDF object streams are all parsed in pure TypeScript, with every parser bounded and fuzz-tested. |
| 🕵️ **Built for scam APKs** | Detects SMS/OTP stealers, Telegram-bot exfiltration, accessibility-abusing banking trojans, overlays, hidden icons, droppers and ~19 Android packers. |
| 🧬 **Knows who called what** | Decoded call sites tell app code from libraries, e.g. *"`SmsReceiver.onReceive` reads SMS **and** sends it to the panel"*. |
| 🧩 **Sees through tricks** | BadPack ZIP headers, empty `classes.dex`, zeroed manifest headers, XOR/base64/char-array string hiding, repackaged APKs (v2/v3 signature verification). |
| 🧪 **Sandbox (Tria.ge Researcher + VirusTotal)** | Opted-in APK/EXE files are looked up or submitted to the Tria.ge sandbox in the background; extracted malware configs (real C2 servers such as SpyNote's `ip:7771`, AgentTesla's SMTP/FTP drop accounts) and observed connections are merged into the report, checked against abuse.ch, and the AI re-assesses the verdict. VirusTotal's sandbox behaviour adds observed connections and MITRE ATT&CK techniques for known files. |
| 🛰️ **Threat intelligence** | VirusTotal reputation, abuse.ch **MalwareBazaar / URLhaus / ThreatFox** lookups, and **RDAP** domain age for every server found inside the file. |
| 🧑‍🤝‍🧑 **Made for non-experts** | Every report translates technical findings into plain consequences (*"can read your OTP codes and drain your account"*) plus emergency steps if the app was already installed. |
| 🤖 **AI verdict, with guardrails** | A schema-validated LLM report that must cite extracted evidence. Missing evidence can never produce a "safe" verdict. |
| 🕵️ **Attacker trace** | A red-labelled *"Jejak pelaku"* card collects what points at the operator: C2 servers (panels, raw IP:port, DDNS, tunnels, Telegram bots, even when hidden in base64/XOR), the name and email typed into the signing certificate, its SHA-256 fingerprint (same fingerprint = same author) and the malware family, each with a copy button for reports to authorities. |
| ☁️ **Close the tab, keep the job** | Analyses run as durable background jobs with automatic retries (Supabase `pg_cron`) and can be cancelled. |
| 🌫️ **Cinematic UX** | A WebGL fractal-noise smoke transition pours out from behind the landing eye. |

## 📸 A real scam APK, dissected

A real **SMSspy** sample from MalwareBazaar, renamed the way victims receive it:

<div align="center">
<img src="docs/screenshots/report.png" alt="Kheronyx report for a real SMS stealer" width="720"/>
</div>

<div align="center">
<img src="docs/screenshots/impact.png" alt="Plain-language impact card for non-technical users" width="720"/>
<br/><sub>What the file can do to your phone, explained for everyone, with emergency steps</sub>
</div>

<table>
<tr>
<td width="50%"><img src="docs/screenshots/threat-intel.png" alt="Threat intelligence panel"/></td>
<td width="25%"><img src="docs/screenshots/smoke-2.png" alt="WebGL smoke transition"/></td>
<td width="25%"><img src="docs/screenshots/mobile.png" alt="Mobile dashboard"/></td>
</tr>
<tr>
<td align="center"><sub>abuse.ch + RDAP intelligence</sub></td>
<td align="center"><sub>Smoke login transition</sub></td>
<td align="center"><sub>Responsive dashboard</sub></td>
</tr>
</table>

## 🎯 Measured on real malware *and* real apps

Measured with `scripts/eval-corpus.ts` on **142 real malware samples** from [MalwareBazaar](https://bazaar.abuse.ch) and **legitimate apps/files** as a false-alarm control. The run used the static extractor only, with no AI, no VirusTotal, no abuse.ch, and nothing executed. In production those layers only add to these numbers.

**🦠 Malware: does Kheronyx catch it?**

| Family | Type | Samples | 🔴 High / critical | 🟠 At least medium |
|---|:-:|:-:|:-:|:-:|
| **SMSspy** (SMS/OTP stealers) | APK | 30 | **100%** | **100%** |
| **SpyNote** (RAT / banker) | APK | 15 | **100%** | **100%** |
| **Cerberus** (banking trojan) | APK | 15 | **100%** | **100%** |
| **Hydra** (banking trojan) | APK | 15 | **100%** | **100%** |
| **Anubis** (banking trojan) | APK | 15 | 67% | 67% |
| **Joker** (subscription fraud) | APK | 2 | 50% | **100%** |
| **RedLine** (info-stealer) | EXE | 15 | 87% | 93% |
| **Lumma** (info-stealer, Go crypters) | EXE | 15 | 73% | 87% |
| **AgentTesla** (info-stealer) | EXE | 4 | **100%** | **100%** |
| **Malicious PDFs** | PDF | 15 | 27% | 40% |

**✅ Legitimate files: does Kheronyx falsely accuse them?**

| Control set | Files | 🔴 High / critical | 🟠 At least medium |
|---|:-:|:-:|:-:|
| F-Droid apps (SMS client, dialer, keyboard, app stores, VLC, Element…) | 19 | **0%** | 5% |
| Windows executables & DLLs (signed and unsigned) | 504 | 0.4% | 2% |
| PDFs (incl. 69 with JavaScript / forms / open actions) | 312 | **0%** | **0%** |

What the misses are: Anubis first-stage droppers that only "install another app" (statically identical to an app store), Go binaries without an encrypted blob, a 7-Zip self-extractor, and plain-text invoice PDFs with no links or code (email-fraud lures). Hash reputation (VirusTotal, MalwareBazaar) covers most of these in the live app.

Evaluation also surfaced real anti-analysis tricks that are now handled and tested: empty `classes.dex`, BadPack compression IDs, manifests with lying ZIP sizes and zeroed headers, poisoned string pools, SMS stealers claiming the default-SMS role, C2 addresses hidden in base64/XOR, and copied Authenticode signatures.

## 🔬 How it works

```mermaid
flowchart LR
    U([🧑 User]) -->|multipart upload| B[(Vercel Blob<br/>private quarantine)]
    U -->|enqueue| J[[Job queue<br/>Supabase]]
    J --> W{{Worker<br/>after · 300 s}}
    B --> W
    W --> X[🔬 Static extractor]
    X --> VT[VirusTotal]
    X --> AB[abuse.ch<br/>MalwareBazaar · URLhaus · ThreatFox]
    X --> RD[RDAP<br/>domain age]
    VT & AB & RD --> AI[🤖 AI assessment<br/>schema-validated]
    AI --> TG[🧪 Tria.ge sandbox<br/>reuse or submit, poll]
    TG -. configs · connections .-> AI
    AI --> R[(Report)]
    W -. delete .-> B
    C([⏰ pg_cron · every minute]) -. retry stalled jobs .-> W
```

1. **Upload**: the browser streams the file straight into a private Vercel Blob store (multipart, live `17 / 48 MB` progress). Up to **250 MB**, PDFs up to 50 MB.
2. **Queue**: a job row is created and the worker starts in `after()`, so the user may close the tab.
3. **Dissect**: the extractor validates magic bytes, then parses the format (see below).
4. **Reputation**: VirusTotal and abuse.ch (hash, servers and URLs) are queried in parallel with RDAP domain ages.
5. **Assess**: only bounded evidence (never the raw file) goes to the LLM, whose JSON answer is validated with Zod.
6. **Clean up**: the quarantined file is deleted. Transient failures retry with backoff (30 s, 1 m, 2 m, 5 m), resumed by a Supabase `pg_cron` heartbeat.

## 🧬 What gets dissected

<details open>
<summary><b>📱 APK</b></summary>

- **Manifest**: permissions, components, intent filters, launcher visibility. Tolerates BadPack and corrupted string pools.
- **Every DEX**: string/type/method/class tables, plus **Dalvik bytecode decoding** for call sites (app code vs. known SDKs) and indirect subclasses.
- **Behaviors**: SMS read/send, OTP interception, accessibility, overlays, notification listeners, device admin, USSD call forwarding, hidden icon, APK installs, dynamic code loading, contacts, call logs, keyboard capture.
- **Exfiltration**: Telegram bot tokens (always redacted), Discord/Slack webhooks, PHP panels, raw-IP endpoints, Firebase.
- **Deobfuscation**: base64, hex, reversed, char/byte arrays, single-byte XOR, StringBuilder chains.
- **Packers**: Jiagu, Bangcle/SecNeo, ijiami, Legu and ~15 more, plus stub-only and empty-DEX detection.
- **Native code**: ELF `.so` symbols, JNI exports, embedded endpoints, anti-debug markers.
- **Signing**: v1/v2/v3 certificates, debug/test keys, and **cryptographic v2/v3 verification** to catch repackaged apps.
</details>

<details>
<summary><b>🪟 EXE / DLL</b></summary>

- PE32/PE32+ headers, sections, entropy, full import and delay-load tables, grouped into injection, keylogging, credential theft, download-and-execute and ransomware patterns.
- Resources: version info, manifest (admin elevation), embedded PE/scripts/archives, **brand impersonation** (claims "BCA" or "Microsoft" but isn't signed by them).
- **.NET metadata**: types, member refs, P/Invoke, user strings, stealer/RAT markers and obfuscators.
- Packers, installers and compilers (UPX, Themida, NSIS, Inno, PyInstaller, Go, …), Authenticode signer, overlay classification.
</details>

<details>
<summary><b>📄 PDF · 🖼️ PNG/JPG</b></summary>

- PDF.js (eval disabled): text, links and JavaScript from the first 30 pages, attachments, and `/OpenAction`, `/Launch`, `/AA`, `/SubmitForm` and `/RichMedia` inside compressed object streams.
- Images: chunk/segment structure and data appended after the image end. Pixels are never rendered.
</details>

## 🛡️ Security model

- 🔐 **Single-password access** with HMAC-signed sessions. Only *wrong* passwords count toward the 8-per-15-minutes lockout.
- 🧱 **No execution, ever.** Parsers are bounded in time, memory and recursion, and fuzzed with thousands of corrupted inputs.
- 🗄️ **Private by default**: private Blob store, RLS-locked Supabase tables, server-only secrets, strict CSP.
- 🙈 **Secret hygiene**: Telegram bot secrets are masked everywhere, even when parsing aborts midway.
- 🚦 **Fair use**: rate limits on analyses, uploads, VirusTotal, abuse.ch, RDAP and large files (to protect the Hobby Blob allowance).

## 🚀 Getting started

```sh
git clone https://github.com/MrPrinceAli/Kheronyx.git
cd Kheronyx
npm ci
cp .env.example .env   # fill in the values below
npm run dev
```

| Variable | Purpose |
|---|---|
| `ACCESS_PASSWORD` / `ACCESS_PASSWORD_HASH` | Login password (use the hash in production: `node scripts/password-hash.mjs`) |
| `SESSION_SECRET` | HMAC key for sessions |
| `AI_API_KEY`, `AI_BASE_URL`, `AI_MODEL`, `AI_FALLBACK_MODEL` | OpenAI-compatible gateway for the assessment; `AI_FALLBACK_MODEL` is a comma-separated backup chain |
| `BLOB_READ_WRITE_TOKEN` | Vercel Blob private store (enables 250 MB uploads and background jobs) |
| `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` | Reports, jobs, rate limits |
| `VIRUSTOTAL_API_KEY` | Hash reputation (optional upload) |
| `ABUSE_CH_AUTH_KEY` | MalwareBazaar, URLhaus, ThreatFox ([free key](https://auth.abuse.ch)) |
| `TRIAGE_API_KEY`, `TRIAGE_API_URL` | Tria.ge sandbox (researcher accounts: samples are public) |
| `CRON_SECRET`, `JOBS_SECRET` | Daily maintenance and the per-minute job scheduler |

Apply the SQL in [`supabase/migrations`](supabase/migrations) to your project. The scheduler migration explains the shared Vault secret it needs.

## 🧪 Testing & evaluation

```sh
npm run typecheck
npm test            # 116 tests: parsers, fuzzing, signing, jobs, threat intel, calibration
npm run build

# Detection accuracy on real samples (never executed, stored read-only in .corpus/)
ABUSE_CH_AUTH_KEY=... npx tsx scripts/eval-corpus.ts fetch --tag SMSspy --limit 30
npx tsx scripts/eval-corpus.ts run .corpus/SMSspy
```

## 📁 Project structure

```
app/                 Next.js routes: landing, dashboard, API (uploads, jobs, reports, auth, cron)
components/          UI, WebGL smoke canvas, report panels
lib/
  extract.ts         Format dispatch, bounding and redaction
  dex.ts             DEX tables + Dalvik bytecode decoder
  behaviors.ts       Scam/banking-trojan behavior catalog
  apk-*.ts, elf.ts   Signing, packers, payloads, native libraries
  pe-*.ts, dotnet.ts PE imports/resources/packers, .NET metadata
  threat-intel.ts    abuse.ch + RDAP
  virustotal.ts      VirusTotal
  jobs.ts            Durable background jobs with retries
  ai.ts              LLM assessment with schema validation
scripts/             Corpus evaluation, env sync, password hashing
supabase/migrations  Tables, job claim function, pg_cron scheduler
tests/               node:test suites incl. fuzzing and real-world trick fixtures
```

## ⚠️ Disclaimer

Kheronyx is a research and awareness tool. Static analysis can miss malware that downloads or decrypts its payload at runtime, and antivirus/threat-intel absence is not proof of safety. Always install apps from official stores only. To report Indonesian scams, use [aduankonten.id](https://aduankonten.id) and your bank's official channels.

## 🙏 Acknowledgements

[Tria.ge](https://tria.ge) (Researcher program) · [VirusTotal](https://www.virustotal.com) · [abuse.ch](https://abuse.ch) (MalwareBazaar, URLhaus, ThreatFox) · [RDAP](https://about.rdap.org) · [PDF.js](https://mozilla.github.io/pdf.js/) · [Vercel](https://vercel.com) · [Supabase](https://supabase.com)

<div align="center">

**Built with 🖤 by [Viclatess](https://github.com/MrPrinceAli)**

<sub>If Kheronyx helped you, consider leaving a ⭐. It helps more people find it.</sub>

</div>
