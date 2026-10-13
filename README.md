# Kheronyx

A private, minimal file intelligence workspace. Landing page + password-only analysis dashboard. Supports PDF, APK, EXE, PNG, JPG/JPEG; DMG is coming soon.

Production: https://kheronyx.vercel.app · Repository: https://github.com/MrPrinceAli/Kheronyx (private). Supabase resources are installed in the user-selected `pelita` project, under Kheronyx-specific names. Credentials stay in the ignored local environment file and server environment variables.

## Run locally

```sh
npm ci
cp .env.example .env
npm run dev
```

Fill `ACCESS_PASSWORD`, a random `SESSION_SECRET`, and `AI_API_KEY` in `.env`. Fill `VIRUSTOTAL_API_KEY` to activate antivirus reputation checks. This workspace includes a preconfigured ignored `.env`; keep its existing values when adding keys. Gateway: `https://tokengateway.ai.id/v1`. Primary: `AI_MODEL=gpt-6-astra`. Backup: `AI_FALLBACK_MODEL=gpt-6.1-sol`. Model IDs must be available to your gateway account. Keys and password validation stay server-side.

The backup is tried once if the primary is unavailable, rate limited, times out, or returns an invalid/incomplete report. Invalid keys, insufficient balance, general bad requests, and explicit model refusals are returned as errors. Both failures produce an error, never a fabricated verdict. Reports record the model that actually returned a valid assessment. Requests to these reasoning GPT models omit temperature and use medium reasoning with an 8,000-token combined reasoning/output cap. Each model has a 65-second request timeout; the combined budget leaves room for VirusTotal in the 240-second analysis route. Leave `AI_FALLBACK_MODEL` explicitly empty to disable the backup.

## Vercel

Connect this repository and deploy as Next.js. Add the same variables under **Project → Settings → Environment Variables**, then redeploy. `.env` is intentionally excluded from Git and deployment uploads: filling the local file does not update production. Production uses `ACCESS_PASSWORD_HASH` instead of storing the shared password in application source. Generate a hash via stdin:

```sh
read -s KHERONYX_PASSWORD
printf '%s' "$KHERONYX_PASSWORD" | node scripts/password-hash.mjs
unset KHERONYX_PASSWORD
```

The Vercel CLI can read secrets through stdin: `vercel env add AI_API_KEY production,preview --sensitive`. Do not put the key in `NEXT_PUBLIC_*` variables.

After filling the local `.env`, run `npm run deploy` to synchronize server environment variables, including `VIRUSTOTAL_API_KEY`, through stdin and redeploy the linked project. The sync script hashes the access password for production and never prints secret values.

## Interface

The landing eye uses a subtle corneal reflection instead of a scan beam. Successful login starts a radial dark transition from the eye, keeps the eye visible while the protected dashboard loads, then fades into the workspace. Incorrect passwords stay on the login form. A navigation timeout restores the form, and reduced-motion preferences skip the cinematic transition. The shared layout owns the overlay so it survives the route change. A small animated signal with **Connected** identifies the configured AI connection in the dashboard.

## VirusTotal

Every analysis performs a [SHA-256 reputation lookup](https://docs.virustotal.com/reference/file-info) when `VIRUSTOTAL_API_KEY` is set. Existing antivirus counts, engine detections, and the original analysis date appear in the report and are supplied to the AI. Missing keys, unknown hashes, quota errors, invalid responses and pending scans are shown explicitly; none is treated as a clean antivirus result.

**Izinkan scan dengan VirusTotal** is checked by default, as configured by the owner. The dashboard explains that a file is submitted only when VirusTotal has no existing record. Users can uncheck it before analysis; that choice persists while the dashboard remains open, including when another file is selected. [Submitted files enter VirusTotal's dataset](https://docs.virustotal.com/reference/files-scan), so the sharing notice appears while submission is enabled. Raw bytes are sent only with this option enabled, under a hash-based filename. Files over 32 MB use the official large-upload URL; URLs are restricted to the VirusTotal HTTPS origin and redirects are blocked. A short wait checks for completion; queued or partial results stay pending. **Perbarui hasil** later fetches the file's reputation without uploading again, updates the report and preserves the initial AI explanation. Local quarantine deletion does not remove copies submitted to VirusTotal.

The shared key is limited by Kheronyx to 4 requests per minute and 500 per day, with counters persisted in Supabase when configured. This matches the [Public API limits](https://docs.virustotal.com/reference/public-vs-premium-api); that API also prohibits commercial products/services. Check the entitlement of the key used for deployment. Provider quotas are displayed without suppressing static analysis. Malicious detections set a conservative minimum risk of high, suspicious detections a minimum of medium; false positives remain possible. Zero detections never lowers an existing concerning static verdict or proves safety. Old reports remain readable without a VirusTotal field. Results are stored inside the existing report JSON; no database migration is needed.

## Supabase

Run `supabase/migrations/202610130001_kheronyx.sql` against the selected project. Configure server-only `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` (a current Supabase secret key also works), and `SUPABASE_BUCKET=kheronyx-quarantine`.

Uploads go directly to a **private quarantine bucket** using server-issued signed upload URLs, avoiding Vercel's request-body limit. The server binds object paths to the authenticated session, checks file signatures and size, and deletes uploads after analysis. A daily Vercel cron deletes abandoned uploads older than 24 hours (typically removed within 48 hours) and reports older than 30 days. Set a random `CRON_SECRET` in Vercel for the cleanup route. Stored reports are accessible only through authenticated server routes; there are no public table/storage policies.

Limits: 40 MB per file with storage, 10 MB for PDF, 4 MB for direct upload without storage. 20 analyses per authenticated session per hour, 12 upload URLs per ten minutes, 8 password attempts per IP per 15 minutes. Rate counters persist in Supabase when configured; local fallback is process memory.

## What the analysis does

- Validates filename type against bytes; calculates SHA-256.
- PDF: reads bounded text/links, metadata, actions, and attachments metadata with PDF.js evaluation disabled. Up to ten pages.
- APK: reads the archive directory, bounded binary Android manifest, permissions/components, and sampled DEX strings. Bounded decompression; nothing is extracted onto the filesystem.
- EXE: PE architecture, sections, entropy, flags, and imported library names; program is never run.
- PNG/JPG: dimensions, structural metadata, and appended-data indicators. Pixels are never rendered.
- Sends extracted evidence to the configured gateway for structured AI assessment; no raw executable upload to the model. Extracted document content can contain sensitive data, so the upload screen discloses AI processing.
- Fetches VirusTotal evidence before AI assessment when configured; optional new-file scanning requires the sharing selection. Completed detections cannot be dismissed by the AI.
- Validates the AI response; incomplete extraction produces an unknown risk verdict unless independent VirusTotal detections justify concern. AI provider or schema failures produce errors, never fabricated reports. VirusTotal failures remain explicit coverage limitations.

**Local inspection is AI-assisted static analysis; antivirus evidence comes from VirusTotal when configured.** Kheronyx does not execute files or establish that a file is safe or free of malware, verify Authenticode/APK signatures, detect all steganography, or fully decompile code. Treat model confidence as interpretation confidence, not a probability of safety. Shared password holders can access the shared report history.

## Validation

```sh
npm run typecheck
npm test
npm run build
```

Security tests cover session forgery/expiry, signature mismatches, bounded decompression, malformed binaries, and unknown verdict enforcement. Browser verification covers landing/login, protected dashboard, file selection/errors, report rendering, downloads, and mobile layouts. A real gateway verdict still requires a valid account key.
