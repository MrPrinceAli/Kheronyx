# Kheronyx

A private, minimal file intelligence workspace. Landing page + password-only analysis dashboard. Supports PDF, APK, EXE, PNG, JPG/JPEG; DMG is coming soon.

## Run locally

```sh
npm ci
cp .env.example .env
npm run dev
```

Fill `ACCESS_PASSWORD`, a random `SESSION_SECRET`, and `AI_API_KEY` in `.env`. This workspace includes a preconfigured ignored `.env` with the requested password; only the AI key is intentionally empty. Gateway: `https://tokengateway.ai.id/v1`. Set `AI_MODEL` to a model offered by your account, or leave it empty for `/models` discovery. Keys and password validation stay server-side.

## Vercel

Connect this repository and deploy as Next.js. Add the same variables under **Project → Settings → Environment Variables**, then redeploy. `.env` is intentionally excluded from Git and deployment uploads: filling the local file does not update production. Production uses `ACCESS_PASSWORD_HASH` instead of storing the shared password in application source. Generate a hash via stdin:

```sh
read -s KHERONYX_PASSWORD
printf '%s' "$KHERONYX_PASSWORD" | node scripts/password-hash.mjs
unset KHERONYX_PASSWORD
```

The Vercel CLI can read secrets through stdin: `vercel env add AI_API_KEY production,preview --sensitive`. Do not put the key in `NEXT_PUBLIC_*` variables.

After filling the local `.env`, run `npm run deploy` to synchronize server environment variables through stdin and redeploy the linked project. The sync script hashes the access password for production and never prints secret values.

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
- Validates the AI response; incomplete extraction always produces an unknown risk verdict. Provider or schema failures produce errors, never fabricated reports.

**This is AI-assisted static risk analysis, not an antivirus or execution sandbox.** It does not establish that a file is safe or free of malware, verify Authenticode/APK signatures, detect all steganography, fully decompile code, or consult threat reputation services. Treat model confidence as interpretation confidence, not a probability of safety. Shared password holders can access the shared report history.

## Validation

```sh
npm run typecheck
npm test
npm run build
```

Security tests cover session forgery/expiry, signature mismatches, bounded decompression, malformed binaries, and unknown verdict enforcement. Browser verification covers landing/login, protected dashboard, file selection/errors, report rendering, downloads, and mobile layouts. A real gateway verdict still requires a valid account key.
