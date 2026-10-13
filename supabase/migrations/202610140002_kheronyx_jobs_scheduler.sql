-- Requires the shared secret first (both already set up for production):
--   1. Vercel env var JOBS_SECRET (all environments).
--   2. Supabase Vault secret 'kheronyx_jobs_secret' with the same value.
-- Retry scheduler. The secret is stored in Vault as 'kheronyx_jobs_secret' (same value as JOBS_SECRET on
-- Vercel); the endpoint is only called when a job is actually waiting, so idle minutes cost nothing.
create extension if not exists pg_net;
create extension if not exists pg_cron;
select cron.unschedule('kheronyx-jobs') where exists (select 1 from cron.job where jobname = 'kheronyx-jobs');
select cron.schedule('kheronyx-jobs', '* * * * *', $job$
  select net.http_post(
    url := 'https://kheronyx.vercel.app/api/jobs/run',
    headers := jsonb_build_object('Content-Type', 'application/json', 'Authorization',
      'Bearer ' || (select decrypted_secret from vault.decrypted_secrets where name = 'kheronyx_jobs_secret')),
    body := '{}'::jsonb, timeout_milliseconds := 5000)
  where exists (select 1 from public.kheronyx_jobs
    where status in ('queued','running') and (locked_until is null or locked_until < now()))
$job$);
