-- NOT APPLIED AUTOMATICALLY: needs the owner to create the shared secret first.
--   1. Vercel: add env var JOBS_SECRET (Production) with a long random value, then redeploy.
--   2. Supabase SQL editor: select vault.create_secret('<same value>', 'kheronyx_jobs_secret');
--   3. Run this file.
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
