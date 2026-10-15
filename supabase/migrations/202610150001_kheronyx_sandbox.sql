-- Tria.ge (Hatching Triage) sandbox: opt-in per job, then polled until the public analysis is reported. The main
-- report is saved first; sandbox checks only enrich it later (merge hosts, reputation, AI re-assessment).
alter table public.kheronyx_jobs add column if not exists upload_triage boolean not null default false;

create table if not exists public.kheronyx_sandbox (
  report_id uuid primary key references public.kheronyx_reports(id) on delete cascade,
  sha256 text not null,
  sample_id text,
  -- Quarantine blob kept only while a rate-limited/failed upload may still be retried (≤ 30 min, else maintenance).
  path text,
  status text not null default 'pending' check (status in ('pending','running','done','failed')),
  attempts integer not null default 0,
  next_check timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists kheronyx_sandbox_due_idx on public.kheronyx_sandbox(status, next_check);
create index if not exists kheronyx_sandbox_sha_idx on public.kheronyx_sandbox(sha256);
alter table public.kheronyx_sandbox enable row level security;
revoke all on public.kheronyx_sandbox from anon, authenticated;
grant all on public.kheronyx_sandbox to service_role;

-- Leases up to p_limit due checks: next_check moves past the lease, so a worker killed mid-check (AI re-assessment
-- included) is picked up again once the lease expires; the worker sets the real next_check when it finishes.
create or replace function public.kheronyx_claim_sandbox(p_limit integer, p_lease_seconds integer)
returns setof public.kheronyx_sandbox language plpgsql security definer set search_path = public as $$
begin
  return query
  update public.kheronyx_sandbox s set attempts = s.attempts + 1, updated_at = now(),
    next_check = now() + make_interval(secs => p_lease_seconds)
  where s.report_id in (
    select report_id from public.kheronyx_sandbox
    where status in ('pending','running') and next_check <= now()
    order by next_check limit greatest(1, least(p_limit, 10)) for update skip locked)
  returning s.*;
end;
$$;
revoke all on function public.kheronyx_claim_sandbox(integer, integer) from public, anon, authenticated;
grant execute on function public.kheronyx_claim_sandbox(integer, integer) to service_role;

-- Same scheduler and Vault secret as 202610140002, now also firing when a sandbox check is due.
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
  or exists (select 1 from public.kheronyx_sandbox
    where status in ('pending','running') and next_check <= now())
$job$);
