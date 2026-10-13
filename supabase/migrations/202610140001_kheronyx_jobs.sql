-- Background analysis jobs: the browser only uploads and enqueues; the server analyzes even after the tab
-- is closed, retrying transient failures (AI gateway, VirusTotal, network, function timeouts).
create table if not exists public.kheronyx_jobs (
  id uuid primary key,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  path text not null,
  filename text not null,
  kind text not null check (kind in ('pdf','apk','exe','png','jpg')),
  size bigint not null,
  upload_virustotal boolean not null default false,
  status text not null default 'queued' check (status in ('queued','running','done','failed')),
  stage text,
  attempts integer not null default 0,
  locked_until timestamptz,
  error text,
  report_id uuid
);
create index if not exists kheronyx_jobs_pending_idx on public.kheronyx_jobs(status, locked_until);
alter table public.kheronyx_jobs enable row level security;
revoke all on public.kheronyx_jobs from anon, authenticated;
grant all on public.kheronyx_jobs to service_role;

-- Atomically leases the next runnable job (or a specific one). A job whose worker died is runnable again
-- once its lease expires; jobs that used up their attempts are marked failed instead.
create or replace function public.kheronyx_claim_job(p_id uuid, p_lease_seconds integer, p_max_attempts integer)
returns setof public.kheronyx_jobs language plpgsql security definer set search_path = public as $$
begin
  update public.kheronyx_jobs set status = 'failed', updated_at = now(),
    error = coalesce(error, 'Analisis berhenti sebelum selesai.') || ' Percobaan otomatis sudah habis.'
  where status in ('queued','running') and attempts >= p_max_attempts and (locked_until is null or locked_until < now());
  return query
  update public.kheronyx_jobs j set status = 'running', attempts = j.attempts + 1, updated_at = now(),
    locked_until = now() + make_interval(secs => p_lease_seconds)
  where j.id = (
    select id from public.kheronyx_jobs
    where (p_id is null or id = p_id) and status in ('queued','running')
      and (locked_until is null or locked_until < now()) and attempts < p_max_attempts
    order by created_at limit 1 for update skip locked)
  returning j.*;
end;
$$;
revoke all on function public.kheronyx_claim_job(uuid, integer, integer) from public, anon, authenticated;
grant execute on function public.kheronyx_claim_job(uuid, integer, integer) to service_role;
