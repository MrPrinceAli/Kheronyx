-- Namespaced resources: safe to use in an existing project.
create table if not exists public.kheronyx_reports (
  id uuid primary key, created_at timestamptz not null default now(),
  filename text not null, kind text not null check (kind in ('pdf','apk','exe','png','jpg')),
  size bigint not null, sha256 text not null, risk text not null,
  report jsonb not null
);
create index if not exists kheronyx_reports_created_idx on public.kheronyx_reports(created_at desc);
alter table public.kheronyx_reports enable row level security;
revoke all on public.kheronyx_reports from anon, authenticated;
grant all on public.kheronyx_reports to service_role;
create table if not exists public.kheronyx_rate_limits (
  key text primary key, count integer not null, reset_at timestamptz not null
);
alter table public.kheronyx_rate_limits enable row level security;
revoke all on public.kheronyx_rate_limits from anon, authenticated;
grant all on public.kheronyx_rate_limits to service_role;
create or replace function public.kheronyx_rate_limit(p_key text, p_limit integer, p_window_seconds integer)
returns boolean language plpgsql security definer set search_path = public as $$
declare v_count integer;
begin
  insert into public.kheronyx_rate_limits(key, count, reset_at)
  values(p_key, 1, now() + make_interval(secs => p_window_seconds))
  on conflict(key) do update set
    count = case when kheronyx_rate_limits.reset_at <= now() then 1 else kheronyx_rate_limits.count + 1 end,
    reset_at = case when kheronyx_rate_limits.reset_at <= now() then now() + make_interval(secs => p_window_seconds) else kheronyx_rate_limits.reset_at end
  returning count into v_count;
  delete from public.kheronyx_rate_limits where reset_at < now() - interval '1 day';
  return v_count <= p_limit;
end;
$$;
revoke all on function public.kheronyx_rate_limit(text, integer, integer) from public, anon, authenticated;
grant execute on function public.kheronyx_rate_limit(text, integer, integer) to service_role;
insert into storage.buckets(id, name, public, file_size_limit)
values('kheronyx-quarantine', 'kheronyx-quarantine', false, 41943040)
on conflict(id) do update set public = false, file_size_limit = 41943040;
-- No anonymous storage policies. Access is issued by the authenticated server only.
