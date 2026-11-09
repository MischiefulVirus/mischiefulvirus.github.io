-- Gallery admin login rate limit
-- Run once in Supabase Dashboard -> SQL Editor.
create table if not exists public.gallery_admin_login_limits (
  ip_hash text primary key,
  window_started_at timestamptz not null default now(),
  attempts integer not null default 0
);

alter table public.gallery_admin_login_limits enable row level security;
revoke all on table public.gallery_admin_login_limits from anon, authenticated;
grant all on table public.gallery_admin_login_limits to service_role;

create or replace function public.claim_gallery_admin_login_slot(p_ip_hash text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  v_attempts integer;
begin
  insert into public.gallery_admin_login_limits (ip_hash, window_started_at, attempts)
  values (p_ip_hash, now(), 1)
  on conflict (ip_hash) do update
    set window_started_at = case
          when public.gallery_admin_login_limits.window_started_at <= now() - interval '15 minutes'
          then now()
          else public.gallery_admin_login_limits.window_started_at
        end,
        attempts = case
          when public.gallery_admin_login_limits.window_started_at <= now() - interval '15 minutes'
          then 1
          else public.gallery_admin_login_limits.attempts + 1
        end
  returning attempts into v_attempts;

  return v_attempts <= 10;
end;
$$;

revoke all on function public.claim_gallery_admin_login_slot(text) from public, anon, authenticated;
grant execute on function public.claim_gallery_admin_login_slot(text) to service_role;
