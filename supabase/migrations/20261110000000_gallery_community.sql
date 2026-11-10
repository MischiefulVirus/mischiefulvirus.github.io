-- Gallery community schema migration
-- Safe to run once in Supabase SQL Editor.
-- Raw IP addresses are intentionally not stored or exposed.
begin;

create table if not exists public.gallery_visitors (
  visitor_hash text primary key,
  display_name text not null unique,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now()
);

alter table public.gallery_images
  add column if not exists uploader_hash text
    references public.gallery_visitors(visitor_hash) on delete set null,
  add column if not exists uploader_name text;

create table if not exists public.gallery_votes (
  image_id uuid not null references public.gallery_images(id) on delete cascade,
  visitor_hash text not null references public.gallery_visitors(visitor_hash) on delete cascade,
  vote smallint not null check (vote in (-1, 1)),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (image_id, visitor_hash)
);

create table if not exists public.gallery_sobs (
  image_id uuid not null references public.gallery_images(id) on delete cascade,
  visitor_hash text not null references public.gallery_visitors(visitor_hash) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (image_id, visitor_hash)
);

alter table public.gallery_visitors enable row level security;
alter table public.gallery_votes enable row level security;
alter table public.gallery_sobs enable row level security;

drop policy if exists "public read gallery votes" on public.gallery_votes;
create policy "public read gallery votes"
  on public.gallery_votes for select to anon, authenticated using (true);

drop policy if exists "public read gallery sobs" on public.gallery_sobs;
create policy "public read gallery sobs"
  on public.gallery_sobs for select to anon, authenticated using (true);

revoke all on public.gallery_visitors from anon, authenticated;
revoke insert, update, delete on public.gallery_votes from anon, authenticated;
revoke insert, update, delete on public.gallery_sobs from anon, authenticated;
grant select on public.gallery_votes, public.gallery_sobs to anon, authenticated;
grant all on public.gallery_visitors, public.gallery_votes, public.gallery_sobs to service_role;

create or replace view public.gallery_image_stats
with (security_invoker = true)
as
select
  i.id as image_id,
  coalesce(v.upvotes, 0)::integer as upvotes,
  coalesce(v.downvotes, 0)::integer as downvotes,
  coalesce(v.score, 0)::integer as score,
  coalesce(s.sobs, 0)::integer as sobs
from public.gallery_images i
left join (
  select
    image_id,
    count(*) filter (where vote = 1) as upvotes,
    count(*) filter (where vote = -1) as downvotes,
    sum(vote) as score
  from public.gallery_votes
  group by image_id
) v on v.image_id = i.id
left join (
  select image_id, count(*) as sobs
  from public.gallery_sobs
  group by image_id
) s on s.image_id = i.id;

grant select on public.gallery_image_stats to anon, authenticated;

-- Keep the existing 5 MiB per-file cap. This only expands accepted formats.
update storage.buckets
set allowed_mime_types = array[
  'image/jpeg', 'image/png', 'image/webp', 'image/gif',
  'video/mp4', 'video/webm', 'video/ogg', 'video/quicktime'
]
where id = 'gallery';

commit;
