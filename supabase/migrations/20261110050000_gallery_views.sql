-- Count every focused gallery view (viewer opens and direct webhook links).
begin;

create table if not exists public.gallery_views (
  id bigint generated always as identity primary key,
  image_id uuid not null references public.gallery_images(id) on delete cascade,
  visitor_hash text not null references public.gallery_visitors(visitor_hash) on delete cascade,
  viewed_at timestamptz not null default now()
);

create index if not exists gallery_views_image_id_idx on public.gallery_views(image_id);
alter table public.gallery_views enable row level security;
revoke all on public.gallery_views from anon, authenticated;
grant all on public.gallery_views to service_role;

create or replace view public.gallery_image_stats
with (security_invoker = false)
as
select
  i.id as image_id,
  coalesce(v.upvotes, 0)::integer as upvotes,
  coalesce(v.downvotes, 0)::integer as downvotes,
  coalesce(v.score, 0)::integer as score,
  coalesce(s.sobs, 0)::integer as sobs,
  coalesce(w.views, 0)::integer as views
from public.gallery_images i
left join (
  select image_id,
    count(*) filter (where vote = 1) as upvotes,
    count(*) filter (where vote = -1) as downvotes,
    sum(vote) as score
  from public.gallery_votes group by image_id
) v on v.image_id = i.id
left join (
  select image_id, count(*) as sobs
  from public.gallery_sobs group by image_id
) s on s.image_id = i.id
left join (
  select image_id, count(*) as views
  from public.gallery_views group by image_id
) w on w.image_id = i.id;

grant select on public.gallery_image_stats to anon, authenticated;
commit;
