-- Community feed posts. Reads and writes are routed through the upload-image Edge Function.
begin;

create table if not exists public.gallery_feed_posts (
  id uuid primary key default gen_random_uuid(),
  visitor_hash text not null references public.gallery_visitors(visitor_hash) on delete cascade,
  display_name text not null,
  body text not null check (char_length(body) between 1 and 4000),
  embed_url text,
  created_at timestamptz not null default now(),
  constraint gallery_feed_posts_embed_url_length check (embed_url is null or char_length(embed_url) <= 1000)
);

create index if not exists gallery_feed_posts_created_at_idx
  on public.gallery_feed_posts (created_at desc);
create index if not exists gallery_feed_posts_visitor_created_idx
  on public.gallery_feed_posts (visitor_hash, created_at desc);

alter table public.gallery_feed_posts enable row level security;
revoke all on public.gallery_feed_posts from anon, authenticated;
grant all on public.gallery_feed_posts to service_role;

commit;
