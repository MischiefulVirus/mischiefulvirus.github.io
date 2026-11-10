begin;

create table if not exists public.gallery_comments (
  id uuid primary key default gen_random_uuid(),
  image_id uuid not null references public.gallery_images(id) on delete cascade,
  visitor_hash text not null,
  display_name text,
  body text not null check (char_length(body) between 1 and 500),
  created_at timestamptz not null default now()
);

create index if not exists gallery_comments_image_created_idx
  on public.gallery_comments (image_id, created_at);

create index if not exists gallery_comments_visitor_created_idx
  on public.gallery_comments (image_id, visitor_hash, created_at desc);

alter table public.gallery_comments enable row level security;
revoke all on public.gallery_comments from anon, authenticated;
grant all on public.gallery_comments to service_role;

commit;
