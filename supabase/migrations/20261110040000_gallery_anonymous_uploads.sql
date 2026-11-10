begin;

alter table public.gallery_images
  add column if not exists is_anonymous boolean not null default false;

create table if not exists public.gallery_upload_private (
  image_id uuid primary key references public.gallery_images(id) on delete cascade,
  uploader_name text not null,
  created_at timestamptz not null default now()
);

alter table public.gallery_upload_private enable row level security;
revoke all on public.gallery_upload_private from anon, authenticated;
grant all on public.gallery_upload_private to service_role;

commit;
