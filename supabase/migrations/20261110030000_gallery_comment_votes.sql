begin;

create table if not exists public.gallery_comment_votes (
  comment_id uuid not null references public.gallery_comments(id) on delete cascade,
  visitor_hash text not null,
  vote smallint not null check (vote in (-1, 1)),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (comment_id, visitor_hash)
);

create index if not exists gallery_comment_votes_comment_idx
  on public.gallery_comment_votes (comment_id);

alter table public.gallery_comment_votes enable row level security;
revoke all on public.gallery_comment_votes from anon, authenticated;
grant all on public.gallery_comment_votes to service_role;

commit;
