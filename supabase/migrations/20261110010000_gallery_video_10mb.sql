-- Raise the Storage bucket ceiling to 10 MiB so videos can use the larger limit.
-- The Edge Function continues enforcing 5 MiB for images and 10 MiB for videos.
begin;
update storage.buckets
set file_size_limit = 10485760
where id = 'gallery';
commit;
