-- Supabase schema for VibeNest
-- Run this in the SQL editor on your Supabase project or via psql using the service_role key.

-- 1) profiles table (app-level metadata linked to auth.users)
create table if not exists profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique,
  display_name text,
  bio text,
  profile_pic text,
  is2fa_enabled text default 'none', -- 'none' | 'email' | 'authenticator'
  two_factor_secret text, -- store encrypted/hashed value (consider encrypting at rest)
  is_admin boolean default false,
  magic_link_email text,
  email2fa_email text,
  created_at timestamptz default now()
);

-- Function to handle new user signup
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, username, display_name)
  values (new.id, new.raw_user_meta_data->>'username', new.raw_user_meta_data->>'displayName');
  return new;
end;
$$ language plpgsql security definer;

-- Trigger to call the function on new user
create or replace trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- 2) photos and videos
create table if not exists photos (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references profiles(id) on delete cascade,
  filename text not null,
  caption text,
  created_at timestamptz default now()
);

create table if not exists videos (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references profiles(id) on delete cascade,
  filename text not null,
  caption text,
  created_at timestamptz default now()
);

-- 3) likes and comments
create table if not exists photo_likes (
  id uuid primary key default gen_random_uuid(),
  photo_id uuid not null references photos(id) on delete cascade,
  user_id uuid not null references profiles(id) on delete cascade,
  created_at timestamptz default now(),
  unique(photo_id, user_id)
);

create table if not exists video_likes (
  id uuid primary key default gen_random_uuid(),
  video_id uuid not null references videos(id) on delete cascade,
  user_id uuid not null references profiles(id) on delete cascade,
  created_at timestamptz default now(),
  unique(video_id, user_id)
);

create table if not exists photo_comments (
  id uuid primary key default gen_random_uuid(),
  photo_id uuid not null references photos(id) on delete cascade,
  user_id uuid not null references profiles(id) on delete cascade,
  text text not null,
  created_at timestamptz default now()
);

create table if not exists video_comments (
  id uuid primary key default gen_random_uuid(),
  video_id uuid not null references videos(id) on delete cascade,
  user_id uuid not null references profiles(id) on delete cascade,
  text text not null,
  created_at timestamptz default now()
);

-- 4) backup codes (single-use recovery codes for TOTP)
create table if not exists backup_codes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references profiles(id) on delete cascade,
  code_hash text not null, -- hash (bcrypt/sha256) of code
  used boolean default false,
  created_at timestamptz default now()
);

create index if not exists idx_backup_codes_user_used on backup_codes(user_id, used);

-- Notes / RLS guidelines:
-- - Enable Row Level Security (RLS) on tables and create policies that allow:
--   - read and insert for own profile/own uploads
--   - allow auth service role to bypass RLS on server
-- - Use Supabase Storage for uploads (buckets) and keep file meta in photos/videos tables.
