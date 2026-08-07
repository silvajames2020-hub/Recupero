-- Recupero: profile model fix + Row Level Security
--
-- Replaces the single `profiles.role` column (which only recognized the exact
-- values 'client' and 'admin') with three columns: `portal` (client|admin),
-- `access_level` (view|analyst|admin), and `org_id` (which client org a client
-- user belongs to). This is what the app's login checks now query, and it's
-- also what every RLS policy below is keyed on.
--
-- Run this once in the Supabase SQL editor (or via the CLI) against the
-- project referenced in config.js, before deploying the updated
-- recupero-demo.html. It is written to be safe to re-run.

create extension if not exists "pgcrypto";

create table if not exists public.orgs (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz not null default now()
);

alter table public.profiles
  add column if not exists portal text,
  add column if not exists access_level text,
  add column if not exists org_id uuid references public.orgs(id);

-- Backfill from the old single-role column, if it's still there.
-- Existing rows (james@/connor@recuperohq.com) had role='admin' with no
-- concept of access tiers, so they map to the highest access level on
-- their side.
do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'profiles' and column_name = 'role'
  ) then
    update public.profiles
      set portal = role,
          access_level = 'admin'
      where portal is null and role in ('client', 'admin');
  end if;
end $$;

alter table public.profiles
  drop constraint if exists profiles_portal_check,
  drop constraint if exists profiles_access_level_check,
  drop constraint if exists profiles_client_org_check;

alter table public.profiles
  add constraint profiles_portal_check check (portal in ('client', 'admin')),
  add constraint profiles_access_level_check check (access_level in ('view', 'analyst', 'admin')),
  add constraint profiles_client_org_check check (portal <> 'client' or org_id is not null);

alter table public.profiles alter column portal set not null;
alter table public.profiles alter column access_level set not null;

alter table public.profiles drop column if exists role;

create index if not exists idx_profiles_org_id on public.profiles(org_id);
create index if not exists idx_profiles_portal on public.profiles(portal);

-- Helper functions ---------------------------------------------------------
-- security definer + fixed search_path so they read the caller's own
-- profiles row while bypassing RLS on that one lookup (avoiding recursive
-- policy evaluation), without ever letting the caller control what gets
-- queried.

create or replace function public.my_portal()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select portal from public.profiles where id = auth.uid()::text;
$$;

create or replace function public.my_access_level()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select access_level from public.profiles where id = auth.uid()::text;
$$;

create or replace function public.my_org_id()
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select org_id from public.profiles where id = auth.uid()::text;
$$;

-- Row Level Security ---------------------------------------------------------

alter table public.orgs enable row level security;
alter table public.profiles enable row level security;

drop policy if exists profiles_select_self on public.profiles;
drop policy if exists profiles_select_admin_portal on public.profiles;
drop policy if exists profiles_select_org_admin on public.profiles;
drop policy if exists profiles_update_admin_portal on public.profiles;
drop policy if exists orgs_select_self on public.orgs;
drop policy if exists orgs_select_admin_portal on public.orgs;

-- A signed-in user can always read their own profile row. This is required
-- for the login flow itself (validateClientLogin/validateAdminLogin read the
-- caller's own row right after sign-in) and is the non-recursive base case
-- the helper functions above rely on.
create policy profiles_select_self on public.profiles
  for select using (id = auth.uid()::text);

-- Admin-portal staff can read every profile (Org Settings > Team & roles).
create policy profiles_select_admin_portal on public.profiles
  for select using (public.my_portal() = 'admin');

-- Client-side org admins can read other users in their own org
-- (Account > Users, admin access_level only).
create policy profiles_select_org_admin on public.profiles
  for select using (
    public.my_portal() = 'client'
    and public.my_access_level() = 'admin'
    and org_id = public.my_org_id()
  );

-- No self-service writes: portal/access_level/org_id are provisioned by
-- admins (or the service role used by create-supabase-users.ps1), never by
-- the signed-in user themselves -- otherwise anyone could grant themselves
-- portal='admin'. Only admin-portal staff with access_level='admin' may
-- update profiles from the client; the service role bypasses RLS entirely
-- for provisioning new users.
create policy profiles_update_admin_portal on public.profiles
  for update using (
    public.my_portal() = 'admin' and public.my_access_level() = 'admin'
  );

-- Client users can read their own org; admin portal can read all orgs.
create policy orgs_select_self on public.orgs
  for select using (id = public.my_org_id());

create policy orgs_select_admin_portal on public.orgs
  for select using (public.my_portal() = 'admin');
