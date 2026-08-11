-- Recupero: client self-service signup requests
--
-- The "Create new account" form on the client login page inserts a row
-- here directly using the public anon key -- RLS only lets it create a
-- 'pending' row with no org attached, so the public-facing form can never
-- grant access to anything by itself. An admin reviews requests in
-- Org Settings and clicks Approve, which invokes the
-- approve-signup-request Edge Function: that creates the org, invites the
-- user, and writes their profile as portal='client', access_level='admin'
-- (first user of a new org is that org's own admin) all under the service
-- role, then marks this row approved.

create table if not exists public.signup_requests (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  company_name text not null,
  contact_name text,
  status text not null default 'pending',
  org_id uuid references public.orgs(id),
  created_at timestamptz not null default now(),
  reviewed_at timestamptz
);

alter table public.signup_requests
  drop constraint if exists signup_requests_status_check;
alter table public.signup_requests
  add constraint signup_requests_status_check check (status in ('pending', 'approved', 'rejected'));

create index if not exists idx_signup_requests_status on public.signup_requests(status);

alter table public.signup_requests enable row level security;

drop policy if exists signup_requests_insert_public on public.signup_requests;
drop policy if exists signup_requests_select_admin on public.signup_requests;
drop policy if exists signup_requests_update_admin on public.signup_requests;

-- Anyone, including anonymous visitors, can submit a request -- this is the
-- entire public attack surface on this table: it can only ever create a
-- 'pending' row with no org attached, nothing that grants access.
create policy signup_requests_insert_public on public.signup_requests
  for insert
  with check (status = 'pending' and org_id is null);

-- Only admin-portal staff can see submitted requests.
create policy signup_requests_select_admin on public.signup_requests
  for select using (public.my_portal() = 'admin');

-- Only admin-portal staff can update them directly (e.g. Reject).
-- Approve instead goes through the Edge Function so the org/user creation
-- and this row's status update happen together under the service role.
create policy signup_requests_update_admin on public.signup_requests
  for update using (public.my_portal() = 'admin');
