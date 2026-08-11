// Creates a new admin-portal login (auth user + profiles row) and emails
// them an invite to set their own password.
//
// Only callable by an already-authenticated admin (portal='admin',
// access_level='admin'). The service_role key never leaves this function --
// it is auto-injected by the Supabase platform and is the only thing here
// with permission to create users or write to profiles, since RLS blocks
// everyone else from inserting into that table (see
// supabase/migrations/0001_portal_access_level_rls.sql).
//
// Deploy: supabase functions deploy create-admin-user

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  const authHeader = req.headers.get('Authorization');
  if (!authHeader) {
    return json({ error: 'Missing authorization' }, 401);
  }

  const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
  const anonKey = Deno.env.get('SUPABASE_ANON_KEY')!;
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

  // Scoped to the caller's own JWT -- used only to find out who they are.
  const callerClient = createClient(supabaseUrl, anonKey, {
    global: { headers: { Authorization: authHeader } },
  });

  const { data: { user: caller }, error: callerErr } = await callerClient.auth.getUser();
  if (callerErr || !caller) {
    return json({ error: 'Not authenticated' }, 401);
  }

  // Service role from here on -- bypasses RLS, so every use of it below is
  // gated on the admin check that just happened above.
  const adminClient = createClient(supabaseUrl, serviceRoleKey);

  const { data: callerProfile, error: profileErr } = await adminClient
    .from('profiles')
    .select('portal, access_level')
    .eq('id', caller.id)
    .maybeSingle();

  if (profileErr || !callerProfile || callerProfile.portal !== 'admin' || callerProfile.access_level !== 'admin') {
    return json({ error: 'Not authorized to add users' }, 403);
  }

  let body: { email?: string; access_level?: string };
  try {
    body = await req.json();
  } catch {
    return json({ error: 'Invalid request body' }, 400);
  }

  const email = body.email?.trim();
  const accessLevel = body.access_level;
  if (!email || !['view', 'analyst', 'admin'].includes(accessLevel ?? '')) {
    return json({ error: 'Provide an email and a valid access_level (view, analyst, or admin).' }, 400);
  }

  const origin = req.headers.get('Origin');
  const { data: created, error: createErr } = await adminClient.auth.admin.inviteUserByEmail(email, {
    redirectTo: origin ? `${origin}/` : undefined,
  });

  if (createErr || !created?.user) {
    return json({ error: createErr?.message || 'Could not create user' }, 400);
  }

  const { error: insertErr } = await adminClient.from('profiles').insert({
    id: created.user.id,
    email,
    portal: 'admin',
    access_level: accessLevel,
    org_id: null,
  });

  if (insertErr) {
    // Don't leave a login with no profile row -- roll the auth user back.
    await adminClient.auth.admin.deleteUser(created.user.id);
    return json({ error: insertErr.message }, 400);
  }

  return json({ ok: true, id: created.user.id });
});
