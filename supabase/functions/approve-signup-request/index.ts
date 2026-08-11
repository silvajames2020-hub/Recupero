// Approves a client signup request: creates the org, invites the user, and
// writes their profile as portal='client', access_level='admin' (first
// user of a new org is that org's own admin) -- all in one step, then
// marks the request approved.
//
// Admin-only, verified the same way as create-admin-user: the caller's own
// JWT is checked against their profile before the service role (which
// never leaves this function) does anything. See that function for the
// full rationale.
//
// Deploy: supabase functions deploy approve-signup-request

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

  const callerClient = createClient(supabaseUrl, anonKey, {
    global: { headers: { Authorization: authHeader } },
  });

  const { data: { user: caller }, error: callerErr } = await callerClient.auth.getUser();
  if (callerErr || !caller) {
    return json({ error: 'Not authenticated' }, 401);
  }

  // Service role from here on -- every use of it below is gated on the
  // admin check that just happened above.
  const adminClient = createClient(supabaseUrl, serviceRoleKey);

  const { data: callerProfile, error: profileErr } = await adminClient
    .from('profiles')
    .select('portal, access_level')
    .eq('id', caller.id)
    .maybeSingle();

  if (profileErr || !callerProfile || callerProfile.portal !== 'admin' || callerProfile.access_level !== 'admin') {
    return json({ error: 'Not authorized to approve requests' }, 403);
  }

  let body: { request_id?: string };
  try {
    body = await req.json();
  } catch {
    return json({ error: 'Invalid request body' }, 400);
  }

  if (!body.request_id) {
    return json({ error: 'Missing request_id' }, 400);
  }

  const { data: signupRequest, error: reqErr } = await adminClient
    .from('signup_requests')
    .select('*')
    .eq('id', body.request_id)
    .maybeSingle();

  if (reqErr || !signupRequest) {
    return json({ error: 'Request not found' }, 404);
  }
  if (signupRequest.status !== 'pending') {
    return json({ error: `Request already ${signupRequest.status}` }, 400);
  }

  // Create the org first -- if anything after this fails, clean it up so we
  // don't leave an orphaned org with no user.
  const { data: org, error: orgErr } = await adminClient
    .from('orgs')
    .insert({ name: signupRequest.company_name })
    .select()
    .single();

  if (orgErr || !org) {
    return json({ error: orgErr?.message || 'Could not create org' }, 400);
  }

  const origin = req.headers.get('Origin');
  const { data: created, error: createErr } = await adminClient.auth.admin.inviteUserByEmail(signupRequest.email, {
    redirectTo: origin ? `${origin}/` : undefined,
  });

  if (createErr || !created?.user) {
    await adminClient.from('orgs').delete().eq('id', org.id);
    return json({ error: createErr?.message || 'Could not create user' }, 400);
  }

  const { error: insertErr } = await adminClient.from('profiles').insert({
    id: created.user.id,
    email: signupRequest.email,
    portal: 'client',
    access_level: 'admin',
    org_id: org.id,
  });

  if (insertErr) {
    await adminClient.auth.admin.deleteUser(created.user.id);
    await adminClient.from('orgs').delete().eq('id', org.id);
    return json({ error: insertErr.message }, 400);
  }

  await adminClient
    .from('signup_requests')
    .update({ status: 'approved', org_id: org.id, reviewed_at: new Date().toISOString() })
    .eq('id', signupRequest.id);

  return json({ ok: true, org_id: org.id, user_id: created.user.id });
});
