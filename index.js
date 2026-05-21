/**
 * Carissa Save Router
 *
 * Receives Churnkey session + dunning webhooks. Filters for 30+ employee /
 * $200+ MRR customers. Routes to one of three tiers:
 *
 *   Tier 1 — Contact offer accepted (real-time handoff). URGENT HubSpot task,
 *            4-hour SLA, save-bonus-eligible. Slack alert in #carissa-chat.
 *   Tier 2 — Cancel completed (winback). HIGH HubSpot task, 7-day SLA,
 *            save-bonus-eligible. Slack alert.
 *   Tier 0 — Aborted Churnkey flow ("free money on the table"). MEDIUM task,
 *            same-day SLA. Slack alert.
 *
 * For all tiers, updates HubSpot Company properties (set save_attempt_logged,
 * save_status='at_risk' if not already in a downstream state, increment
 * save_attempt_count, set last_save_attempt_at).
 *
 * Designed as a parallel service to Nick's existing
 * https://app.buddypunch.com/churnkeywebhook handler. Configure Churnkey to
 * fan the same webhook to BOTH endpoints — we don't touch Nick's code, and
 * if our service fails it doesn't break theirs.
 *
 * Required env vars:
 *   PORT                          (Railway provides)
 *   HUBSPOT_ACCESS_TOKEN          (Slack Bot private app, same as oracle-sync-engine)
 *   HUBSPOT_OWNER_ID_CARISSA      (defaults to 612907040)
 *   HUBSPOT_PORTAL_ID             (defaults to 23365103)
 *   SUPABASE_URL + SUPABASE_KEY   (Oracle warehouse — for customer enrichment)
 *   SLACK_BOT_TOKEN               (same workspace as carissa-leads-bot)
 *   CARISSA_CHAT_CHANNEL          (defaults to C065Y8AND6J)
 *   CHURNKEY_WEBHOOK_SECRET       (HMAC-SHA256 signing secret from Churnkey admin)
 *   SAVE_ROUTER_ENABLED           ('true' to act on webhooks; anything else = log-only mode)
 */

const express = require('express');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const PORT = process.env.PORT || 3000;
const HUBSPOT_ACCESS_TOKEN = process.env.HUBSPOT_ACCESS_TOKEN;
const HUBSPOT_OWNER_ID_CARISSA = process.env.HUBSPOT_OWNER_ID_CARISSA || '612907040';
const HUBSPOT_PORTAL_ID = process.env.HUBSPOT_PORTAL_ID || '23365103';
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const SLACK_BOT_TOKEN = process.env.SLACK_BOT_TOKEN;
const CARISSA_CHAT_CHANNEL = process.env.CARISSA_CHAT_CHANNEL || 'C065Y8AND6J';
const CHURNKEY_WEBHOOK_SECRET = process.env.CHURNKEY_WEBHOOK_SECRET;
const ROUTER_ENABLED = (process.env.SAVE_ROUTER_ENABLED || 'false').toLowerCase() === 'true';

const TASK_TO_COMPANY_ASSOC_TYPE_ID = 192;

const supabase = SUPABASE_URL && SUPABASE_KEY ? createClient(SUPABASE_URL, SUPABASE_KEY) : null;

const app = express();
// Capture the raw body for HMAC verification — needs to be byte-for-byte what Churnkey signed.
app.use(express.json({
  verify: (req, _res, buf) => { req.rawBody = buf; },
  limit: '1mb',
}));

// ============================================================
// Signature verification
// ============================================================

function verifyChurnkeySignature(rawBody, signatureHeader) {
  if (!CHURNKEY_WEBHOOK_SECRET) {
    // No secret set yet — fail closed in production. Log clearly.
    console.warn('[security] CHURNKEY_WEBHOOK_SECRET not set — rejecting webhook');
    return false;
  }
  if (!signatureHeader) {
    console.warn('[security] ck-signature header missing');
    return false;
  }
  const expected = crypto
    .createHmac('sha256', CHURNKEY_WEBHOOK_SECRET)
    .update(rawBody)
    .digest('hex');
  // Constant-time compare
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(signatureHeader, 'hex'));
  } catch {
    return false;
  }
}

// ============================================================
// Customer lookup + threshold
// ============================================================

async function lookupCustomer(stripeCustomerId) {
  if (!supabase || !stripeCustomerId) return null;
  // Pull a flat slice from oracle_customers + oracle_account_state for the threshold + HubSpot ID
  const { data: customers, error: ce } = await supabase
    .from('oracle_customers')
    .select('id, hubspot_company_id, company_name, primary_email, plan, mrr, employee_count, industry, churn_risk, contact_url')
    .eq('stripe_customer_id', stripeCustomerId)
    .limit(1);
  if (ce) console.error('[lookup] oracle_customers error:', ce.message);
  const customer = (customers && customers[0]) || null;

  const { data: states, error: se } = await supabase
    .from('oracle_account_state')
    .select('bp_account_id, account_name, plan_name, industry_name, active_employee_count, geofences_count, integrations_list')
    .eq('stripe_customer_id', stripeCustomerId)
    .limit(1);
  if (se) console.error('[lookup] oracle_account_state error:', se.message);
  const state = (states && states[0]) || null;

  return { customer, state };
}

function meetsBigCustomerThreshold({ customer, state }) {
  const mrr = customer?.mrr ? parseFloat(customer.mrr) : 0;
  const ee = state?.active_employee_count ?? customer?.employee_count ?? 0;
  return mrr >= 200 || ee >= 30;
}

// ============================================================
// HubSpot helpers
// ============================================================

async function hsRequest(method, path, body = null) {
  if (!HUBSPOT_ACCESS_TOKEN) throw new Error('HUBSPOT_ACCESS_TOKEN not set');
  const opts = {
    method,
    headers: {
      Authorization: `Bearer ${HUBSPOT_ACCESS_TOKEN}`,
      'Content-Type': 'application/json',
    },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(`https://api.hubapi.com${path}`, opts);
  const text = await res.text();
  let parsed = null;
  try { parsed = JSON.parse(text); } catch { /* not JSON */ }
  if (!res.ok) {
    const err = new Error(`HubSpot ${res.status} ${method} ${path}: ${text.substring(0, 400)}`);
    err.status = res.status;
    err.body = parsed || text;
    throw err;
  }
  return parsed ?? text;
}

async function createTaskOnCompany({ companyId, subject, body, priority, dueAtMs, taskType }) {
  const payload = {
    properties: {
      hs_timestamp: String(dueAtMs),
      hs_task_subject: subject,
      hs_task_body: body,
      hs_task_priority: priority,
      hs_task_status: 'NOT_STARTED',
      hs_task_type: taskType || 'CALL',
      hubspot_owner_id: HUBSPOT_OWNER_ID_CARISSA,
    },
  };
  if (companyId) {
    payload.associations = [{
      to: { id: String(companyId) },
      types: [{ associationCategory: 'HUBSPOT_DEFINED', associationTypeId: TASK_TO_COMPANY_ASSOC_TYPE_ID }],
    }];
  }
  return hsRequest('POST', '/crm/v3/objects/tasks', payload);
}

async function updateCompanySaveState(companyId, { increment = true } = {}) {
  if (!companyId) return null;
  // Read current state so we don't trample downstream save_status values
  let current = null;
  try {
    current = await hsRequest('GET', `/crm/v3/objects/companies/${companyId}?properties=save_status,save_attempt_count`);
  } catch (e) {
    if (e.status !== 404) console.error('[updateCompanySaveState] read failed:', e.message);
  }
  const curStatus = current?.properties?.save_status || null;
  const curCount = parseInt(current?.properties?.save_attempt_count || '0', 10);

  const props = {
    save_attempt_logged: 'true',
    last_save_attempt_at: new Date().toISOString(),
  };
  // Only set save_status to at_risk if not already in a downstream state
  if (!curStatus || curStatus === 'at_risk' || curStatus === 'not_eligible') {
    props.save_status = 'at_risk';
  }
  if (increment) props.save_attempt_count = String(curCount + 1);

  return hsRequest('PATCH', `/crm/v3/objects/companies/${companyId}`, { properties: props });
}

// ============================================================
// Slack
// ============================================================

async function slackPost(text, blocks) {
  if (!SLACK_BOT_TOKEN) return null;
  const res = await fetch('https://slack.com/api/chat.postMessage', {
    method: 'POST',
    headers: { Authorization: `Bearer ${SLACK_BOT_TOKEN}`, 'Content-Type': 'application/json; charset=utf-8' },
    body: JSON.stringify({ channel: CARISSA_CHAT_CHANNEL, text, blocks, unfurl_links: false }),
  });
  const data = await res.json();
  if (!data.ok) console.error('[slack]', data);
  return data;
}

function hubSpotCompanyLink(id) {
  if (!id) return null;
  return `https://app.hubspot.com/contacts/${HUBSPOT_PORTAL_ID}/company/${id}`;
}

// ============================================================
// Tier definitions
// ============================================================

const TIERS = {
  TIER_1_CONTACT: {
    label: 'Tier 1 — Contact offer accepted (real-time handoff)',
    emoji: '🚨',
    priority: 'HIGH',
    taskType: 'CALL',
    dueDays: 0,  // 4-hour SLA — same day
    saveEligible: true,
  },
  TIER_2_CANCELLED: {
    label: 'Tier 2 — Cancel completed (winback)',
    emoji: '🔁',
    priority: 'HIGH',
    taskType: 'CALL',
    dueDays: 7,
    saveEligible: true,
  },
  TIER_0_ABORT: {
    label: 'Tier 0 — Aborted Churnkey flow',
    emoji: '👀',
    priority: 'MEDIUM',
    taskType: 'CALL',
    dueDays: 1,
    saveEligible: false,  // didn't actually cancel
  },
};

function classifyEvent(event) {
  // Churnkey session webhook fields (per docs):
  //   event.event === 'session'
  //   event.result in 'cancel' | 'pause' | 'discount' | 'abort'
  //   event.acceptedOffer.offerType in 'DISCOUNT' | 'PAUSE' | 'PLAN_CHANGE' | 'CONTACT' | 'TRIAL_EXTENSION' | 'REDIRECT'
  if (event?.event !== 'session') return null;
  const offerType = event.acceptedOffer?.offerType || null;
  if (offerType === 'CONTACT') return 'TIER_1_CONTACT';
  if (event.result === 'cancel') return 'TIER_2_CANCELLED';
  if (event.result === 'abort') return 'TIER_0_ABORT';
  // Pause / discount / plan_change / trial_extension / redirect accepted — Carissa doesn't get paged.
  return null;
}

// ============================================================
// Main route handler
// ============================================================

async function handleChurnkeyEvent(event) {
  const tierKey = classifyEvent(event);
  if (!tierKey) {
    return { handled: false, reason: 'event does not match a Carissa tier', event_summary: { event: event?.event, result: event?.result, offerType: event?.acceptedOffer?.offerType } };
  }
  const tier = TIERS[tierKey];

  // Look up customer (Stripe customer ID → BP/HubSpot/state)
  const stripeCustomerId = event.customer?.customerId || event.customer?.id || null;
  const lookup = await lookupCustomer(stripeCustomerId);
  if (!lookup || (!lookup.customer && !lookup.state)) {
    return { handled: false, reason: 'no oracle_customers/state row for stripe_customer_id', tier: tierKey, stripe_customer_id: stripeCustomerId };
  }

  // Threshold filter — Churnkey automation handles sub-30-EE customers
  if (!meetsBigCustomerThreshold(lookup)) {
    return { handled: false, reason: 'below 30+ EE / $200 MRR threshold', tier: tierKey, stripe_customer_id: stripeCustomerId };
  }

  const companyName = lookup.state?.account_name || lookup.customer?.company_name || lookup.customer?.primary_email || '(unknown)';
  const companyId = lookup.customer?.hubspot_company_id || null;
  const mrr = lookup.customer?.mrr ? `$${Math.round(parseFloat(lookup.customer.mrr))}/mo` : '?';
  const ee = lookup.state?.active_employee_count ?? lookup.customer?.employee_count ?? '?';
  const plan = lookup.state?.plan_name || lookup.customer?.plan || '?';
  const industry = lookup.state?.industry_name || lookup.customer?.industry || '?';

  // ---- Log-only mode? ----
  if (!ROUTER_ENABLED) {
    const summary = { handled: false, reason: 'SAVE_ROUTER_ENABLED is not true — log-only mode', tier: tierKey, company: companyName, mrr, ee, plan, industry };
    console.log('[handleChurnkeyEvent log-only]', JSON.stringify(summary));
    return summary;
  }

  // ---- Live mode ----
  const result = { handled: true, tier: tierKey, company: companyName, mrr, ee, plan, industry, actions: {} };

  // 1. Create HubSpot task
  try {
    const dueAtMs = Date.now() + tier.dueDays * 24 * 60 * 60 * 1000;
    const subject = `[Churnkey ${tier.emoji}] ${tier.label} — ${companyName} (${mrr} • ${ee} EE)`;
    const bodyLines = [
      `${tier.label}`,
      `${companyName} • ${mrr} • ${ee} EE • ${plan} plan • ${industry}`,
      '',
      `Churnkey session result: ${event.result || '?'}`,
      `Accepted offer: ${event.acceptedOffer?.offerType || 'none'}`,
      `Session timestamp: ${event.timestamp || new Date().toISOString()}`,
    ];
    if (event.surveyResponse) {
      bodyLines.push('', 'Survey response:', JSON.stringify(event.surveyResponse, null, 2));
    }
    if (tier.saveEligible) {
      bodyLines.push('', '✅ Save-bonus-eligible. Confirmation locks in after 90-day clawback.');
    }
    bodyLines.push('', companyId ? `HubSpot company: ${hubSpotCompanyLink(companyId)}` : '(no HubSpot company match — investigate)');
    const task = await createTaskOnCompany({
      companyId,
      subject,
      body: bodyLines.join('\n'),
      priority: tier.priority,
      dueAtMs,
      taskType: tier.taskType,
    });
    result.actions.task_id = task?.id;
  } catch (e) {
    console.error('[task create]', e.message);
    result.actions.task_error = e.message;
  }

  // 2. Update Company save state
  if (companyId) {
    try {
      await updateCompanySaveState(companyId);
      result.actions.company_state_updated = true;
    } catch (e) {
      console.error('[company state]', e.message);
      result.actions.company_state_error = e.message;
    }
  } else {
    result.actions.company_state_skipped = 'no hubspot_company_id';
  }

  // 3. Slack alert
  try {
    const slaText = tier.dueDays === 0 ? '4-hour SLA' : `${tier.dueDays}-day SLA`;
    const blocks = [
      { type: 'header', text: { type: 'plain_text', text: `${tier.emoji} ${tier.label}` }},
      { type: 'section', text: { type: 'mrkdwn', text: `*${companyName}* — ${mrr} • ${ee} EE • ${plan} • ${industry}\nSLA: ${slaText} • Save-eligible: ${tier.saveEligible ? 'yes' : 'no'}` }},
      { type: 'section', text: { type: 'mrkdwn', text: `Churnkey result: \`${event.result || '?'}\` • Offer: \`${event.acceptedOffer?.offerType || 'none'}\`` }},
    ];
    if (companyId) {
      blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `<${hubSpotCompanyLink(companyId)}|Open in HubSpot>` }});
    }
    await slackPost(`${tier.emoji} ${tier.label} — ${companyName}`, blocks);
    result.actions.slack_posted = true;
  } catch (e) {
    console.error('[slack]', e.message);
    result.actions.slack_error = e.message;
  }

  return result;
}

// ============================================================
// Endpoints
// ============================================================

app.get('/', (_req, res) => res.send('OK — carissa-save-router'));
app.get('/healthz', (_req, res) => res.json({ ok: true, ts: Date.now(), enabled: ROUTER_ENABLED }));

app.post('/webhooks/churnkey', async (req, res) => {
  const signature = req.headers['ck-signature'] || req.headers['x-churnkey-signature'] || '';
  const rawBody = req.rawBody;

  if (!verifyChurnkeySignature(rawBody, signature)) {
    return res.status(401).json({ ok: false, error: 'invalid signature' });
  }

  // Acknowledge fast (Churnkey expects 200 within a few seconds)
  res.json({ ok: true, received: true });

  // Process async
  try {
    const result = await handleChurnkeyEvent(req.body);
    console.log('[webhook]', JSON.stringify(result));
  } catch (e) {
    console.error('[webhook] async handler error:', e);
  }
});

/**
 * POST /admin/simulate — local testing without a real Churnkey webhook.
 * Pass a body matching the Churnkey session payload shape. Bypasses signature
 * check. Always runs in log-only mode unless SAVE_ROUTER_ENABLED=true.
 *
 * Example:
 *   curl -X POST .../admin/simulate -H 'Content-Type: application/json' \
 *     -d '{"event":"session","result":"cancel","customer":{"customerId":"cus_..."},"acceptedOffer":null}'
 */
app.post('/admin/simulate', async (req, res) => {
  try {
    const result = await handleChurnkeyEvent(req.body);
    res.json({ ok: true, result });
  } catch (e) {
    console.error('[simulate]', e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.listen(PORT, () => {
  console.log(`carissa-save-router listening on ${PORT}`);
  console.log(`  SAVE_ROUTER_ENABLED = ${ROUTER_ENABLED}`);
  console.log(`  HUBSPOT_OWNER_ID_CARISSA = ${HUBSPOT_OWNER_ID_CARISSA}`);
  console.log(`  CARISSA_CHAT_CHANNEL = ${CARISSA_CHAT_CHANNEL}`);
  console.log(`  Webhook secret: ${CHURNKEY_WEBHOOK_SECRET ? 'configured' : 'NOT SET — rejecting all webhooks'}`);
});
