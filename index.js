/**
 * Carissa Save Router
 *
 * Receives Churnkey session + dunning webhooks. Filters for 30+ employee /
 * $200+ MRR customers. Routes to one of three tiers:
 *
 *   Tier 1 — Contact offer accepted (real-time handoff). URGENT HubSpot task,
 *            4-hour SLA, save-bonus-eligible. Slack alert in #carissa-chat.
 *   Tier 2 — Cancel completed (winback). HIGH HubSpot task, 7-day SLA,
 *            save-bonus-eligible. Slack alert. Also writes cancel_reason
 *            (extracted from Churnkey survey response) to the HubSpot company
 *            so Aspire workflows can branch the cancel sequence on reason.
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

  // 90-day peak employee_count from history. This catches the downgrade-then-
  // cancel scenario (account was at 47 EE, dropped to 1 EE, then cancelled) —
  // without this lookup the router would skip them because current EE is below
  // the threshold. oracle_account_state_history is an append-only daily
  // snapshot populated by trg_snapshot_account_state on every upsert to
  // oracle_account_state.
  let peak90 = null;
  if (state?.bp_account_id) {
    const ninetyDaysAgoISO = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000)
      .toISOString()
      .slice(0, 10);
    const { data: peaks, error: pe } = await supabase
      .from('oracle_account_state_history')
      .select('active_employee_count, snapshot_date')
      .eq('bp_account_id', state.bp_account_id)
      .gte('snapshot_date', ninetyDaysAgoISO)
      .order('active_employee_count', { ascending: false })
      .limit(1);
    if (pe) console.error('[lookup] oracle_account_state_history error:', pe.message);
    peak90 = (peaks && peaks[0]) || null;
  }

  return { customer, state, peak90 };
}

function meetsBigCustomerThreshold({ customer, state, peak90 }) {
  const mrr = customer?.mrr ? parseFloat(customer.mrr) : 0;
  const ee = state?.active_employee_count ?? customer?.employee_count ?? 0;
  const peakEE = peak90?.active_employee_count ?? 0;
  // Current MRR/EE OR historical 90-day peak EE. The historical-peak check
  // is what catches downgrade-then-cancel customers — without it, an account
  // that was 47 EE three months ago but is 1 EE today gets ignored entirely.
  return mrr >= 200 || ee >= 30 || peakEE >= 30;
}

// ============================================================
// Cancel-reason extraction (Churnkey exit-survey → canonical category)
// ============================================================

/**
 * Extracts a canonical cancel reason from a Churnkey session event.
 * Churnkey returns the survey answer in event.surveyResponse — shape varies
 * (sometimes a string, sometimes { reason: ... }, sometimes { answers: [...] }).
 * We stringify the whole thing and keyword-match against the four categories
 * Kirsten cares about for branching the cancellation sequence:
 *   - "No Longer Need"  (most common, ~64%)
 *   - "Better Alternative" (~16%)
 *   - "Price" (~13%)
 *   - "Fit" (~10%)
 *
 * Returns null if event.surveyResponse is missing entirely, "Other" if
 * present but doesn't match any keyword set. Canonical strings match the
 * cancel_reason HubSpot company property values that Aspire workflows
 * branch on.
 */
function extractCancelReason(event) {
  const survey = event?.surveyResponse;
  if (!survey) return null;

  // Stringify everything we can find. Handle: plain string, object, array.
  let blob = '';
  try {
    if (typeof survey === 'string') {
      blob = survey;
    } else {
      blob = JSON.stringify(survey);
    }
  } catch {
    return null;
  }
  if (!blob || blob === '{}' || blob === '[]') return null;

  const text = blob.toLowerCase();

  // Order matters: more-specific patterns first so a phrase like
  // "switched to a cheaper alternative" doesn't fall into "Price" by accident.

  // "Better Alternative" — explicit competitor mention or switching language
  if (
    /\bcompetitor\b/.test(text) ||
    /\bswitch(ed|ing)?\b/.test(text) ||
    /\balternative\b/.test(text) ||
    /\bother (tool|software|product|app|solution)\b/.test(text) ||
    /\bfound (a |another )?better\b/.test(text) ||
    /\bmoving to\b/.test(text) ||
    /(quickbooks time|qb time|tsheets|connecteam|homebase|when i work|deputy|7shifts|bamboo|rippling|gusto|paychex|adp)/.test(text)
  ) {
    return 'Better Alternative';
  }

  // "Price" — affordability/cost language
  if (
    /\b(too )?expensive\b/.test(text) ||
    /\bcost(s|ly|ing)?\b/.test(text) ||
    /\bprice\b/.test(text) ||
    /\bbudget\b/.test(text) ||
    /\baffordab(le|ility)\b/.test(text) ||
    /\bcheaper\b/.test(text) ||
    /\btoo much\b/.test(text)
  ) {
    return 'Price';
  }

  // "Fit" — wrong tool for them, missing feature, doesn't work for their case
  if (
    /\bdoesn['']?t (work|fit|suit|match|meet)\b/.test(text) ||
    /\bmissing (feature|functionality)\b/.test(text) ||
    /\bnot (the )?right (fit|tool|solution|product)\b/.test(text) ||
    /\bwrong (fit|tool|solution)\b/.test(text) ||
    /\bneed (different|something else)\b/.test(text) ||
    /\bfeatures? (we |i )?need\b/.test(text) ||
    /\blimitations?\b/.test(text)
  ) {
    return 'Fit';
  }

  // "No Longer Need" — business closed, project ended, downsized
  if (
    /\bno longer\b/.test(text) ||
    /\bdon['']?t need\b/.test(text) ||
    /\bbusiness (closed|closing|shut|sold)\b/.test(text) ||
    /\bproject (ended|done|complete)\b/.test(text) ||
    /\b(closed|closing|out of business)\b/.test(text) ||
    /\b(seasonal|temporary|short[-\s]?term)\b/.test(text) ||
    /\bdownsized?\b/.test(text) ||
    /\b(reduce|reduced|fewer) (employees|staff|team)\b/.test(text) ||
    /\bnot using\b/.test(text)
  ) {
    return 'No Longer Need';
  }

  // Present but didn't match any category
  return 'Other';
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

async function updateCompanySaveState(companyId, { increment = true, cancelReason = null, cancellationPending = false } = {}) {
  if (!companyId) return null;
  // Read current state so we don't trample downstream save_status values
  let current = null;
  try {
    current = await hsRequest('GET', `/crm/v3/objects/companies/${companyId}?properties=save_status,save_attempt_count,cancel_reason`);
  } catch (e) {
    if (e.status !== 404) console.error('[updateCompanySaveState] read failed:', e.message);
  }
  const curStatus = current?.properties?.save_status || null;
  const curCount = parseInt(current?.properties?.save_attempt_count || '0', 10);
  const curReason = current?.properties?.cancel_reason || null;

  const props = {
    save_attempt_logged: 'true',
    last_save_attempt_at: new Date().toISOString(),
  };
  // Only set save_status to at_risk if not already in a downstream state
  if (!curStatus || curStatus === 'at_risk' || curStatus === 'not_eligible') {
    props.save_status = 'at_risk';
  }
  if (increment) props.save_attempt_count = String(curCount + 1);

  // cancel_reason: write only when provided, and only if not already set
  // (preserves the original survey-derived reason on the first cancel — if
  // a customer winbacks and re-cancels later, that's a new save loop and
  // should be a separate analysis cycle).
  if (cancelReason && !curReason) {
    props.cancel_reason = cancelReason;
  }

  // bp_cancellation_pending: TIER_2 cancels flip this to true so Aspire's
  // suppression rules + "Any-stage to Churned" workflow can fire without
  // waiting for the nightly bp-signal-sync run.
  if (cancellationPending) {
    props.bp_cancellation_pending = 'true';
  }

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
  const peakEE = lookup.peak90?.active_employee_count ?? null;
  // Show "1 (peak 47 in last 90d)" when the historical-peak rule is what
  // qualified them, so it's obvious in the logs WHY this account is in Carissa's queue.
  const eeDisplay = (peakEE != null && typeof ee === 'number' && peakEE > ee) ? `${ee} (peak ${peakEE} in last 90d)` : `${ee}`;
  const plan = lookup.state?.plan_name || lookup.customer?.plan || '?';
  const industry = lookup.state?.industry_name || lookup.customer?.industry || '?';

  // Extract canonical cancel reason from the Churnkey survey response.
  // Only meaningful for TIER_2_CANCELLED (actual cancels) — Tier 1 (saved)
  // and Tier 0 (aborted) don't get the reason written because they didn't
  // complete the survey.
  const cancelReason = tierKey === 'TIER_2_CANCELLED' ? extractCancelReason(event) : null;

  // ---- Log-only mode? ----
  if (!ROUTER_ENABLED) {
    const summary = { handled: false, reason: 'SAVE_ROUTER_ENABLED is not true — log-only mode', tier: tierKey, company: companyName, mrr, ee, peakEE, plan, industry, cancel_reason: cancelReason };
    console.log('[handleChurnkeyEvent log-only]', JSON.stringify(summary));
    return summary;
  }

  // ---- Live mode ----
  const result = { handled: true, tier: tierKey, company: companyName, mrr, ee, peakEE, plan, industry, cancel_reason: cancelReason, actions: {} };

  // 1. Create HubSpot task
  try {
    const dueAtMs = Date.now() + tier.dueDays * 24 * 60 * 60 * 1000;
    const subject = `[Churnkey ${tier.emoji}] ${tier.label} — ${companyName} (${mrr} • ${eeDisplay} EE)`;
    const bodyLines = [
      `${tier.label}`,
      `${companyName} • ${mrr} • ${eeDisplay} EE • ${plan} plan • ${industry}`,
      '',
      `Churnkey session result: ${event.result || '?'}`,
      `Accepted offer: ${event.acceptedOffer?.offerType || 'none'}`,
      `Session timestamp: ${event.timestamp || new Date().toISOString()}`,
    ];
    if (cancelReason) {
      bodyLines.push('', `Cancel reason (extracted from survey): ${cancelReason}`);
    }
    if (event.surveyResponse) {
      bodyLines.push('', 'Survey response (raw):', JSON.stringify(event.surveyResponse, null, 2));
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

  // 2. Update Company save state + cancel_reason (when applicable)
  if (companyId) {
    try {
      await updateCompanySaveState(companyId, {
        cancelReason,
        cancellationPending: tierKey === 'TIER_2_CANCELLED',
      });
      result.actions.company_state_updated = true;
      if (cancelReason) result.actions.cancel_reason_written = cancelReason;
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
    const headerLines = [`*${companyName}* — ${mrr} • ${eeDisplay} EE • ${plan} • ${industry}`, `SLA: ${slaText} • Save-eligible: ${tier.saveEligible ? 'yes' : 'no'}`];
    if (cancelReason) headerLines.push(`Cancel reason: \`${cancelReason}\``);
    const blocks = [
      { type: 'header', text: { type: 'plain_text', text: `${tier.emoji} ${tier.label}` }},
      { type: 'section', text: { type: 'mrkdwn', text: headerLines.join('\n') }},
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
 *     -d '{"event":"session","result":"cancel","customer":{"customerId":"cus_..."},"acceptedOffer":null,"surveyResponse":{"reason":"Too expensive"}}'
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

/**
 * GET /admin/test-reason?text=... — quick check the extractCancelReason
 * keyword matcher against an arbitrary phrase. Returns the canonical category.
 */
app.get('/admin/test-reason', (req, res) => {
  const text = req.query.text || '';
  const reason = extractCancelReason({ surveyResponse: text });
  res.json({ input: text, reason });
});

app.listen(PORT, () => {
  console.log(`carissa-save-router listening on ${PORT}`);
  console.log(`  SAVE_ROUTER_ENABLED = ${ROUTER_ENABLED}`);
  console.log(`  HUBSPOT_OWNER_ID_CARISSA = ${HUBSPOT_OWNER_ID_CARISSA}`);
  console.log(`  CARISSA_CHAT_CHANNEL = ${CARISSA_CHAT_CHANNEL}`);
  console.log(`  Webhook secret: ${CHURNKEY_WEBHOOK_SECRET ? 'configured' : 'NOT SET — rejecting all webhooks'}`);
});
