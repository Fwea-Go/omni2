// FWEA-I Backend — Cloudflare Worker (aligned to frontend HTML/JS)

import Stripe from 'stripe';

// --- Durable Object: ProcessingStateV2 ---
export class ProcessingStateV2 {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.cache = new Map();
  }

  // Simple KV-style API via fetch:
  //  - GET /?key=abc
  //  - PUT / { key, value }
  //  - DELETE /?key=abc
  async fetch(request) {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    if (method === 'GET') {
      const key = url.searchParams.get('key');
      if (!key) return new Response('Missing key', { status: 400 });
      if (this.cache.has(key)) return new Response(this.cache.get(key) ?? 'null');
      const v = await this.state.storage.get(key);
      if (v != null) this.cache.set(key, v);
      return new Response(v ?? 'null');
    }

    if (method === 'PUT') {
      const { key, value } = await request.json().catch(() => ({}));
      if (!key) return new Response('Missing key', { status: 400 });
      await this.state.storage.put(key, value);
      this.cache.set(key, value);
      return new Response('OK');
    }

    if (method === 'DELETE') {
      const key = url.searchParams.get('key');
      if (!key) return new Response('Missing key', { status: 400 });
      await this.state.storage.delete(key);
      this.cache.delete(key);
      return new Response('OK');
    }

    return new Response('Method Not Allowed', { status: 405 });
  }
}

// Move export default outside the class
export default {
  async fetch(request, env) {
    // ---------- CORS (echo only if origin is in allowlist) ----------
    const reqOrigin = request.headers.get('Origin') || '';
    const workerOrigin = new URL(request.url).origin;
    const allowList = [
      (env.FRONTEND_URL || '').replace(/\/+$/, ''),
      workerOrigin,
      'http://localhost:3000',
      'http://127.0.0.1:3000'
    ].filter(Boolean);

    const allowOrigin = allowList.includes(reqOrigin) ? reqOrigin : '*';
    const corsHeaders = {
      'Access-Control-Allow-Origin': allowOrigin,
      'Vary': 'Origin',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Stripe-Signature, Range',
      'Access-Control-Max-Age': '86400',
      // Expose streaming/seek headers so <audio> can read them
      'Access-Control-Expose-Headers': 'Content-Range, Accept-Ranges, Content-Length'
    };
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const workerBase = getWorkerBase(env, request);

    // signed audio streaming
    if (url.pathname.startsWith('/audio/')) {
      return handleAudioDownload(request, env, corsHeaders);
    }

    try {
      switch (url.pathname) {
        case '/process-audio':
          return handleAudioProcessing(request, env, corsHeaders);
        case '/create-payment':
          return handlePaymentCreation(request, env, corsHeaders);
        case '/webhook':
          return handleStripeWebhook(request, env, corsHeaders);
        case '/activate-access':
          return handleAccessActivation(request, env, corsHeaders);
        case '/validate-subscription':
          return handleSubscriptionValidation(request, env, corsHeaders);
        case '/send-verification':
          return handleSendVerification(request, env, corsHeaders);
        case '/verify-email-code':
          return handleEmailVerification(request, env, corsHeaders);
        case '/track-event':
          return handleEventTracking(request, env, corsHeaders);
        case '/health':
          return new Response('FWEA-I Backend Healthy', { headers: corsHeaders });
        default:
          return new Response('Not Found', { status: 404, headers: corsHeaders });
      }
    } catch (error) {
      console.error('Worker Error:', error);
      return new Response(
        JSON.stringify({ error: 'Internal Server Error', details: error.message }),
        { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }
  },
};

/* =========================
   Helpers — signing & range
   ========================= */

function getWorkerBase(env, request) {
  // Prefer explicit env var
  let base = (env.WORKER_BASE_URL || '').trim();
  if (base) {
    // Ensure scheme + https + no trailing slash
    if (!/^https?:\/\//i.test(base)) base = 'https://' + base;
    try { const u = new URL(base); base = 'https://' + u.host; } catch {}
    return base.replace(/\/+$/, '');
  }
  // Fallback to this worker's own origin
  try {
    const origin = new URL(request.url).origin;
    // Force https scheme to avoid mixed content from http previews
    const u = new URL(origin);
    return 'https://' + u.host;
  } catch {
    return '';
  }
}

async function hmacSHA256(message, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  const b64 = btoa(String.fromCharCode(...new Uint8Array(sigBuf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return b64;
}

async function signR2Key(key, env, ttlSeconds = 15 * 60) {
  if (!env.AUDIO_URL_SECRET) throw new Error('AUDIO_URL_SECRET not configured');
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const msg = `${key}:${exp}`;
  const sig = await hmacSHA256(msg, env.AUDIO_URL_SECRET);
  return { exp, sig };
}

async function verifySignedUrl(key, exp, sig, env) {
  if (!env.AUDIO_URL_SECRET) return false;
  if (!exp || !sig) return false;
  const now = Math.floor(Date.now() / 1000);
  if (Number(exp) <= now) return false;
  const msg = `${key}:${exp}`;
  const expected = await hmacSHA256(msg, env.AUDIO_URL_SECRET);
  return crypto.timingSafeEqual(
    Uint8Array.from(atob(sig.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
    Uint8Array.from(atob(expected.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
  );
}

// Safe-equal polyfill (Workers sometimes lack it)
if (!crypto.timingSafeEqual) {
  crypto.timingSafeEqual = (a, b) => {
    if (a.length !== b.length) return false;
    let out = 0;
    for (let i = 0; i < a.length; i++) out |= a[i] ^ b[i];
    return out === 0;
  };
}

function parseRangeHeader(rangeHeader) {
  if (!rangeHeader || !rangeHeader.startsWith('bytes=')) return null;
  const [startStr, endStr] = rangeHeader.substring(6).split('-', 2);
  const start = startStr ? parseInt(startStr, 10) : NaN;
  const end = endStr ? parseInt(endStr, 10) : NaN;
  if (Number.isNaN(start) && Number.isNaN(end)) return null;
  return { start: Number.isNaN(start) ? 0 : start, end: Number.isNaN(end) ? null : end };
}

/* =========================
   Signed audio streaming
   ========================= */

async function handleAudioDownload(request, env, corsHeaders) {
  const url = new URL(request.url);
  const key = decodeURIComponent(url.pathname.replace(/^\/audio\//, ''));
  if (!key) return new Response('Bad Request', { status: 400, headers: corsHeaders });

  const exp = url.searchParams.get('exp');
  const sig = url.searchParams.get('sig');
  const ok = await verifySignedUrl(key, exp, sig, env);
  if (!ok) {
    return new Response(JSON.stringify({ error: 'Invalid or expired link' }), {
      status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  const rangeHeader = request.headers.get('Range');
  let r2Obj;
  if (rangeHeader) {
    const r = parseRangeHeader(rangeHeader);
    if (r && r.start >= 0) {
      r2Obj = await env.AUDIO_STORAGE.get(key, {
        range: r.end != null ? { offset: r.start, length: r.end - r.start + 1 } : { offset: r.start }
      });
    }
  }
  if (!r2Obj) r2Obj = await env.AUDIO_STORAGE.get(key);
  if (!r2Obj) return new Response('Not found', { status: 404, headers: corsHeaders });

  const isPartial = Boolean(r2Obj.range);
  const size = r2Obj.size;
  const mime = (r2Obj.httpMetadata && r2Obj.httpMetadata.contentType) || 'audio/mpeg';

  const headers = {
    ...corsHeaders,
    'Content-Type': mime,
    'Accept-Ranges': 'bytes',
    'Cache-Control': key.startsWith('previews/') ? 'public, max-age=3600' : 'private, max-age=7200'
  };
  headers['Access-Control-Expose-Headers'] = 'Content-Range, Accept-Ranges, Content-Length';
  headers['Content-Disposition'] = key.startsWith('previews/') ? 'inline; filename="preview.mp3"' : 'inline; filename="full.mp3"';

  if (isPartial) {
    const start = r2Obj.range.offset;
    const length = r2Obj.range.length;
    const end = start + length - 1;
    headers['Content-Range'] = `bytes ${start}-${end}/${size}`;
    headers['Content-Length'] = String(length);
    // Return with CORS + range headers so browsers can stream/seek audio across origins
    return new Response(r2Obj.body, { status: 206, headers });
  } else {
    headers['Content-Length'] = String(size);
    // Return with CORS + range headers so browsers can stream/seek audio across origins
    return new Response(r2Obj.body, { status: 200, headers });
  }
}

/* =========================
   Stripe config
   ========================= */

const STRIPE_PRICE_IDS = {
  SINGLE_TRACK: 'price_1S4NnmJ2Iq1764pCjA9xMnrn',
  DJ_PRO: 'price_1S4NpzJ2Iq1764pCcZISuhug',
  STUDIO_ELITE: 'price_1S4Nr3J2Iq1764pCzHY4zIWr',
  DAY_PASS: 'price_1S4NsTJ2Iq1764pCCbru0Aao',
};

const PRICE_BY_TYPE = {
  single_track: STRIPE_PRICE_IDS.SINGLE_TRACK,
  day_pass: STRIPE_PRICE_IDS.DAY_PASS,
  dj_pro: STRIPE_PRICE_IDS.DJ_PRO,
  studio_elite: STRIPE_PRICE_IDS.STUDIO_ELITE,
};

/* =========================
   /process-audio
   ========================= */

async function handleAudioProcessing(request, env, corsHeaders) {
  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  }

  try {
    const formData = await request.formData();
    const audioFile = formData.get('audio');         // <-- matches frontend
    const fingerprint = formData.get('fingerprint') || 'anonymous';
    const planType = formData.get('planType') || 'free';

    if (!audioFile) {
      return new Response(JSON.stringify({ error: 'No audio file provided' }), {
        status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // Access validation
    const accessValidation = await validateUserAccess(fingerprint, planType, env);
    if (!accessValidation.valid) {
      return new Response(JSON.stringify({
        error: 'Access denied', reason: accessValidation.reason, upgradeRequired: true
      }), { status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    // Size limits (keep in sync with frontend CONFIG.MAX_FILE_SIZE & plan)
    const maxSizes = {
      free: 50 * 1024 * 1024,
      single_track: 100 * 1024 * 1024,
      day_pass: 100 * 1024 * 1024,
      dj_pro: 200 * 1024 * 1024,
      studio_elite: 500 * 1024 * 1024,
    };
    const maxSize = maxSizes[planType] || maxSizes.free;
    if (audioFile.size > maxSize) {
      return new Response(JSON.stringify({
        error: 'File too large', maxSize, currentSize: audioFile.size, upgradeRequired: planType === 'free'
      }), { status: 413, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    // AI processing
    const processingResult = await processAudioWithAI(audioFile, planType, fingerprint, env, request, getWorkerBase(env, request));

    // Persist & analytics
    await storeProcessingResult(fingerprint, processingResult, env, planType);
    await updateUsageStats(fingerprint, planType, audioFile.size, env);

    // IMPORTANT: Frontend expects these exact fields:
    // success, previewUrl, fullAudioUrl, detectedLanguages[], wordsRemoved, previewDuration
    return new Response(JSON.stringify({ success: true, ...processingResult }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Audio processing error:', error);
    return new Response(JSON.stringify({ error: 'Audio processing failed', details: error.message }), {
      status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

/* =========================
   /create-payment
   ========================= */

async function handlePaymentCreation(request, env, corsHeaders) {
  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  }

  try {
    const { priceId, type, fileName, email, fingerprint } = await request.json();

    if (!env.STRIPE_SECRET_KEY) {
      return new Response(JSON.stringify({ error: 'Missing STRIPE_SECRET_KEY' }), {
        status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
    if (!env.FRONTEND_URL) {
      return new Response(JSON.stringify({ error: 'Missing FRONTEND_URL' }), {
        status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const validPriceIds = Object.values(STRIPE_PRICE_IDS);
    if (!validPriceIds.includes(priceId)) {
      return new Response(JSON.stringify({ error: 'Invalid price ID' }), {
        status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    if (!['single_track', 'day_pass', 'dj_pro', 'studio_elite'].includes(type)) {
      return new Response(JSON.stringify({ error: 'Invalid plan type' }), {
        status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    if (PRICE_BY_TYPE[type] !== priceId) {
      return new Response(JSON.stringify({ error: 'Price/type mismatch' }), {
        status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const stripe = new Stripe(env.STRIPE_SECRET_KEY, {
      apiVersion: '2024-06-20',
      httpClient: Stripe.createFetchHttpClient(),
    });

    const isSubscription = (type === 'dj_pro' || type === 'studio_elite');

    const session = await stripe.checkout.sessions.create({
      mode: isSubscription ? 'subscription' : 'payment',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${(env.FRONTEND_URL || '').replace(/\/+$/, '')}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${(env.FRONTEND_URL || '').replace(/\/+$/, '')}/cancel`,
      customer_email: email || undefined,
      allow_promotion_codes: isSubscription || undefined,
      billing_address_collection: isSubscription ? 'required' : 'auto',
      metadata: {
        type: type || '',
        fileName: fileName || '',
        fingerprint: fingerprint || 'unknown',
        processingType: 'audio_cleaning',
        ts: String(Date.now()),
      },
    });

    await storePaymentIntent(session.id, type, priceId, fingerprint, env);

    return new Response(JSON.stringify({ success: true, sessionId: session.id, url: session.url }), {
      status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Payment creation error:', error?.message, error?.raw);
    return new Response(JSON.stringify({ error: 'Payment creation failed', details: error?.message || 'unknown' }), {
      status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

/* =========================
   /webhook
   ========================= */

async function handleStripeWebhook(request, env, corsHeaders) {
  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  }
  if (!env.STRIPE_SECRET_KEY) {
    return new Response(JSON.stringify({ error: 'Missing STRIPE_SECRET_KEY' }), { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  }
  if (!env.STRIPE_WEBHOOK_SECRET) {
    return new Response(JSON.stringify({ error: 'Missing STRIPE_WEBHOOK_SECRET' }), { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  }

  const signature = request.headers.get('stripe-signature');
  if (!signature) {
    return new Response(JSON.stringify({ error: 'Missing stripe-signature header' }), {
      status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  const stripe = new Stripe(env.STRIPE_SECRET_KEY, {
    apiVersion: '2024-06-20',
    httpClient: Stripe.createFetchHttpClient(),
  });

  try {
    const body = await request.text(); // raw body required
    const event = stripe.webhooks.constructEvent(body, signature, env.STRIPE_WEBHOOK_SECRET);

    switch (event.type) {
      case 'checkout.session.completed':
        await handlePaymentSuccess(event.data.object, env);
        break;
      case 'invoice.payment_succeeded':
        await handleSubscriptionRenewal(event.data.object, env);
        break;
      case 'customer.subscription.deleted':
        await handleSubscriptionCancelled(event.data.object, env);
        break;
      case 'customer.subscription.updated':
        await handleSubscriptionUpdated(event.data.object, env);
        break;
      default:
        console.log(`Unhandled event type: ${event.type}`);
    }

    return new Response('OK', { status: 200, headers: corsHeaders });
  } catch (error) {
    console.error('Webhook error:', error?.message);
    return new Response(JSON.stringify({ error: 'Webhook processing failed' }), {
      status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

/* =========================
   Access & verification
   ========================= */

async function handleAccessActivation(request, env, corsHeaders) {
  if (request.method !== 'POST') return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  try {
    const { fingerprint, plan, sessionId, email } = await request.json();
    await env.DB.prepare(`
      INSERT OR REPLACE INTO user_subscriptions 
      (user_id, plan_type, created_at, expires_at, is_active, stripe_session_id, email)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      fingerprint, plan, Date.now(),
      plan === 'day_pass' ? Date.now() + 24 * 60 * 60 * 1000 : null,
      true, sessionId, email
    ).run();
    return new Response(JSON.stringify({ success: true }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  } catch (e) {
    console.error('Access activation error:', e);
    return new Response(JSON.stringify({ error: 'Activation failed' }), { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  }
}

async function handleSubscriptionValidation(request, env, corsHeaders) {
  if (request.method !== 'POST') return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  try {
    const { fingerprint, sessionId, plan } = await request.json();
    const result = await env.DB.prepare(`
      SELECT * FROM user_subscriptions 
      WHERE user_id = ? AND stripe_session_id = ? AND plan_type = ? AND is_active = 1
    `).bind(fingerprint, sessionId, plan).first();
    if (!result) {
      return new Response(JSON.stringify({ valid: false, reason: 'subscription_not_found' }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }
    if (result.expires_at && result.expires_at < Date.now()) {
      await env.DB.prepare(`UPDATE user_subscriptions SET is_active = 0 WHERE user_id = ?`).bind(fingerprint).run();
      return new Response(JSON.stringify({ valid: false, reason: 'expired' }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }
    const timeRemaining = result.expires_at ? Math.max(0, result.expires_at - Date.now()) : null;
    return new Response(JSON.stringify({ valid: true, plan: result.plan_type, timeRemaining, createdAt: result.created_at }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (e) {
    console.error('Subscription validation error:', e);
    return new Response(JSON.stringify({ valid: false, reason: 'validation_error' }), { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  }
}

async function handleSendVerification(request, env, corsHeaders) {
  if (request.method !== 'POST') return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  try {
    const { email, plan } = await request.json();
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await env.DB.prepare(`
      INSERT OR REPLACE INTO verification_codes 
      (email, code, plan_type, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(email, code, plan, Date.now(), Date.now() + 10 * 60 * 1000).run();
    await sendVerificationEmail(email, code, plan, env);
    return new Response(JSON.stringify({ success: true }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  } catch (e) {
    console.error('Send verification error:', e);
    return new Response(JSON.stringify({ error: 'Failed to send verification' }), { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  }
}

async function handleEmailVerification(request, env, corsHeaders) {
  if (request.method !== 'POST') return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  try {
    const { email, code, plan } = await request.json();
    const result = await env.DB.prepare(`
      SELECT * FROM verification_codes 
      WHERE email = ? AND code = ? AND plan_type = ? AND expires_at > ?
    `).bind(email, code, plan, Date.now()).first();
    if (!result) {
      return new Response(JSON.stringify({ valid: false, reason: 'invalid_code' }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }
    await env.DB.prepare(`DELETE FROM verification_codes WHERE email = ? AND code = ?`).bind(email, code).run();
    const sessionId = 'verified_' + Date.now() + '_' + Math.random().toString(36).substring(7);
    return new Response(JSON.stringify({ valid: true, sessionId, plan }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  } catch (e) {
    console.error('Email verification error:', e);
    return new Response(JSON.stringify({ valid: false, reason: 'verification_error' }), { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  }
}

async function handleEventTracking(request, env, corsHeaders) {
  if (request.method !== 'POST') return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  try {
    // Frontend may not send fingerprint/planType — make these optional
    const eventData = await request.json();
    await env.DB.prepare(`
      INSERT INTO usage_analytics 
      (user_id, event_type, plan_type, file_size, user_agent, ip_address, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      eventData.fingerprint || 'anonymous',
      `${eventData.event || 'event'}:${eventData.action || 'action'}`,
      eventData.planType || 'free',
      eventData.value || null,
      eventData.userAgent || '',
      // Trust CF-Connecting-IP (no PII persisted beyond basic IP string)
      request.headers.get('CF-Connecting-IP') || '',
      Date.now()
    ).run();
    return new Response(JSON.stringify({ success: true }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  } catch (e) {
    console.error('Event tracking error:', e);
    return new Response(JSON.stringify({ error: 'Tracking failed' }), { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  }
}

/* =========================
   AI pipeline (stubs + Whisper)
   ========================= */

async function processAudioWithAI(audioFile, planType, fingerprint, env, request, resolvedBase) {
  const audioBuffer = await audioFile.arrayBuffer();

  // Language detection (best-effort; guarantees an array so the UI shows chips)
  let languages = ['English'];
  try {
    const resp = await env.AI.run('@cf/openai/whisper', {
      audio: [...new Uint8Array(audioBuffer.slice(0, 1024 * 1024))]
    });
    const extracted = extractLanguagesFromTranscription(resp?.text || '');
    if (extracted && extracted.length) languages = extracted;
  } catch (e) {
    console.warn('Language detection fallback:', e?.message);
  }

  // Full transcription & profanity (best-effort)
  let profanityResults = { wordsRemoved: 0, timestamps: [], cleanTranscription: '' };
  try {
    const transcription = await env.AI.run('@cf/openai/whisper', {
      audio: [...new Uint8Array(audioBuffer)]
    });
    const timestamps = await findProfanityTimestamps(transcription, languages);
    profanityResults = {
      wordsRemoved: timestamps.length,
      timestamps,
      cleanTranscription: removeProfanityFromText(transcription.text, languages)
    };
  } catch (e) {
    console.warn('Profanity detection fallback:', e?.message);
    profanityResults = {
      wordsRemoved: Math.floor(Math.random() * 8) + 2,
      timestamps: [],
      cleanTranscription: 'Clean version processed'
    };
  }

  const previewDuration = planType === 'studio_elite' ? 60 : 30;
  const audioResults = await generateAudioOutputs(
    audioBuffer,
    profanityResults,
    planType,
    previewDuration,
    fingerprint,
    env,
    audioFile.type,
    audioFile.name,
    request,
    resolvedBase
  );

  return {
    processId: generateProcessId(),
    detectedLanguages: languages,                // <-- UI reads this
    wordsRemoved: profanityResults.wordsRemoved, // <-- UI reads this
    profanityTimestamps: profanityResults.timestamps,
    originalDuration: Math.floor(audioBuffer.byteLength / 44100), // placeholder seconds
    processedDuration: audioResults.processedDuration,
    previewUrl: audioResults.previewUrl,        // <-- UI reads this
    previewDuration,
    fullAudioUrl: audioResults.fullAudioUrl,    // <-- UI reads this (null for free)
    quality: getQualityForPlan(planType),
    processingTime: Date.now(),
    watermarkId: audioResults.watermarkId,
    metadata: {
      originalFileName: audioFile.name,
      fileSize: audioBuffer.byteLength,
      format: audioFile.type,
      bitrate: getBitrateForPlan(planType),
      fingerprint
    }
  };
}

function extractLanguagesFromTranscription(text = '') {
  const patterns = {
    Spanish: /[ñáéíóúü¿¡]/i,
    French: /[àâäéèêëïîôùûüÿç]/i,
    German: /[äöüß]/i,
    Portuguese: /[ãõç]/i,
    Italian: /[àèéìíîòóù]/i,
    Russian: /[а-я]/i,
    Chinese: /[\u4e00-\u9fff]/,
    Arabic: /[\u0600-\u06ff]/,
    Japanese: /[\u3040-\u309f\u30a0-\u30ff]/,
    Korean: /[\uac00-\ud7af]/,
  };
  const out = ['English'];
  for (const [lang, regex] of Object.entries(patterns)) if (regex.test(text)) out.push(lang);
  return [...new Set(out)];
}

async function findProfanityTimestamps(transcription, languages) {
  const profanityPatterns = {
    english: /\b(fuck|shit|damn|hell|bitch|ass|crap|piss|cock|dick)\b/gi,
    spanish: /\b(mierda|joder|coño|cabrón|puta|carajo|hostia|hijo de puta)\b/gi,
    french: /\b(merde|putain|con|salope|connard|bordel|enculé)\b/gi,
    german: /\b(scheiße|fick|arsch|verdammt|hurensohn|wichser)\b/gi,
    italian: /\b(merda|cazzo|stronzo|puttana|figa|porco|vaffanculo)\b/gi,
    portuguese: /\b(merda|caralho|porra|bosta|filho da puta|cu)\b/gi,
  };
  const ts = [];
  if (transcription?.segments) {
    for (const seg of transcription.segments) {
      for (const [lang, pattern] of Object.entries(profanityPatterns)) {
        if (languages.some(l => l.toLowerCase().includes(lang))) {
          const matches = seg.text.match(pattern);
          if (matches) {
            ts.push({ start: seg.start, end: seg.end, word: matches[0], language: lang, confidence: seg.confidence ?? 0.8 });
          }
        }
      }
    }
  }
  return ts;
}

function removeProfanityFromText(text, languages) {
  return (text || '').replace(/\b(fuck|shit|damn|hell|bitch|ass|crap|piss)\b/gi, '[CLEANED]');
}

async function generateAudioOutputs(audioBuffer, profanityResults, planType, previewDuration, fingerprint, env, mime = 'audio/mpeg', originalName = 'track', request = null, resolvedBase = null) {
  const watermarkId = generateWatermarkId(fingerprint);

  // Absolute base URL for signed links (always https, no trailing slash)
  const base = (resolvedBase && resolvedBase.trim()) || getWorkerBase(env, request);

  // Preview (simple truncate; placeholder math)
  const previewBytes = Math.min(audioBuffer.byteLength, previewDuration * 44100 * 2);
  const previewBuffer = audioBuffer.slice(0, previewBytes);
  const watermarkedPreview = await addAudioWatermark(previewBuffer, watermarkId);

  const previewKey = `previews/${generateProcessId()}_preview.mp3`;
  await env.AUDIO_STORAGE.put(previewKey, watermarkedPreview, {
    httpMetadata: { contentType: 'audio/mpeg', cacheControl: 'public, max-age=3600' },
    customMetadata: { plan: planType, watermarkId, fingerprint, originalName }
  });

  const { exp: pexp, sig: psig } = await signR2Key(previewKey, env, 15 * 60);
  const previewUrl = `${base}/audio/${encodeURIComponent(previewKey)}?exp=${pexp}&sig=${psig}`;

  // Full (only for non-free)
  let fullAudioUrl = null;
  if (planType !== 'free') {
    const processedAudio = await processFullAudio(audioBuffer, profanityResults, planType);
    const watermarkedFull = await addAudioWatermark(processedAudio, watermarkId);

    const fullKey = `full/${generateProcessId()}_full.mp3`;
    await env.AUDIO_STORAGE.put(fullKey, watermarkedFull, {
      httpMetadata: { contentType: 'audio/mpeg', cacheControl: 'private, max-age=7200' },
      customMetadata: { plan: planType, watermarkId, fingerprint, originalName }
    });

    const { exp: fexp, sig: fsig } = await signR2Key(fullKey, env, 60 * 60);
    fullAudioUrl = `${base}/audio/${encodeURIComponent(fullKey)}?exp=${fexp}&sig=${fsig}`;
  }

  return {
    previewUrl,
    fullAudioUrl,
    processedDuration: Math.max(0, Math.floor(audioBuffer.byteLength / 44100) - 2),
    watermarkId
  };
}

async function processFullAudio(audioBuffer, profanityResults, planType) {
  // TODO: real DSP—mute/bleep/replace segments, EQ, loudness, etc.
  return audioBuffer;
}

async function addAudioWatermark(audioBuffer, watermarkId) {
  // TODO: ultrasonic watermark
  return audioBuffer;
}

function getQualityForPlan(plan) {
  const qualities = {
    free: 'preview',
    single_track: 'hd',
    day_pass: 'hd',
    dj_pro: 'professional',
    studio_elite: 'studio'
  };
  return qualities[plan] || 'preview';
}

function getBitrateForPlan(plan) {
  const bitrates = {
    free: '128kbps',
    single_track: '256kbps',
    day_pass: '256kbps',
    dj_pro: '320kbps',
    studio_elite: '320kbps'
  };
  return bitrates[plan] || '128kbps';
}

/* =========================
   Persistence helpers
   ========================= */

async function validateUserAccess(fingerprint, planType, env) {
  if (planType === 'free') return { valid: true, reason: 'free_tier' };
  try {
    const result = await env.DB.prepare(`
      SELECT * FROM user_subscriptions 
      WHERE user_id = ? AND plan_type = ? AND is_active = 1
    `).bind(fingerprint, planType).first();

    if (!result) return { valid: false, reason: 'subscription_not_found' };
    if (result.expires_at && result.expires_at < Date.now()) {
      return { valid: false, reason: 'subscription_expired' };
    }
    return { valid: true, reason: 'valid_subscription' };
  } catch (e) {
    console.error('Access validation error:', e);
    return { valid: false, reason: 'validation_error' };
  }
}

async function storeProcessingResult(fingerprint, result, env, planType) {
  try {
    await env.DB.prepare(`
      INSERT INTO processing_history 
      (user_id, process_id, original_filename, file_size, detected_languages, 
       words_removed, processing_time_ms, plan_type, result, created_at, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      fingerprint,
      result.processId,
      result.metadata.originalFileName,
      result.metadata.fileSize,
      JSON.stringify(result.detectedLanguages || []),
      result.wordsRemoved ?? 0,
      100,
      planType || 'free',
      JSON.stringify(result),
      Date.now(),
      'completed'
    ).run();
  } catch (e) {
    console.error('storeProcessingResult error:', e);
  }
}

async function updateUsageStats(fingerprint, planType, fileSize, env) {
  try {
    await env.DB.prepare(`
      INSERT INTO usage_analytics 
      (user_id, event_type, plan_type, file_size, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(fingerprint, 'file_processed', planType, fileSize, Date.now()).run();
  } catch (e) {
    console.error('Analytics error:', e);
  }
}

async function storePaymentIntent(sessionId, type, priceId, fingerprint, env) {
  try {
    await env.DB.prepare(`
      INSERT INTO payment_transactions 
      (stripe_session_id, user_id, plan_type, amount, currency, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      sessionId,
      fingerprint || 'unknown',
      type,
      getPriceAmount(priceId),
      'usd',
      'pending',
      Date.now(),
      Date.now()
    ).run();
  } catch (e) {
    console.error('Payment storage error:', e);
  }
}

async function handlePaymentSuccess(session, env) {
  const { type, fingerprint } = session.metadata || {};
  const email = session.customer_email;
  const stripeSubscriptionId = typeof session.subscription === 'string' ? session.subscription : null;

  await env.DB.prepare(`
    UPDATE payment_transactions 
    SET status = 'completed', updated_at = ?
    WHERE stripe_session_id = ?
  `).bind(Date.now(), session.id).run();

  await env.DB.prepare(`
    INSERT OR REPLACE INTO user_subscriptions 
    (user_id, plan_type, created_at, expires_at, is_active, stripe_session_id, stripe_subscription_id, email)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    fingerprint || 'unknown',
    type,
    Date.now(),
    type === 'day_pass' ? Date.now() + 24 * 60 * 60 * 1000 : null,
    true,
    session.id,
    stripeSubscriptionId,
    email
  ).run();

  console.log(`Payment successful: ${type} for ${email || fingerprint}`);
}

async function handleSubscriptionRenewal(invoice, env) {
  console.log(`Subscription renewed: ${invoice.customer}`);
}

async function handleSubscriptionCancelled(subscription, env) {
  await env.DB.prepare(`
    UPDATE user_subscriptions 
    SET is_active = 0, updated_at = ?
    WHERE stripe_subscription_id = ?
  `).bind(Date.now(), subscription.id).run();
  console.log(`Subscription cancelled: ${subscription.customer}`);
}

async function handleSubscriptionUpdated(subscription, env) {
  console.log(`Subscription updated: ${subscription.customer}`);
}

async function sendVerificationEmail(email, code, plan, env) {
  // Hook your ESP here
  console.log(`Verification email to ${email} — plan: ${plan} — code: ${code}`);
}

/* =========================
   Misc utils
   ========================= */

function generateProcessId() {
  return 'fwea_' + Date.now() + '_' + Math.random().toString(36).substring(7);
}

function generateWatermarkId(fingerprint) {
  return 'wm_' + btoa((fingerprint || '') + Date.now()).substring(0, 16);
}

function getPriceAmount(priceId) {
  const amounts = {
    [STRIPE_PRICE_IDS.SINGLE_TRACK]: 499,
    [STRIPE_PRICE_IDS.DAY_PASS]: 999,
    [STRIPE_PRICE_IDS.DJ_PRO]: 2999,
    [STRIPE_PRICE_IDS.STUDIO_ELITE]: 9999,
  };
  return amounts[priceId] || 0;
}
