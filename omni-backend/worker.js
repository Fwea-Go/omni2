// FWEA-I Backend — Cloudflare Worker (Updated and Fixed)

import Stripe from 'stripe';

// --- Durable Object: ProcessingStateV2 ---
export class ProcessingStateV2 {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.cache = new Map();
  }

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

// ---------- Enhanced Profanity Detection ----------
const PROF_CACHE = new Map();

async function getProfanityTrieFor(lang, env) {
  const key = `lists/${lang}.json`;
  if (PROF_CACHE.has(key)) return PROF_CACHE.get(key);

  let words = await env.PROFANITY_LISTS?.get(key, { type: 'json' });
  if (!Array.isArray(words)) words = [];

  // Simple pattern matcher for better reliability
  const patterns = words.map(word => ({
    original: word,
    normalized: normalizeForProfanity(String(word))
  })).filter(p => p.normalized.length > 0);

  const pack = { patterns, words };
  PROF_CACHE.set(key, pack);
  return pack;
}

function normalizeForProfanity(s = '') {
  s = s.toLowerCase();
  s = s.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  
  const replacements = {
    '@': 'a', '₳': 'a', 'Α': 'a', '4': 'a',
    '0': 'o', 'о': 'o', 'Ο': 'o', '〇': 'o',
    '1': 'i', 'l': 'i', '|': 'i', '！': 'i',
    '$': 's', '5': 's',
    '3': 'e', 'Ɛ': 'e',
    '7': 't', 'Т': 't',
    '¢': 'c', 'ç': 'c',
    'ß': 'ss'
  };

  for (const [from, to] of Object.entries(replacements)) {
    s = s.replaceAll(from, to);
  }

  s = s.replace(/(.)\1{2,}/g, '$1$1');
  return s.replace(/[^\p{L}\p{N}\s]/gu, ' ').replace(/\s+/g, ' ').trim();
}

async function matchProfanity(text, lang, env) {
  const pack = await getProfanityTrieFor(lang, env);
  const norm = normalizeForProfanity(text || '');
  if (!pack.patterns || !norm) return [];

  const hits = [];
  
  for (const pattern of pack.patterns) {
    if (!pattern.normalized) continue;
    
    const regex = new RegExp(`\\b${escapeRegex(pattern.normalized)}\\b`, 'gi');
    let match;
    
    while ((match = regex.exec(norm)) !== null) {
      hits.push({
        word: pattern.original,
        start: match.index,
        end: match.index + match[0].length,
        confidence: 0.9
      });
    }
  }

  return dedupeOverlaps(hits);
}

function escapeRegex(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function dedupeOverlaps(arr) {
  arr.sort((a, b) => a.start - b.start || b.end - a.end);
  const out = [];
  let lastEnd = -1;
  
  for (const m of arr) {
    if (m.start >= lastEnd) { 
      out.push(m); 
      lastEnd = m.end; 
    }
  }
  
  return out;
}

function normalizeLangs(langs = []) {
  const map = {
    english: 'en', spanish: 'es', french: 'fr', german: 'de', portuguese: 'pt',
    italian: 'it', russian: 'ru', chinese: 'zh', arabic: 'ar', japanese: 'ja',
    korean: 'ko', hindi: 'hi', turkish: 'tr', indonesian: 'id', swahili: 'sw',
  };
  const out = new Set();
  for (const l of langs) {
    const k = String(l || '').toLowerCase();
    out.add(map[k] || k.slice(0, 2));
  }
  return [...out];
}

// Main Worker
export default {
  async fetch(request, env) {
    // Enhanced CORS
    const reqOrigin = request.headers.get('Origin') || '';
    const workerOrigin = new URL(request.url).origin;
    const configuredFrontend = (env.FRONTEND_URL || '').replace(/\/+$/, '');

    const allowList = [
      configuredFrontend,
      workerOrigin,
      'https://fwea-i.com',
      'https://www.fwea-i.com',
      'http://localhost:3000',
      'http://127.0.0.1:3000'
    ].filter(Boolean);

    const pagesDevPattern = /^https:\/\/[a-z0-9-]+\.pages\.dev$/i;
    const isAllowed = allowList.includes(reqOrigin) || pagesDevPattern.test(reqOrigin);
    const allowOrigin = isAllowed && reqOrigin ? reqOrigin : workerOrigin;

    const corsHeaders = {
      'Access-Control-Allow-Origin': allowOrigin,
      'Vary': 'Origin',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Stripe-Signature, Range, X-FWEA-Admin, X-Requested-With',
      'Access-Control-Max-Age': '86400',
      'Access-Control-Expose-Headers': 'Content-Range, Accept-Ranges, Content-Length, ETag, Content-Type, Last-Modified',
      'Cross-Origin-Resource-Policy': 'cross-origin',
      'Timing-Allow-Origin': '*'
    };

    if (allowOrigin !== workerOrigin && isAllowed) {
      corsHeaders['Access-Control-Allow-Credentials'] = 'true';
    }

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    // Audio streaming
    if (url.pathname.startsWith('/audio/')) {
      return handleAudioDownload(request, env, corsHeaders);
    }

    try {
      switch (url.pathname) {
        case '/process-audio':
          return await handleAudioProcessing(request, env, corsHeaders);
        case '/create-payment':
          return await handlePaymentCreation(request, env, corsHeaders);
        case '/webhook':
          return await handleStripeWebhook(request, env, corsHeaders);
        case '/activate-access':
          return await handleAccessActivation(request, env, corsHeaders);
        case '/validate-subscription':
          return await handleSubscriptionValidation(request, env, corsHeaders);
        case '/send-verification':
          return await handleSendVerification(request, env, corsHeaders);
        case '/verify-email-code':
          return await handleEmailVerification(request, env, corsHeaders);
        case '/track-event':
          return await handleEventTracking(request, env, corsHeaders);
        case '/health':
          return new Response(JSON.stringify({
            status: 'healthy',
            version: '2.0.0',
            timestamp: Date.now(),
            services: {
              r2: Boolean(env.AUDIO_STORAGE),
              database: Boolean(env.DB),
              ai: Boolean(env.AI),
              profanity_lists: Boolean(env.PROFANITY_LISTS),
              stripe: Boolean(env.STRIPE_SECRET_KEY)
            }
          }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });

        // Admin endpoints
        case '/ping-r2':
          return await handlePingR2(request, env, corsHeaders);
        case '/debug-audio':
          return await handleDebugAudio(request, env, corsHeaders);
        case '/sign-audio':
          return await handleSignAudio(request, env, corsHeaders);
        case '/debug-env':
          return await handleDebugEnv(request, env, corsHeaders);
        case '/__log':
          return await handleAdminLog(request, env, corsHeaders);
        case '/redeem-download':
          return await handleRedeemDownload(request, env, corsHeaders);
        case '/download-page':
          return await handleDownloadPage(request, env, corsHeaders);

        default:
          return new Response('Not Found', { status: 404, headers: corsHeaders });
      }
    } catch (error) {
      console.error('Worker Error:', error);
      return new Response(
        JSON.stringify({ 
          error: 'Internal Server Error', 
          details: error.message,
          requestId: crypto.randomUUID()
        }),
        { 
          status: 500, 
          headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
        }
      );
    }
  },
};

// Stripe Configuration
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

// Audio Processing Handler
async function handleAudioProcessing(request, env, corsHeaders) {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), { 
      status: 405, 
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  try {
    const formData = await request.formData();
    const audioFile = formData.get('audio');
    const fingerprint = formData.get('fingerprint') || 'anonymous';
    const planType = formData.get('planType') || 'free';
    const admin = isAdminRequest(request, env);
    const effectivePlan = admin ? 'studio_elite' : planType;

    if (!env.AUDIO_STORAGE) {
      return new Response(JSON.stringify({
        success: false,
        error: 'Storage not configured',
        hint: 'R2 bucket not properly bound'
      }), {
        status: 503,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    if (!audioFile) {
      return new Response(JSON.stringify({
        success: false,
        error: 'No audio file provided',
        hint: 'Send FormData with field name "audio"'
      }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // Validate file size
    const maxSizes = {
      free: 50 * 1024 * 1024,
      single_track: 100 * 1024 * 1024,
      day_pass: 100 * 1024 * 1024,
      dj_pro: 200 * 1024 * 1024,
      studio_elite: 500 * 1024 * 1024,
    };

    const maxSize = maxSizes[effectivePlan] || maxSizes.free;
    if (audioFile.size > maxSize) {
      return new Response(JSON.stringify({
        success: false,
        error: 'File too large',
        maxSize,
        currentSize: audioFile.size,
        upgradeRequired: effectivePlan === 'free'
      }), {
        status: 413,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // Process audio
    const processingResult = await processAudioWithAI(audioFile, effectivePlan, fingerprint, env, request);

    // Store results
    if (env.DB) {
      await storeProcessingResult(fingerprint, processingResult, env, planType);
      await updateUsageStats(fingerprint, planType, audioFile.size, env);
    }

    return new Response(JSON.stringify({
      success: true,
      ...processingResult
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Audio processing error:', error);
    return new Response(JSON.stringify({
      success: false,
      error: 'Audio processing failed',
      details: error.message
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// Payment Creation Handler
async function handlePaymentCreation(request, env, corsHeaders) {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  try {
    const { priceId, type, fileName, email, fingerprint } = await request.json();

    if (!env.STRIPE_SECRET_KEY) {
      return new Response(JSON.stringify({ error: 'Stripe not configured' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    if (!env.FRONTEND_URL) {
      return new Response(JSON.stringify({ error: 'Frontend URL not configured' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const validPriceIds = Object.values(STRIPE_PRICE_IDS);
    if (!validPriceIds.includes(priceId)) {
      return new Response(JSON.stringify({ error: 'Invalid price ID' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    if (!['single_track', 'day_pass', 'dj_pro', 'studio_elite'].includes(type)) {
      return new Response(JSON.stringify({ error: 'Invalid plan type' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
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
      success_url: `${env.FRONTEND_URL.replace(/\/+$/, '')}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${env.FRONTEND_URL.replace(/\/+$/, '')}/cancel`,
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

    // Store payment intent
    if (env.DB) {
      await storePaymentIntent(session.id, type, priceId, fingerprint, env);
    }

    return new Response(JSON.stringify({
      success: true,
      sessionId: session.id,
      url: session.url
    }), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Payment creation error:', error);
    return new Response(JSON.stringify({
      error: 'Payment creation failed',
      details: error.message
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// AI Processing Function
async function processAudioWithAI(audioFile, planType, fingerprint, env, request) {
  try {
    const audioBuffer = await audioFile.arrayBuffer();
    
    // Mock transcription for now - replace with actual AI call
    const transcription = {
      text: "This is a sample transcription with some inappropriate content",
      language: 'en',
      segments: [{
        start: 0,
        end: 30,
        text: "This is a sample transcription with some inappropriate content",
        confidence: 0.9
      }]
    };

    // Language detection
    const detectedLanguages = extractLanguagesFromTranscription(transcription.text);
    const normalizedLanguages = normalizeLangs(detectedLanguages);
    
    // Profanity detection  
    const profanityResults = await findProfanityTimestamps(transcription, normalizedLanguages, env);
    
    // Generate audio outputs
    const audioOutputs = await generateAudioOutputs(
      audioBuffer,
      profanityResults,
      planType,
      getPreviewDuration(planType),
      fingerprint,
      env,
      audioFile.type,
      audioFile.name,
      request
    );

    return {
      success: true,
      previewUrl: audioOutputs.previewUrl,
      fullAudioUrl: audioOutputs.fullAudioUrl,
      languages: normalizedLanguages,
      profanityFound: profanityResults.timestamps?.length || 0,
      transcription: planType !== 'free' ? transcription : null,
      quality: getQualityForPlan(planType),
      watermarkId: audioOutputs.watermarkId
    };

  } catch (error) {
    console.error('AI processing error:', error);
    return {
      success: false,
      error: 'AI processing failed',
      details: error.message
    };
  }
}

// Helper functions
function extractLanguagesFromTranscription(text = '') {
  const patterns = {
    Spanish: /[ñáéíóúü¿¡]/i,
    French: /[àâäéèêëïîôùûüÿç]/i,
    German: /[äöüß]/i
  };

  const detected = ['English'];
  for (const [lang, regex] of Object.entries(patterns)) {
    if (regex.test(text)) detected.push(lang);
  }
  
  return [...new Set(detected)];
}

async function findProfanityTimestamps(transcription, languages, env) {
  const timestamps = [];
  
  if (!transcription?.segments?.length) {
    return { timestamps };
  }

  const langCodes = normalizeLangs(languages);
  
  for (const segment of transcription.segments) {
    for (const langCode of langCodes) {
      const matches = await matchProfanity(segment.text || '', langCode, env);
      
      for (const match of matches) {
        timestamps.push({
          start: segment.start || 0,
          end: segment.end || 30,
          word: match.word,
          language: langCode,
          confidence: match.confidence || 0.8
        });
      }
    }
  }

  return { timestamps };
}

async function generateAudioOutputs(audioBuffer, profanityResults, planType, previewDuration, fingerprint, env, mimeType, originalName, request) {
  const processId = generateProcessId();
  const base = getWorkerBase(env, request);
  
  // Generate preview
  const previewKey = `previews/${processId}_preview.mp3`;
  const previewSlice = audioBuffer.slice(0, Math.min(audioBuffer.byteLength, previewDuration * 44100 * 2)); // Rough approximation
  
  try {
    await env.AUDIO_STORAGE.put(previewKey, previewSlice, {
      httpMetadata: { contentType: 'audio/mpeg' },
      customMetadata: {
        plan: planType,
        fingerprint,
        originalName,
        previewMs: String(previewDuration * 1000)
      }
    });
  } catch (e) {
    console.warn('R2 put preview failed:', e?.message || e);
  }

  const { exp: pexp, sig: psig } = await signR2Key(previewKey, env, 15 * 60);
  const previewUrl = psig 
    ? `${base}/audio/${encodeURIComponent(previewKey)}?exp=${pexp}&sig=${psig}`
    : `${base}/audio/${encodeURIComponent(previewKey)}`;

  // Generate full version for paid plans
  let fullAudioUrl = null;
  if (planType !== 'free') {
    const fullKey = `full/${processId}_full.mp3`;
    
    try {
      await env.AUDIO_STORAGE.put(fullKey, audioBuffer, {
        httpMetadata: { contentType: 'audio/mpeg' },
        customMetadata: { plan: planType, fingerprint, originalName }
      });
    } catch (e) {
      console.warn('R2 put full failed:', e?.message || e);
    }

    const { exp: fexp, sig: fsig } = await signR2Key(fullKey, env, 60 * 60);
    fullAudioUrl = fsig
      ? `${base}/audio/${encodeURIComponent(fullKey)}?exp=${fexp}&sig=${fsig}`
      : `${base}/audio/${encodeURIComponent(fullKey)}`;
  }

  return {
    previewUrl,
    fullAudioUrl,
    watermarkId: generateWatermarkId(fingerprint)
  };
}

// Utility functions
function getPreviewDuration(plan) {
  const durations = { free: 30, single_track: 45, day_pass: 45, dj_pro: 45, studio_elite: 60 };
  return durations[plan] || 30;
}

function getQualityForPlan(plan) {
  const qualities = { free: 'Standard', single_track: 'HD', day_pass: 'HD', dj_pro: 'HD+', studio_elite: 'Studio Grade' };
  return qualities[plan] || 'Standard';
}

function generateProcessId() {
  return Date.now().toString(36) + Math.random().toString(36).substring(2);
}

function generateWatermarkId(fingerprint) {
  return fingerprint + '_' + Date.now().toString(36);
}

function isAdminRequest(request, env) {
  try {
    const hdr = (request.headers.get('X-FWEA-Admin') || '').trim();
    const tok = (env.ADMIN_API_TOKEN || '').trim();
    if (!hdr || !tok) return false;
    return hdr === tok; // Simple comparison for now
  } catch {
    return false;
  }
}

function getWorkerBase(env, request) {
  let base = (env.WORKER_BASE_URL || '').trim();
  if (base) {
    if (!/^https?:\/\//i.test(base)) base = 'https://' + base;
    try { 
      const u = new URL(base); 
      base = 'https://' + u.host; 
    } catch {}
    return base.replace(/\/+$/, '');
  }
  
  try {
    const origin = new URL(request.url).origin;
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
  if (!env.AUDIO_URL_SECRET) {
    return { exp: 0, sig: '' };
  }
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const msg = `${key}:${exp}`;
  const sig = await hmacSHA256(msg, env.AUDIO_URL_SECRET);
  return { exp, sig };
}

async function verifySignedUrl(key, exp, sig, env) {
  if (!env.AUDIO_URL_SECRET) return true;
  if (!exp || !sig) return false;
  const now = Math.floor(Date.now() / 1000);
  if (Number(exp) <= now) return false;
  const msg = `${key}:${exp}`;
  const expected = await hmacSHA256(msg, env.AUDIO_URL_SECRET);
  return expected === sig;
}

// Audio download handler
async function handleAudioDownload(request, env, corsHeaders) {
  const url = new URL(request.url);
  const key = decodeURIComponent(url.pathname.replace(/^\/audio\//, ''));
  if (!key) return new Response('Bad Request', { status: 400, headers: corsHeaders });

  if (!env.AUDIO_STORAGE) {
    return new Response(JSON.stringify({ error: 'Storage not configured' }), {
      status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  const exp = url.searchParams.get('exp');
  const sig = url.searchParams.get('sig');
  const ok = await verifySignedUrl(key, exp, sig, env);
  if (!ok) {
    return new Response(JSON.stringify({ error: 'Invalid or expired link' }), {
      status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  const r2Obj = await env.AUDIO_STORAGE.get(key);
  if (!r2Obj) return new Response('Not found', { status: 404, headers: corsHeaders });

  const headers = {
    ...corsHeaders,
    'Content-Type': 'audio/mpeg',
    'Content-Length': String(r2Obj.size),
    'Accept-Ranges': 'bytes',
    'Cache-Control': key.startsWith('previews/') ? 'public, max-age=3600' : 'private, max-age=7200'
  };

  return new Response(r2Obj.body, { status: 200, headers });
}

// Stub implementations for remaining handlers
async function handleStripeWebhook(request, env, corsHeaders) {
  return new Response('OK', { status: 200, headers: corsHeaders });
}

async function handleAccessActivation(request, env, corsHeaders) {
  return new Response(JSON.stringify({ success: true }), { 
    headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
  });
}

async function handleSubscriptionValidation(request, env, corsHeaders) {
  return new Response(JSON.stringify({ valid: true }), { 
    headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
  });
}

async function handleSendVerification(request, env, corsHeaders) {
  return new Response(JSON.stringify({ success: true }), { 
    headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
  });
}

async function handleEmailVerification(request, env, corsHeaders) {
  return new Response(JSON.stringify({ valid: true }), { 
    headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
  });
}

async function handleEventTracking(request, env, corsHeaders) {
  return new Response(JSON.stringify({ success: true }), { 
    headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
  });
}

async function handlePingR2(request, env, corsHeaders) {
  if (!isAdminRequest(request, env)) {
    return new Response('Forbidden', { status: 403, headers: corsHeaders });
  }
  return new Response(JSON.stringify({ ok: true, hasR2: Boolean(env.AUDIO_STORAGE) }), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

async function handleDebugAudio(request, env, corsHeaders) {
  if (!isAdminRequest(request, env)) {
    return new Response('Forbidden', { status: 403, headers: corsHeaders });
  }
  return new Response(JSON.stringify({ debug: true }), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

async function handleSignAudio(request, env, corsHeaders) {
  if (!isAdminRequest(request, env)) {
    return new Response('Forbidden', { status: 403, headers: corsHeaders });
  }
  return new Response(JSON.stringify({ signed: true }), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

async function handleDebugEnv(request, env, corsHeaders) {
  if (!isAdminRequest(request, env)) {
    return new Response('Forbidden', { status: 403, headers: corsHeaders });
  }
  
  const debug = {
    has_AUDIO_URL_SECRET: Boolean(env.AUDIO_URL_SECRET),
    FRONTEND_URL: env.FRONTEND_URL || null,
    WORKER_BASE_URL: env.WORKER_BASE_URL || null,
    has_R2: Boolean(env.AUDIO_STORAGE),
    has_DB: Boolean(env.DB),
    has_AI: Boolean(env.AI),
    has_PROFANITY_KV: Boolean(env.PROFANITY_LISTS),
    workerBase: getWorkerBase(env, request),
  };
  
  return new Response(JSON.stringify(debug, null, 2), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

async function handleAdminLog(request, env, corsHeaders) {
  if (!isAdminRequest(request, env)) {
    return new Response('Forbidden', { status: 403, headers: corsHeaders });
  }
  return new Response('OK', { headers: corsHeaders });
}

async function handleRedeemDownload(request, env, corsHeaders) {
  return new Response('Redeem endpoint', { status: 200, headers: corsHeaders });
}

async function handleDownloadPage(request, env, corsHeaders) {
  return new Response('Download page', { status: 200, headers: corsHeaders });
}

// Stub database functions
async function storeProcessingResult(fingerprint, result, env, planType) {
  if (!env.DB) return;
  // Store processing result in database
}

async function updateUsageStats(fingerprint, planType, fileSize, env) {
  if (!env.DB) return;
  // Update usage statistics
}

async function storePaymentIntent(sessionId, type, priceId, fingerprint, env) {
  if (!env.DB) return;
  // Store payment intent in database
}
