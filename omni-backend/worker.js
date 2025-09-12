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

// ---------- Profanity detection (Trie over KV) ----------
// Cache per-language tries so we only build once per Worker instance
const PROF_CACHE = new Map(); // key: `lists/<lang>.json` -> { trie, words }

async function getProfanityTrieFor(lang, env) {
  const key = `lists/${lang}.json`;
  if (PROF_CACHE.has(key)) return PROF_CACHE.get(key);

  // Get JSON array of words for this language from KV
  let words = await env.PROFANITY_LISTS?.get(key, { type: 'json' });
  if (!Array.isArray(words)) words = [];

  // Build Aho–Corasick trie at runtime (bundled via npm dep)
  const { default: Aho } = await import('ahocorasick');
  const builder = new Aho.Trie();
  for (const w of words) {
    if (w) builder.add(normalizeForProfanity(String(w)));
  }
  const trie = builder.build();
  const pack = { trie, words };
  PROF_CACHE.set(key, pack);
  return pack;
}

function normalizeForProfanity(s = '') {
  s = s.toLowerCase();
  // strip diacritics
  s = s.normalize('NFD').replace(/\p{Diacritic}+/gu, '');
  // simple leetspeak & lookalikes
  s = s
    .replace(/[@₳Α]/g, 'a')
    .replace(/[0оＯ〇º°]/g, 'o')
    .replace(/[1l|！Ι]/g, 'i')
    .replace(/\$/g, 's')
    .replace(/[3Ɛ]/g, 'e')
    .replace(/[7Ｔ]/g, 't')
    .replace(/[5Ｓ]/g, 's')
    .replace(/[¢ç]/g, 'c')
    .replace(/[¡ɪ]/g, 'i')
    .replace(/[ß]/g, 'ss');
  // collapse 3+ repeats to 2
  s = s.replace(/(.)\1{2,}/g, '$1$1');
  // remove punctuation but keep spaces; collapse spaces
  return s.replace(/[^\p{L}\p{N}\s]/gu, ' ').replace(/\s+/g, ' ').trim();
}

async function matchProfanity(text, lang, env) {
  const pack = await getProfanityTrieFor(lang, env);
  const norm = normalizeForProfanity(text || '');
  if (!pack.trie || !norm) return [];
  const hits = [];
  for (const h of pack.trie.find(norm)) {
    for (const w of h.outputs) {
      hits.push({ word: w, start: h.index - w.length + 1, end: h.index + 1 });
    }
  }
  return dedupeOverlaps(hits);
}

function dedupeOverlaps(arr) {
  arr.sort((a, b) => a.start - b.start || b.end - a.end);
  const out = [];
  let lastEnd = -1;
  for (const m of arr) {
    if (m.start >= lastEnd) { out.push(m); lastEnd = m.end; }
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

// Move export default outside the class
export default {
  async fetch(request, env) {
    // ---------- CORS (echo only if origin is in allowlist) ----------
    const reqOrigin = request.headers.get('Origin') || '';
    const workerOrigin = new URL(request.url).origin;

    // Normalize configured frontend (strip trailing slash)
    const configuredFrontend = (env.FRONTEND_URL || '').replace(/\/+$/, '');

    // Allowlist plus pattern-matches for Pages previews and prod domains
    const allowList = [
      configuredFrontend,
      workerOrigin,
      'https://fwea-i.com',
      'https://www.fwea-i.com',
      'http://localhost:3000',
      'http://127.0.0.1:3000'
    ].filter(Boolean);

    // Accept reqOrigin if it matches the allowList OR known patterns (*.pages.dev)
    const pagesDevPattern = /^https:\/\/[a-z0-9-]+\.pages\.dev$/i;
    const isAllowed =
      allowList.includes(reqOrigin) ||
      pagesDevPattern.test(reqOrigin);

    // If we can positively echo the origin, do it; otherwise fall back to worker origin (NOT "*")
    const allowOrigin = isAllowed && reqOrigin ? reqOrigin : workerOrigin;

    // Only advertise credentials support when we're echoing a concrete origin
    const baseCors = {
      'Access-Control-Allow-Origin': allowOrigin,
      'Vary': 'Origin',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Stripe-Signature, Range, X-FWEA-Admin, X-Requested-With',
      'Access-Control-Max-Age': '86400',
      // Expose streaming/seek headers so <audio> can read them
      'Access-Control-Expose-Headers': 'Content-Range, Accept-Ranges, Content-Length, ETag, Content-Type, Last-Modified',
      'Cross-Origin-Resource-Policy': 'cross-origin',
      'Timing-Allow-Origin': '*'
    };
    // Conditionally add credentials header (illegal with "*" / opaque origins)
    const corsHeaders = allowOrigin === workerOrigin
      ? baseCors
      : { ...baseCors, 'Access-Control-Allow-Credentials': 'true' };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    // Support versioned paths like /v2/* by normalizing to unversioned routes
    let path = url.pathname;
    if (path.startsWith('/v2/')) {
      path = path.slice(3); // drop the leading '/v2'
    }

    // signed audio streaming
    if (path.startsWith('/audio/')) {
      return handleAudioDownload(request, env, corsHeaders);
    }

    try {
      switch (path) {
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

        // NEW: helpers to check R2 & sign files (kept from your version) …
        case '/ping-r2': {
          if (!isAdminRequest(request, env)) {
            return new Response('Forbidden', { status: 403, headers: corsHeaders });
          }
          try {
            const hasR2 = Boolean(env.AUDIO_STORAGE);
            let putOk = false, got = null;
            if (hasR2) {
              const key = '__health/ping.txt';
              await env.AUDIO_STORAGE.put(key, 'ok', {
                httpMetadata: { contentType: 'text/plain' }
              });
              putOk = true;
              got = await env.AUDIO_STORAGE.get(key);
            }
            return new Response(JSON.stringify({
              ok: true,
              hasR2,
              wrote: putOk,
              read: Boolean(got),
              size: got?.size ?? null
            }), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
          } catch (e) {
            return new Response(JSON.stringify({
              ok: false,
              error: e?.message || String(e)
            }), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
          }
        }
        case '/transcribe': {
          if (request.method !== 'POST') return new Response('Method not allowed', { status: 405, headers: corsHeaders });
          try {
            // If an external transcriber is configured, proxy the request through unchanged.
            if (env.TRANSCRIBE_ENDPOINT) {
              const endpoint = String(env.TRANSCRIBE_ENDPOINT).replace(/\/+$/, '') + '/transcribe';
              const ct = request.headers.get('content-type') || '';
              const init = { method: 'POST', headers: {} };

              if (ct.startsWith('multipart/form-data')) {
                init.body = await request.formData();
              } else {
                // Pass-through raw body for non-multipart requests
                init.body = await request.arrayBuffer();
                if (ct) init.headers['Content-Type'] = ct;
              }
              if (env.TRANSCRIBE_TOKEN) init.headers['X-API-Token'] = String(env.TRANSCRIBE_TOKEN);

              const resp = await fetch(endpoint, init);
              const buf = await resp.arrayBuffer();
              const outCT = resp.headers.get('content-type') || 'application/json';
              return new Response(buf, { status: resp.status, headers: { ...corsHeaders, 'Content-Type': outCT } });
            }

            // Otherwise, do local transcription using Workers AI
            const form = await request.formData();
            const file = form.get('audio') || form.get('file');
            if (!file) {
              return new Response(JSON.stringify({ error: 'missing audio' }), {
                status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
              });
            }
            const buf = await file.arrayBuffer();
            const tr  = await aiTranscribe(buf, env);
            return new Response(JSON.stringify({ success: true, transcription: tr }), {
              status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
          } catch (e) {
            console.warn('transcription_failed', e?.message || e);
            return new Response(JSON.stringify({ success: false, error: 'transcription_failed' }), {
              status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
          }
        }
        case '/debug-audio': {
          if (!isAdminRequest(request, env)) {
            return new Response('Forbidden', { status: 403, headers: corsHeaders });
          }
          const q = new URL(request.url);
          const key = q.searchParams.get('key') || '';
          if (!key) {
            return new Response(JSON.stringify({ error: 'Missing ?key=' }), {
              status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
          }
          try {
            const obj = await env.AUDIO_STORAGE?.get(key);
            return new Response(JSON.stringify({
              exists: Boolean(obj),
              size: obj?.size || 0,
              range: obj?.range || null,
              httpMetadata: obj?.httpMetadata || null,
              customMetadata: obj?.customMetadata || null
            }, null, 2), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
          } catch (e) {
            return new Response(JSON.stringify({
              exists: false,
              error: e?.message || String(e)
            }), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
          }
        }
        case '/sign-audio': {
          if (!isAdminRequest(request, env)) {
            return new Response('Forbidden', { status: 403, headers: corsHeaders });
          }
          const u = new URL(request.url);
          const key = u.searchParams.get('key');
          if (!key) {
            return new Response(JSON.stringify({ error: 'Missing ?key=' }), {
              status: 400,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
          }
          try {
            const { exp, sig } = await signR2Key(key, env, 15 * 60);
            const base = getWorkerBase(env, request);
            const url2 = sig
              ? `${base}/audio/${encodeURIComponent(key)}?exp=${exp}&sig=${sig}`
              : `${base}/audio/${encodeURIComponent(key)}`;
            return new Response(JSON.stringify({ url: url2, exp, sig }), {
              status: 200,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
          } catch (e) {
            return new Response(JSON.stringify({ error: e?.message || String(e) }), {
              status: 200,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
          }
        }

        // NEW: post-payment redemption (download gated by active sub)
        case '/redeem-download': {
          const u = new URL(request.url);
          const sessionId = u.searchParams.get('session_id') || '';
          const processId = u.searchParams.get('process_id') || '';
          if (!env.DB || !sessionId) {
            return new Response('Missing session_id or DB not configured', { status: 400, headers: corsHeaders });
          }
          try {
            const row = await env.DB.prepare(`SELECT user_id, plan_type, is_active FROM user_subscriptions WHERE stripe_session_id = ?`).bind(sessionId).first();
            if (!row || !row.is_active) return new Response('Subscription not active', { status: 403, headers: corsHeaders });
            const hist = processId
              ? await env.DB.prepare(`SELECT result FROM processing_history WHERE process_id = ? LIMIT 1`).bind(processId).first()
              : await env.DB.prepare(`SELECT result FROM processing_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 1`).bind(row.user_id).first();
            if (!hist) return new Response('No processed audio found', { status: 404, headers: corsHeaders });
            const result = JSON.parse(hist.result || '{}');
            const fullUrl = result.fullAudioUrl;
            if (!fullUrl) return new Response('Full audio not available', { status: 404, headers: corsHeaders });
            return Response.redirect(fullUrl, 302);
          } catch {
            return new Response('Redeem failed', { status: 500, headers: corsHeaders });
          }
        }
        case '/download-page': {
          const u = new URL(request.url);
          const sessionId = u.searchParams.get('session_id') || '';
          const processId = u.searchParams.get('process_id') || '';
          if (!env.DB || !sessionId) {
            return new Response('Missing session_id or DB not configured', { status: 400, headers: corsHeaders });
          }
          try {
            const row = await env.DB.prepare(`SELECT user_id, plan_type, is_active FROM user_subscriptions WHERE stripe_session_id = ?`).bind(sessionId).first();
            if (!row || !row.is_active) return new Response('Subscription not active', { status: 403, headers: corsHeaders });
            const hist = processId
              ? await env.DB.prepare(`SELECT result FROM processing_history WHERE process_id = ? LIMIT 1`).bind(processId).first()
              : await env.DB.prepare(`SELECT result FROM processing_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 1`).bind(row.user_id).first();
            if (!hist) return new Response('No processed audio found', { status: 404, headers: corsHeaders });
            const result = JSON.parse(hist.result || '{}');
            const fullUrl = result.fullAudioUrl;
            if (!fullUrl) return new Response('Full audio not available', { status: 404, headers: corsHeaders });
            const html = `<!doctype html><meta charset="utf-8"><title>Your Download</title><style>body{font-family:system-ui;padding:24px;line-height:1.45}a{font-size:18px}</style><h1>Ready to download</h1><p>Your clean track is ready.</p><p><a href="${fullUrl}">Download clean version</a></p>`;
            return new Response(html, { status: 200, headers: { ...corsHeaders, 'Content-Type': 'text/html; charset=utf-8' } });
          } catch {
            return new Response('Download page failed', { status: 500, headers: corsHeaders });
          }
        }

        case '/debug-env': {
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
            has_TRANSCRIBE_ENDPOINT: Boolean(env.TRANSCRIBE_ENDPOINT),
            has_TRANSCRIBE_TOKEN: Boolean(env.TRANSCRIBE_TOKEN),
            workerBase: getWorkerBase(env, request),
          };
          return new Response(JSON.stringify(debug, null, 2), {
            status: 200,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }
        case '/__log': {
          if (!isAdminRequest(request, env)) return new Response('Forbidden', { status: 403, headers: corsHeaders });
          const body = await request.text();
          console.log('[ADMIN LOG]', body);
          return new Response('OK', { headers: corsHeaders });
        }

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

  async queue(batch, env) {
    if (!env.TRANSCODER_URL) { for (const m of batch.messages) m.ack(); return; }
    for (const m of batch.messages) {
      try {
        await fetch(env.TRANSCODER_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(m.body || {})
        });
        m.ack();
      } catch (e) {
        console.warn('queue push failed', e?.message || e);
        m.retry();
      }
    }
  },

};
/* =========================
   Helpers — signing & range
   ========================= */

function isAdminRequest(request, env) {
  try {
    const hdr = (request.headers.get('X-FWEA-Admin') || '').trim();
    const tok = (env.ADMIN_API_TOKEN || '').trim();
    if (!hdr || !tok) return false;
    const enc = new TextEncoder();
    const a = enc.encode(hdr);
    const b = enc.encode(tok);
    if (crypto.timingSafeEqual) return crypto.timingSafeEqual(a, b);
    if (a.length !== b.length) return false;
    let out = 0; for (let i = 0; i < a.length; i++) out |= a[i] ^ b[i];
    return out === 0;
  } catch { return false; }
}

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
  if (!env.AUDIO_URL_SECRET) {
    // Lenient/dev mode: allow unsigned links
    return { exp: 0, sig: '' };
  }
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const msg = `${key}:${exp}`;
  const sig = await hmacSHA256(msg, env.AUDIO_URL_SECRET);
  return { exp, sig };
}

async function verifySignedUrl(key, exp, sig, env) {
  // If no secret configured, accept any request (dev/lenient mode)
  if (!env.AUDIO_URL_SECRET) return true;
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

  // Surface preview/profanity metadata to clients
  const meta = r2Obj?.customMetadata || {};

  const isPartial = Boolean(r2Obj.range);
  const size = r2Obj.size;
  const mime = (r2Obj.httpMetadata && r2Obj.httpMetadata.contentType) || 'audio/mpeg';
  const headers = {
    ...corsHeaders,
    'Content-Type': mime,
    'Accept-Ranges': 'bytes',
    'Cache-Control': key.startsWith('previews/') ? 'public, max-age=3600' : 'private, max-age=7200'
  };
  headers['Access-Control-Expose-Headers'] =
    (headers['Access-Control-Expose-Headers'] || 'Content-Range, Accept-Ranges, Content-Length, ETag, Content-Type, Last-Modified') +
    ', X-Preview-Limit-Ms, X-Profanity';

  if (meta && meta.previewMs) headers['X-Preview-Limit-Ms'] = meta.previewMs;
  if (meta && meta.profanity) headers['X-Profanity'] = meta.profanity;

  // Set ETag header if available
  const etag = r2Obj?.httpEtag || r2Obj?.etag || null;
  if (etag) headers['ETag'] = etag;
  // Set Last-Modified header if available
  const lastMod = r2Obj?.uploaded || r2Obj?.httpMetadata?.lastModified || null;
  if (lastMod) headers['Last-Modified'] = new Date(lastMod).toUTCString();
  headers['Content-Disposition'] = key.startsWith('previews/') ? 'inline; filename="preview.mp3"' : 'inline; filename="full.mp3"';
  // Harden MIME guard: fallback to audio/mpeg if missing or not audio
  if (!headers['Content-Type'] || !String(headers['Content-Type']).startsWith('audio/')) {
    headers['Content-Type'] = 'audio/mpeg';
  }

  if (isPartial) {
    const start = r2Obj.range.offset;
    const length = r2Obj.range.length;
    const end = start + length - 1;
    headers['Content-Range'] = `bytes ${start}-${end}/${size}`;
    headers['Content-Length'] = String(length);
    headers['Accept-Ranges'] = 'bytes';
    return new Response(r2Obj.body, { status: 206, headers });
  } else {
    headers['Content-Length'] = String(size);
    headers['Accept-Ranges'] = 'bytes';
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
    const admin = isAdminRequest(request, env);
    const effectivePlan = admin ? 'studio_elite' : planType;

    if (!env.AUDIO_STORAGE) {
      const payload = {
        success: false,
        error: 'Storage not configured',
        hint: 'Bind your R2 bucket as AUDIO_STORAGE in wrangler.toml and in the Dashboard.'
      };
      return new Response(JSON.stringify(payload), {
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
      });
    }

    if (!audioFile) {
      return new Response(JSON.stringify({ error: 'No audio file provided', hint: 'Send FormData with field name \"audio\".' }), {
        status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // Access validation
    const accessValidation = await validateUserAccess(fingerprint, planType, env, request);
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
    const maxSize = maxSizes[effectivePlan] || maxSizes.free;
    if (audioFile.size > maxSize) {
      return new Response(JSON.stringify({
        error: 'File too large', maxSize, currentSize: audioFile.size, upgradeRequired: effectivePlan === 'free'
      }), { status: 413, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    // AI processing
    const processingResult = await processAudioWorkersAI(audioFile, effectivePlan, fingerprint, env, request, getWorkerBase(env, request));

    if (!processingResult.previewUrl) {
      console.warn('No previewUrl generated; check R2 binding and AUDIO_URL_SECRET');
    }

    await storeProcessingResult(fingerprint, processingResult, env, planType);
    await updateUsageStats(fingerprint, planType, audioFile.size, env);

    return new Response(JSON.stringify({ success: true, ...processingResult }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Audio processing error:', error);
    const payload = {
      success: false,
      error: 'Audio processing failed',
      details: (error && error.message) ? error.message : String(error || 'unknown'),
      hint: 'If this persists, check R2 binding, AUDIO_URL_SECRET, and Workers AI availability.'
    };
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
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
    if (!env.DB) {
      return new Response(JSON.stringify({ success: false, error: 'db_not_configured' }), {
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
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
    if (!env.DB) {
      return new Response(JSON.stringify({ valid: false, reason: 'db_not_configured' }), {
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
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
    if (!env.DB) {
      return new Response(JSON.stringify({ success: false, error: 'db_not_configured' }), {
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
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
    if (!env.DB) {
      return new Response(JSON.stringify({ valid: false, reason: 'db_not_configured' }), {
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
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
    if (!env.DB) {
      // Soft-success when analytics storage is unavailable
      return new Response(JSON.stringify({ success: true, note: 'analytics_disabled' }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }
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

async function processAudioWorkersAI(audioFile, planType, fingerprint, env, request, resolvedBase) {
  const audioBuffer = await audioFile.arrayBuffer();

  // Safety guard: empty or tiny file
  if (!audioBuffer || audioBuffer.byteLength < 64) {
    return {
      processId: generateProcessId(),
      detectedLanguages: ['English'],
      wordsRemoved: 0,
      profanityTimestamps: [],
      originalDuration: 0,
      processedDuration: 0,
      previewUrl: null,
      previewDuration: 0,
      fullAudioUrl: null,
      quality: getQualityForPlan(planType),
      processingTime: Date.now(),
      watermarkId: generateWatermarkId(fingerprint),
      metadata: {
        originalFileName: audioFile.name,
        fileSize: 0,
        format: (audioFile.type && audioFile.type.startsWith('audio/')) ? audioFile.type : 'audio/mpeg',
        bitrate: getBitrateForPlan(planType),
        fingerprint
      }
    };
  }

  // Transcribe (external endpoint if configured, otherwise Workers AI Whisper)
  let transcription = null;
  try {
    transcription = await aiTranscribe(audioBuffer, env);
  } catch (e) {
    console.warn('Workers-AI transcription failed:', e?.message || e);
  }

  // Language detection from transcript text (best-effort)
  let languages = ['English'];
  try {
    const text = transcription && transcription.text ? transcription.text : '';
    const inferred = extractLanguagesFromTranscription(text);
    if (inferred && inferred.length) languages = inferred;
  } catch {}

  // Profanity windows based on transcript segments
  let profanityResults = { wordsRemoved: 0, timestamps: [], cleanTranscription: '' };
  try {
    if (transcription) {
      const timestamps = await findProfanityTimestamps(transcription, languages, env);
      profanityResults = {
        wordsRemoved: timestamps.length,
        timestamps,
        cleanTranscription: removeProfanityFromText(transcription.text || '', languages)
      };
    }
  } catch (e) {
    console.warn('Profanity marking failed:', e?.message || e);
  }

  const previewDuration = planType === 'studio_elite' ? 60 : 30;

  // Generate streaming outputs (R2-signed)
  let audioResults = {
    previewUrl: null,
    fullAudioUrl: null,
    processedDuration: Math.max(0, Math.floor(audioBuffer.byteLength / 44100) - 2),
    watermarkId: generateWatermarkId(fingerprint)
  };
  try {
    audioResults = await generateAudioOutputs(
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
  } catch (e) {
    console.warn('generateAudioOutputs failed:', e?.message || e);
  }

  return {
    processId: generateProcessId(),
    detectedLanguages: languages,
    wordsRemoved: profanityResults.wordsRemoved,
    profanityTimestamps: profanityResults.timestamps,
    cleanTranscription: profanityResults.cleanTranscription,
    originalDuration: Math.floor(audioBuffer.byteLength / 44100),
    processedDuration: audioResults.processedDuration,
    previewUrl: audioResults.previewUrl,
    previewDuration,
    fullAudioUrl: audioResults.fullAudioUrl,
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
// Workers-AI transcription helper
async function aiTranscribe(buffer, env, capBytes = 5 * 1024 * 1024) {
  // Prefer external transcriber when configured; fallback to Workers AI Whisper
  const out = { text: '', segments: [] };

  // Try external service first if configured
  try {
    const endpoint = (env && env.TRANSCRIBE_ENDPOINT) ? String(env.TRANSCRIBE_ENDPOINT).replace(/\/+$/, '') : '';
    const token = (env && env.TRANSCRIBE_TOKEN) ? String(env.TRANSCRIBE_TOKEN) : '';
    if (endpoint) {
      const slice = buffer && buffer.byteLength > capBytes ? buffer.slice(0, capBytes) : buffer;
      const blob  = new Blob([slice], { type: 'audio/mpeg' });
      const file  = new File([blob], 'audio.mp3', { type: 'audio/mpeg' });
      const fd    = new FormData();
      fd.set('audio', file, file.name);

      const resp = await fetch(`${endpoint}/transcribe`, {
        method: 'POST',
        body: fd,
        headers: token ? { 'X-API-Token': token } : {}
      });

      const ct   = resp.headers.get('content-type') || '';
      const data = ct.includes('application/json') ? await resp.json().catch(() => ({}))
                                                   : { text: await resp.text() };
      if (!resp.ok) throw new Error(`transcriber ${resp.status}`);

      out.text = String(data.text || data.transcription || '');
      if (Array.isArray(data.segments)) out.segments = data.segments;
      return out;
    }
  } catch (e) {
    console.warn('External transcriber failed, falling back to Workers AI:', e?.message || e);
  }

  // Fallback: Workers AI Whisper
  try {
    if (!env?.AI || typeof env.AI.run !== 'function') return out;
    const slice = buffer && buffer.byteLength > capBytes ? buffer.slice(0, capBytes) : buffer;
    const resp  = await env.AI.run('@cf/openai/whisper', { audio: [...new Uint8Array(slice)] });
    if (resp && typeof resp === 'object') {
      out.text = resp.text || '';
      if (Array.isArray(resp.segments)) out.segments = resp.segments;
    }
  } catch (e) {
    console.warn('aiTranscribe (Workers AI) error:', e?.message || e);
  }
  return out;
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

async function findProfanityTimestamps(transcription, languages, env) {
  const ts = [];
  if (!transcription?.segments?.length) return ts;
  const langCodes = normalizeLangs(languages);

  for (const seg of transcription.segments) {
    for (const lc of langCodes) {
      const matches = await matchProfanity(seg.text || '', lc, env);
      for (const m of matches) {
        ts.push({
          start: seg.start,
          end: seg.end,
          word: m.word,
          language: lc,
          confidence: seg.confidence ?? 0.8
        });
      }
    }
  }
  return ts;
}

function removeProfanityFromText(text, languages) {
  return (text || '').replace(/\b(fuck|shit|damn|hell|bitch|ass|crap|piss)\b/gi, '[CLEANED]');
}

async function runTranscriptionAllVariants(buffer, env) {
  const out = { primary: null, variants: [] };
  try {
    if (!env?.AI || typeof env.AI.run !== 'function') return out;
    const CAP = 5 * 1024 * 1024;
    const slice = buffer.byteLength > CAP ? buffer.slice(0, CAP) : buffer;
    const base = await env.AI.run('@cf/openai/whisper', { audio: [...new Uint8Array(slice)] }).catch(()=>null);
    if (base) out.primary = base;
    return out;
  } catch { return out; }
}

/* =========================
   PREVIEW/TRIMMING + FULL OUTPUT
   ========================= */

async function generateAudioOutputs(audioBuffer, profanityResults, planType, previewDuration, fingerprint, env, mime = 'audio/mpeg', originalName = 'track', request = null, resolvedBase = null) {
  // Robust MIME guard
  const extFromName = (String(originalName||'').split('.').pop()||'').toLowerCase();
  const mimeByExt = {
    mp3:'audio/mpeg', wav:'audio/wav', flac:'audio/flac', ogg:'audio/ogg', opus:'audio/opus', webm:'audio/webm', m4a:'audio/mp4', aac:'audio/aac'
  };
  if (!mime || typeof mime !== 'string' || !mime.startsWith('audio/')) {
    mime = mimeByExt[extFromName] || 'audio/mpeg';
  }
  const watermarkId = generateWatermarkId(fingerprint);

  // Absolute base URL for signed links
  const base = (resolvedBase && resolvedBase.trim()) || getWorkerBase(env, request);

 // (A) PREVIEW: always clean and exact length
let previewWork = audioBuffer;
const profanityInWindow = (profanityResults && Array.isArray(profanityResults.timestamps))
  ? profanityResults.timestamps.some(w => Number.isFinite(w.start) && w.start < (previewDuration || 0))
  : false;

if (isLikelyWav(previewWork)) {
  const muted = await processFullAudio(previewWork, profanityResults, planType);
  previewWork = trimWavToSeconds(muted, previewDuration);
} else {
  // If we can't surgically mute (compressed), guarantee cleanliness:
  if (profanityInWindow) {
    previewWork = generateSilentWav(previewDuration);
    mime = 'audio/wav';
  } else {
    // No profanity in preview window → fast approximate trim by bitrate
    const bps = bytesPerSecondFromBitrate(getBitrateForPlan('free'));
    const capBytes = Math.min(previewWork.byteLength, Math.max(1, previewDuration * bps));
    previewWork = previewWork.slice(0, capBytes);
  }
}
const watermarkedPreview = await addAudioWatermark(previewWork, watermarkId);
  

  const extByMime = {
    'audio/mpeg': 'mp3',
    'audio/mpeg3': 'mp3',
    'audio/mp3': 'mp3',
    'audio/wav': 'wav',
    'audio/x-wav': 'wav',
    'audio/flac': 'flac',
    'audio/x-flac': 'flac',
    'audio/ogg': 'ogg',
    'audio/opus': 'opus',
    'audio/webm': 'webm',
    'audio/mp4': 'm4a',
    'audio/aac': 'aac',
    'audio/x-aac': 'aac'
  };
  const guessedExt = extByMime[mime] || (String(originalName).split('.').pop() || 'bin');
  const previewKey = `previews/${generateProcessId()}_preview.${guessedExt}`;

  // hard-cut preview: approximate bytes from plan bitrate
  const bitrateStr = getBitrateForPlan('free');
  const bps = bytesPerSecondFromBitrate(bitrateStr);
  const capBytes = Math.min(audioBuffer.byteLength, Math.max(1, previewDuration * bps));

  try {
  await env.AUDIO_STORAGE.put(previewKey, watermarkedPreview, {
    httpMetadata: { contentType: mime || 'application/octet-stream', cacheControl: 'public, max-age=3600' },
    customMetadata: {
      plan: planType,
      watermarkId,
      fingerprint,
      originalName,
      previewMs: String(previewDuration * 1000),
      previewExact: 'true',
      previewCodec: mime || 'unknown',
      profanity: JSON.stringify(profanityResults && profanityResults.timestamps ? profanityResults.timestamps : [])
    }
  });
} catch (e) {
  console.warn('R2 put preview failed:', e?.message || e);
}

  const { exp: pexp, sig: psig } = await signR2Key(previewKey, env, 30 * 60);
  const previewUrl = psig
    ? `${base}/audio/${encodeURIComponent(previewKey)}?exp=${pexp}&sig=${psig}`
    : `${base}/audio/${encodeURIComponent(previewKey)}`;

 
// (B) FULL clean output (only for non-free)
let fullAudioUrl = null;
if (planType !== 'free') {
  const fullKey = `full/${generateProcessId()}_full.${guessedExt}`;
  if (isLikelyWav(audioBuffer)) {
    const processedAudio = await processFullAudio(audioBuffer, profanityResults, planType);
    const watermarkedFull = await addAudioWatermark(processedAudio, watermarkId);
    try {
      await env.AUDIO_STORAGE.put(fullKey, watermarkedFull, {
        httpMetadata: { contentType: mime || 'application/octet-stream', cacheControl: 'private, max-age=7200' },
        customMetadata: { plan: planType, watermarkId, fingerprint, originalName, transcoded: 'false', clean: 'true' }
      });
    } catch (e) {
      console.warn('R2 put full failed:', e?.message || e);
    }
  } else {
    // Placeholder + queue → external transcoder will clean and overwrite this key
    try {
      await env.AUDIO_STORAGE.put(fullKey, new Uint8Array(), {
        httpMetadata: { contentType: mime || 'application/octet-stream', cacheControl: 'private, max-age=300' },
        customMetadata: { plan: planType, watermarkId, fingerprint, originalName, transcoded: 'pending', clean: 'pending' }
      });
    } catch (e) { console.warn('R2 placeholder full failed:', e?.message || e); }
    if (env.TRANSCODE_QUEUE) {
      const job = {
        kind: 'full',
        r2OutKey: fullKey,
        mime,
        fingerprint,
        originalName,
        profanity: (profanityResults && profanityResults.timestamps) || []
      };
      try { await env.TRANSCODE_QUEUE.send(job); } catch (e) { console.warn('enqueue full transcode failed', e?.message || e); }
    }
  }
  const { exp: fexp, sig: fsig } = await signR2Key(fullKey, env, 60 * 60);
  fullAudioUrl = fsig
    ? `${base}/audio/${encodeURIComponent(fullKey)}?exp=${fexp}&sig=${fsig}`
    : `${base}/audio/${encodeURIComponent(fullKey)}`;
  }

  console.log('Generated URLs', { previewUrl, fullAudioUrl, base });

  return {
    previewUrl,
    fullAudioUrl,
    processedDuration: Math.max(0, Math.min(Math.floor(audioBuffer.byteLength / 44100) - 2, Math.floor((previewDuration || 0)))),
    watermarkId
  };
}

async function processFullAudio(audioBuffer, profanityResults, planType) {
  // Best-effort server-side mute for WAV/PCM only; passthrough for compressed formats.
  try {
    if (!audioBuffer || audioBuffer.byteLength < 44) return audioBuffer;
    const dv = new DataView(audioBuffer);
    // Check RIFF/WAVE header
    if (dv.getUint32(0, false) !== 0x52494646 /* 'RIFF' */ || dv.getUint32(8, false) !== 0x57415645 /* 'WAVE' */) {
      return audioBuffer; // unsupported container
    }
    // Locate 'fmt ' chunk
    let offset = 12; let fmtOffset = -1, fmtSize = 0;
    while (offset + 8 <= dv.byteLength) {
      const id = dv.getUint32(offset, false);
      const sz = dv.getUint32(offset + 4, true);
      if (id === 0x666d7420 /* 'fmt ' */) { fmtOffset = offset + 8; fmtSize = sz; break; }
      offset += 8 + sz + (sz & 1);
    }
    if (fmtOffset < 0) return audioBuffer;
    const audioFormat = dv.getUint16(fmtOffset + 0, true); // 1 = PCM, 3 = IEEE float
    const numChannels = dv.getUint16(fmtOffset + 2, true);
    const sampleRate = dv.getUint32(fmtOffset + 4, true);
    const bitsPerSample = dv.getUint16(fmtOffset + 14, true);
    if (!sampleRate || !numChannels || (audioFormat !== 1 && audioFormat !== 3)) return audioBuffer;

    // Find 'data' chunk
    offset = fmtOffset + fmtSize; let dataOffset = -1, dataSize = 0;
    while (offset + 8 <= dv.byteLength) {
      const id = dv.getUint32(offset, false);
      const sz = dv.getUint32(offset + 4, true);
      if (id === 0x64617461 /* 'data' */) { dataOffset = offset + 8; dataSize = sz; break; }
      offset += 8 + sz + (sz & 1);
    }
    if (dataOffset < 0 || dataOffset + dataSize > dv.byteLength) return audioBuffer;

    const bytesPerSample = bitsPerSample / 8;
    const frameSize = bytesPerSample * numChannels;
    const dataEnd = dataOffset + dataSize;

    const silenceWindow = (startSec, endSec) => {
      const startIdx = Math.max(0, Math.floor(startSec * sampleRate));
      const endIdx = Math.max(startIdx, Math.floor(endSec * sampleRate));
      for (let i = startIdx; i < endIdx; i++) {
        const byteIndex = dataOffset + i * frameSize;
        if (byteIndex + frameSize > dataEnd) break;
        if (audioFormat === 1) {
          // PCM int
          for (let ch = 0; ch < numChannels; ch++) {
            const p = byteIndex + ch * bytesPerSample;
            if (bitsPerSample === 16) dv.setInt16(p, 0, true);
            else if (bitsPerSample === 24) { dv.setInt8(p + 0, 0); dv.setInt8(p + 1, 0); dv.setInt8(p + 2, 0); }
            else if (bitsPerSample === 32) dv.setInt32(p, 0, true);
            else dv.setInt8(p, 0);
          }
        } else if (audioFormat === 3) {
          // IEEE float
          for (let ch = 0; ch < numChannels; ch++) {
            const p = byteIndex + ch * bytesPerSample;
            if (bitsPerSample === 32) dv.setFloat32(p, 0, true);
            else if (bitsPerSample === 64) dv.setFloat64(p, 0, true);
          }
        }
      }
    };

    const windows = (profanityResults && Array.isArray(profanityResults.timestamps)) ? profanityResults.timestamps : [];
    for (const w of windows) {
      if (Number.isFinite(w.start) && Number.isFinite(w.end)) {
        const pad = 0.05; // 50ms padding to avoid clicks
        silenceWindow(Math.max(0, w.start - pad), w.end + pad);
      }
    }
    return audioBuffer;
  } catch (e) {
    console.warn('processFullAudio mute failed:', e?.message || e);
    return audioBuffer;
  }
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

function bytesPerSecondFromBitrate(bitrateStr) {
  // bitrateStr like '128kbps', '256kbps', '320kbps'
  const m = /([0-9]+)\\s*k?b\\s*p\\s*s/i.exec(String(bitrateStr || ''));
  const kbps = m ? parseInt(m[1], 10) : 128;
  // kbps -> bytes/s
  return Math.max(1, Math.floor((kbps * 1000) / 8));
}


function generateSilentWav(seconds, sampleRate = 44100, channels = 2, bitsPerSample = 16) {
  const frames = Math.max(0, Math.floor(seconds * sampleRate));
  const bytesPerSample = bitsPerSample / 8;
  const blockAlign = channels * bytesPerSample;
  const dataSize = frames * blockAlign;
  const buffer = new ArrayBuffer(44 + dataSize);
  const dv = new DataView(buffer);
  // RIFF header
  dv.setUint32(0, 0x52494646, false);
  dv.setUint32(4, 36 + dataSize, true);
  dv.setUint32(8, 0x57415645, false); // 'WAVE'
  // fmt chunk
  dv.setUint32(12, 0x666d7420, false); // 'fmt '
  dv.setUint32(16, 16, true);
  dv.setUint16(20, 1, true);  // PCM
  dv.setUint16(22, channels, true);
  dv.setUint32(24, sampleRate, true);
  dv.setUint32(28, sampleRate * blockAlign, true);
  dv.setUint16(32, blockAlign, true);
  dv.setUint16(34, bitsPerSample, true);
  // data chunk
  dv.setUint32(36, 0x64617461, false); // 'data'
  dv.setUint32(40, dataSize, true);
  // zeros body = silence
  return buffer;
}

function isLikelyWav(buffer) {
  if (!buffer || buffer.byteLength < 12) return false;
  const dv = new DataView(buffer);
  return dv.getUint32(0, false) === 0x52494646 /* 'RIFF' */ &&
         dv.getUint32(8, false) === 0x57415645 /* 'WAVE' */;
}

function trimWavToSeconds(buffer, seconds) {
  try {
    if (!isLikelyWav(buffer)) return buffer;
    const dv = new DataView(buffer);
    let offset = 12, fmtOffset = -1, fmtSize = 0, dataOffset = -1, dataSize = 0;
    while (offset + 8 <= dv.byteLength) {
      const id = dv.getUint32(offset, false);
      const sz = dv.getUint32(offset + 4, true);
      if (id === 0x666d7420) { fmtOffset = offset + 8; fmtSize = sz; }
      if (id === 0x64617461) { dataOffset = offset + 8; dataSize = sz; break; }
      offset += 8 + sz + (sz & 1);
    }
    if (fmtOffset < 0 || dataOffset < 0) return buffer;
    const numChannels = dv.getUint16(fmtOffset + 2, true);
    const sampleRate  = dv.getUint32(fmtOffset + 4, true);
    const bitsPerSample = dv.getUint16(fmtOffset + 14, true);
    if (!sampleRate || !numChannels) return buffer;

    const bytesPerSample = bitsPerSample / 8;
    const frameSize = bytesPerSample * numChannels;
    const framesToKeep = Math.max(0, Math.floor(seconds * sampleRate));
    const bytesToKeep  = Math.min(framesToKeep * frameSize, dataSize);

    const headerSize = dataOffset;
    const out = new Uint8Array(8 + headerSize + bytesToKeep);
    // 'RIFF'
    out[0]=0x52; out[1]=0x49; out[2]=0x46; out[3]=0x46;
    const chunkSize = 4 + (8 + fmtSize) + (8 + bytesToKeep);
    new DataView(out.buffer).setUint32(4, chunkSize, true);
    // 'WAVE'
    out[8]=0x57; out[9]=0x41; out[10]=0x56; out[11]=0x45;
    // copy fmt chunk
    out.set(new Uint8Array(buffer.slice(12, 12 + 8 + fmtSize)), 12);
    let o = 12 + 8 + fmtSize;
    // 'data'
    out[o+0]=0x64; out[o+1]=0x61; out[o+2]=0x74; out[o+3]=0x61;
    new DataView(out.buffer).setUint32(o+4, bytesToKeep, true);
    o += 8;
    out.set(new Uint8Array(buffer, dataOffset, bytesToKeep), o);
    return out.buffer;
  } catch {
    return buffer;
  }
}

/* =========================
   Persistence helpers
   ========================= */

async function validateUserAccess(fingerprint, planType, env, request) {
  if (!env.DB) {
    return { valid: false, reason: 'db_not_configured' };
  }
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
  if (!env.DB) return;
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
  if (!env.DB) return;
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
  if (!env.DB) return;
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
  if (!env.DB) return;
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

  // Hint for frontend where to send the user
  console.log(`Redeem URL: /download-page?session_id=${encodeURIComponent(session.id)}`);
  console.log(`Payment successful: ${type} for ${email || fingerprint}`);
}

async function handleSubscriptionRenewal(invoice, env) {
  console.log(`Subscription renewed: ${invoice.customer}`);
}

async function handleSubscriptionCancelled(subscription, env) {
  if (!env.DB) return;
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
