// FWEA-I Backend — Cloudflare Worker (End-to-End, aligned+consolidated)

// ---------- Imports ----------
import Stripe from 'stripe';

// ---------- Durable Object: ProcessingStateV2 ----------
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

// ---------- Small state helpers (use DO as a lightweight KV) ----------
async function getProcessingStub(env, name = 'global') {
  // FIX: use correct binding name from wrangler.toml
  if (!env?.PROCESSING_STATE_V2) return null;
  try {
    const id = env.PROCESSING_STATE_V2.idFromName(name);
    return env.PROCESSING_STATE_V2.get(id);
  } catch {
    return null;
  }
}
async function putStateKV(env, key, value) {
  const stub = await getProcessingStub(env);
  if (!stub) return false;
  try {
    await stub.fetch('https://state/put', { method: 'PUT', body: JSON.stringify({ key, value }) });
    return true;
  } catch { return false; }
}
async function getStateKV(env, key) {
  const stub = await getProcessingStub(env);
  if (!stub) return null;
  try {
    const res = await stub.fetch('https://state/get?key=' + encodeURIComponent(key));
    const txt = await res.text();
    return txt && txt !== 'null' ? JSON.parse(txt) : null;
  } catch { return null; }
}
function json(body, status = 200, corsHeaders = {}) {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
}

async function callTranscriberWithFile(audioFile, env) {
  if (!env.TRANSCRIBE_ENDPOINT) throw new Error('TRANSCRIBE_ENDPOINT not set');
  const fd = new FormData();
  // most FastAPI handlers expect "file"; keep "audio" too just in case
  fd.set('file', audioFile, audioFile.name || 'audio.mp3');
  fd.set('audio', audioFile, audioFile.name || 'audio.mp3');
  if (env.ASR_MODEL)   fd.set('model',   env.ASR_MODEL);
  if (env.ASR_COMPUTE) fd.set('compute', env.ASR_COMPUTE);

  const resp = await fetch(env.TRANSCRIBE_ENDPOINT.replace(/\/+$/,'') + '/transcribe', {
    method: 'POST',
    body: fd,
    headers: { 'X-API-Token': env.TRANSCRIBE_TOKEN || '' }
  });

  const ct = resp.headers.get('content-type') || '';
  const isJSON = ct.includes('application/json');
  const data = isJSON ? await resp.json().catch(() => ({})) : { text: await resp.text() };

  if (!resp.ok) {
    throw new Error(`Transcriber ${resp.status}: ${data?.detail || data?.error || JSON.stringify(data).slice(0,200)}`);
  }
  // expected: { text, language?, segments?[] }
  if (!data || !data.text) throw new Error('Transcriber returned no text');
  if (!Array.isArray(data.segments)) {
    // best-effort single segment if API doesn’t send segments
    data.segments = [{ start: 0, end: 30, text: String(data.text), confidence: 0.9 }];
  }
  return data;
}

// ---------- Enhanced Profanity Detection ----------
const PROF_CACHE = new Map();
async function getProfanityTrieFor(lang, env) {
  const key = `lists/${lang}.json`;
  if (PROF_CACHE.has(key)) return PROF_CACHE.get(key);
  let words = await env.PROFANITY_LISTS?.get(key, { type: 'json' });
  if (!Array.isArray(words)) words = [];
  const patterns = words
    .map(word => ({ original: word, normalized: normalizeForProfanity(String(word)) }))
    .filter(p => p.normalized.length > 0);
  const pack = { patterns, words };
  PROF_CACHE.set(key, pack);
  return pack;
}
function normalizeForProfanity(s = '') {
  s = s.toLowerCase();
  s = s.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  const rep = {'@':'a','₳':'a','Α':'a','4':'a','0':'o','о':'o','Ο':'o','〇':'o','1':'i','l':'i','|':'i','！':'i','$':'s','5':'s','3':'e','Ɛ':'e','7':'t','Т':'t','¢':'c','ç':'c','ß':'ss'};
  for (const [from,to] of Object.entries(rep)) s = s.replaceAll(from,to);
  s = s.replace(/(.)\1{2,}/g,'$1$1');
  return s.replace(/[^\p{L}\p{N}\s]/gu,' ').replace(/\s+/g,' ').trim();
}
async function matchProfanity(text, lang, env) {
  const pack = await getProfanityTrieFor(lang, env);
  const norm = normalizeForProfanity(text || '');
  if (!pack.patterns || !norm) return [];
  const hits = [];
  for (const p of pack.patterns) {
    if (!p.normalized) continue;
    const re = new RegExp(`\\b${escapeRegex(p.normalized)}\\b`, 'gi');
    let m; while ((m = re.exec(norm)) !== null) {
      hits.push({ word: p.original, start: m.index, end: m.index + m[0].length, confidence: 0.9 });
    }
  }
  return dedupeOverlaps(hits);
}
function escapeRegex(s){return s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}
function dedupeOverlaps(arr){arr.sort((a,b)=>a.start-b.start||b.end-a.end);const out=[];let last=-1;for(const m of arr){if(m.start>=last){out.push(m);last=m.end}}return out}
function normalizeLangs(langs=[]){const map={english:'en',spanish:'es',french:'fr',german:'de',portuguese:'pt',italian:'it',russian:'ru',chinese:'zh',arabic:'ar',japanese:'ja',korean:'ko',hindi:'hi',turkish:'tr',indonesian:'id',swahili:'sw'};const out=new Set();for(const l of langs){const k=String(l||'').toLowerCase();out.add(map[k]||k.slice(0,2))}return[...out]}

// ---------- Main Worker ----------

export default {
  async fetch(request, env) {
    // CORS
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
    if (allowOrigin !== workerOrigin && isAllowed) corsHeaders['Access-Control-Allow-Credentials'] = 'true';
    if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders });


    const url = new URL(request.url);



    // Audio streaming
    if (url.pathname.startsWith('/audio/')) return handleAudioDownload(request, env, corsHeaders);

    try {
      switch (url.pathname) {
        case '/transcribe':               return await handleTranscribe(request, env, corsHeaders);
        case '/process-audio':            return await handleAudioProcessing(request, env, corsHeaders);
        case '/create-payment':           return await handlePaymentCreation(request, env, corsHeaders);
        case '/webhook':                  return await handleStripeWebhook(request, env, corsHeaders);
        case '/activate-access':          return await handleAccessActivation(request, env, corsHeaders);
        case '/validate-subscription':    return await handleSubscriptionValidation(request, env, corsHeaders);
        case '/send-verification':        return await handleSendVerification(request, env, corsHeaders);
        case '/verify-email-code':        return await handleEmailVerification(request, env, corsHeaders);
        case '/track-event':              return await handleEventTracking(request, env, corsHeaders);
        case '/redeem-download':          return await handleRedeemDownload(request, env, corsHeaders);
        case '/download-page':            return await handleDownloadPage(request, env, corsHeaders);
        case '/health':
          return json({
            status: 'healthy',
            version: '2.1.1',
            timestamp: Date.now(),
            services: {
              r2: Boolean(env.AUDIO_STORAGE),
              database: Boolean(env.DB),
              ai: Boolean(env.AI),
              profanity_lists: Boolean(env.PROFANITY_LISTS),
              stripe: Boolean(env.STRIPE_SECRET_KEY),
              transcriber_cfg: Boolean(env.TRANSCRIBE_ENDPOINT)
            }
          }, 200, corsHeaders);
        default:
          return new Response('Not Found', { status: 404, headers: corsHeaders });
      }
    } catch (error) {
      console.error('Worker Error:', error);
      return json({ error: 'Internal Server Error', details: error.message, requestId: crypto.randomUUID() }, 500, corsHeaders);
    }
  },
};

// ---------- Stripe IDs ----------
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

// ---------- /transcribe (proxy to RunPod FastAPI) ----------
async function handleTranscribe(request, env, corsHeaders) {
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405, corsHeaders);
  if (!env.TRANSCRIBE_ENDPOINT) return json({ error: 'TRANSCRIBE_ENDPOINT not configured' }, 500, corsHeaders);

  try {
    const ct = request.headers.get('content-type') || '';
    let resp;

    // Pass through multipart directly (file upload)
    if (ct.includes('multipart/form-data')) {
      const fd = await request.formData();
      // (optional) allow overrides via query/form: model / compute
      if (!fd.get('model') && env.ASR_MODEL) fd.set('model', env.ASR_MODEL);
      if (!fd.get('compute') && env.ASR_COMPUTE) fd.set('compute', env.ASR_COMPUTE);

      resp = await fetch(env.TRANSCRIBE_ENDPOINT.replace(/\/+$/,'') + '/transcribe', {
        method: 'POST',
        body: fd,
        headers: {
          // Forward auth token in a simple custom header (match FastAPI expectation)
          'X-API-Token': env.TRANSCRIBE_TOKEN || '',
        }
      });
    } else {
      // JSON body with { url: "https://..." } or similar
      const body = await request.json().catch(() => ({}));
      resp = await fetch(env.TRANSCRIBE_ENDPOINT.replace(/\/+$/,'') + '/transcribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Token': env.TRANSCRIBE_TOKEN || '',
        },
        body: JSON.stringify(body),
      });
    }

    // Bubble up response
    const outCT = resp.headers.get('content-type') || 'application/json';
    const buf = await resp.arrayBuffer();
    return new Response(buf, { status: resp.status, headers: { ...corsHeaders, 'Content-Type': outCT } });
  } catch (e) {
    console.error('Transcribe proxy error:', e);
    return json({ error: 'Transcription proxy failed', details: e.message }, 502, corsHeaders);
  }
}

// ---------- /process-audio (route handler) ----------
async function handleAudioProcessing(request, env, corsHeaders) {
  if (request.method !== 'POST') {
    return json({ error: 'Method not allowed' }, 405, corsHeaders);
  }

  try {
    const formData   = await request.formData();
    const audioFile  = formData.get('audio') || formData.get('file');
    const fingerprint = formData.get('fingerprint') || 'anonymous';
    const planType    = formData.get('planType') || 'free';

    const admin = (request.headers.get('X-FWEA-Admin') || '') === (env.ADMIN_API_TOKEN || '');
    const effectivePlan = admin ? 'studio_elite' : planType;

    if (!env.AUDIO_STORAGE) {
      return json({ success:false, error:'Storage not configured', hint:'Bind R2 bucket' }, 503, corsHeaders);
    }
    if (!audioFile) {
      return json({ success:false, error:'No audio file provided', hint:'Send FormData field "audio" (or "file")' }, 400, corsHeaders);
    }

    const maxSizes = {
      free: 50*1024*1024, single_track: 100*1024*1024, day_pass: 100*1024*1024,
      dj_pro: 200*1024*1024, studio_elite: 500*1024*1024
    };
    const maxSize = maxSizes[effectivePlan] || maxSizes.free;
    if (audioFile.size > maxSize) {
      return json({ success:false, error:'File too large', maxSize, currentSize: audioFile.size, upgradeRequired: effectivePlan==='free' }, 413, corsHeaders);
    }

    const processingResult = await processAudioWithAI(audioFile, effectivePlan, fingerprint, env, request);

    try {
      await storeProcessingResult(fingerprint, processingResult, env);
      await updateUsageStats(fingerprint, planType, audioFile.size, env);
    } catch {}

    return json({ success: true, ...processingResult }, 200, corsHeaders);
  } catch (error) {
    console.error('Audio processing error:', error);
    return json({ success:false, error:'Audio processing failed', details: error.message }, 500, corsHeaders);
  }
}

  


// ---------- /process-audio ----------
async function processAudioWithAI(audioFile, planType, fingerprint, env, request) {
  try {
    const audioBuffer = await audioFile.arrayBuffer();

    // ✅ CALL YOUR TRANSCRIBER
    const transcription = await callTranscriberWithFile(audioFile, env);
    // transcription: { text, language?, segments:[{start,end,text,confidence}] }

    const detectedLanguages = extractLanguagesFromTranscription(transcription.text);
    const normalizedLanguages = normalizeLangs(detectedLanguages);
    const profanityResults = await findProfanityTimestamps(transcription, normalizedLanguages, env);

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
    return { success:false, error:'AI processing failed', details:error.message };
  }
}
// ---------- /create-payment ----------
async function handlePaymentCreation(request, env, corsHeaders) {
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405, corsHeaders);

  try {
    const { priceId, type, fileName, email, fingerprint } = await request.json();

    if (!env.STRIPE_SECRET_KEY) return json({ error:'Stripe not configured' }, 500, corsHeaders);
    if (!env.FRONTEND_URL)      return json({ error:'Frontend URL not configured' }, 500, corsHeaders);

    const validPriceIds = Object.values(STRIPE_PRICE_IDS);
    if (!validPriceIds.includes(priceId)) return json({ error:'Invalid price ID' }, 400, corsHeaders);
    if (!['single_track','day_pass','dj_pro','studio_elite'].includes(type)) return json({ error:'Invalid plan type' }, 400, corsHeaders);

    const stripe = new Stripe(env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20', httpClient: Stripe.createFetchHttpClient() });
    const isSubscription = (type === 'dj_pro' || type === 'studio_elite');

    const session = await stripe.checkout.sessions.create({
      mode: isSubscription ? 'subscription' : 'payment',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${env.FRONTEND_URL.replace(/\/+$/, '')}/success?session_id=\${CHECKOUT_SESSION_ID}`,
      cancel_url: `${env.FRONTEND_URL.replace(/\/+$/, '')}/cancel`,
      customer_email: email || undefined,
      allow_promotion_codes: true,
      automatic_tax: { enabled: true },
      customer_creation: 'if_required',
      payment_method_types: ['card', 'link'],
      metadata: {
        type: type || '',
        fileName: fileName || '',
        fingerprint: fingerprint || 'unknown',
        processingType: 'audio_cleaning',
        ts: String(Date.now()),
      },
    });

    if (env.DB) await storePaymentIntent(session.id, type, priceId, fingerprint, env);

    return json({ success: true, sessionId: session.id, url: session.url }, 200, corsHeaders);
  } catch (error) {
    console.error('Payment creation error:', error);
    return json({ error:'Payment creation failed', details:error.message }, 500, corsHeaders);
  }
}


    

// ---------- Lang / Profanity helpers ----------
function extractLanguagesFromTranscription(text=''){const pats={Spanish:/[ñáéíóúü¿¡]/i,French:/[àâäéèêëïîôùûüÿç]/i,German:/[äöüß]/i};const out=['English'];for(const [lang,re] of Object.entries(pats)){if(re.test(text)) out.push(lang)}return[...new Set(out)]}
async function findProfanityTimestamps(transcription, languages, env) {
  const timestamps = [];
  if (!transcription?.segments?.length) return { timestamps };
  const langCodes = normalizeLangs(languages);
  for (const segment of transcription.segments) {
    for (const langCode of langCodes) {
      const matches = await matchProfanity(segment.text || '', langCode, env);
      for (const match of matches) {
        timestamps.push({ start: segment.start || 0, end: segment.end || 30, word: match.word, language: langCode, confidence: match.confidence || 0.8 });
      }
    }
  }
  return { timestamps };
}

// ---------- R2 output & signing ----------
async function generateAudioOutputs(audioBuffer, profanityResults, planType, previewDuration, fingerprint, env, mimeType, originalName, request) {
  const processId = generateProcessId();
  const base = getWorkerBase(env, request);

  // preview
  const previewKey = `previews/${processId}_preview.mp3`;
  const approxBytes = Math.min(audioBuffer.byteLength, previewDuration * 44100 * 2);
  const previewSlice = audioBuffer.slice(0, approxBytes);
  try {
    await env.AUDIO_STORAGE.put(previewKey, previewSlice, {
      httpMetadata: { contentType: 'audio/mpeg' },
      customMetadata: { plan: planType, fingerprint, originalName, previewMs: String(previewDuration * 1000) }
    });
  } catch (e) { console.warn('R2 put preview failed:', e?.message || e); }

  const { exp: pexp, sig: psig } = await signR2Key(previewKey, env, 15 * 60);
  const previewUrl = psig ? `${base}/audio/${encodeURIComponent(previewKey)}?exp=${pexp}&sig=${psig}` : `${base}/audio/${encodeURIComponent(previewKey)}`;

  // full (paid)
  let fullAudioUrl = null; let fullKey = null;
  if (planType !== 'free') {
    fullKey = `full/${processId}_full.mp3`;
    try {
      await env.AUDIO_STORAGE.put(fullKey, audioBuffer, {
        httpMetadata: { contentType: 'audio/mpeg' },
        customMetadata: { plan: planType, fingerprint, originalName }
      });
    } catch (e) { console.warn('R2 put full failed:', e?.message || e); }

    const { exp: fexp, sig: fsig } = await signR2Key(fullKey, env, 60 * 60);
    fullAudioUrl = fsig ? `${base}/audio/${encodeURIComponent(fullKey)}?exp=${fexp}&sig=${fsig}` : `${base}/audio/${encodeURIComponent(fullKey)}`;
  }

  // Remember last keys for this fingerprint
  try {
    await putStateKV(env, `latest:${fingerprint}`, { processId, previewKey, fullKey, originalName, planType });
  } catch {}

  return { previewUrl, fullAudioUrl, watermarkId: generateWatermarkId(fingerprint) };
}

function getPreviewDuration(plan){const d={free:30,single_track:45,day_pass:45,dj_pro:45,studio_elite:60};return d[plan]||30}
function getQualityForPlan(plan){const q={free:'Standard',single_track:'HD',day_pass:'HD',dj_pro:'HD+',studio_elite:'Studio Grade'};return q[plan]||'Standard'}
function generateProcessId(){return Date.now().toString(36)+Math.random().toString(36).substring(2)}
function generateWatermarkId(fp){return fp+'_'+Date.now().toString(36)}
function isAdminRequest(request, env){try{const hdr=(request.headers.get('X-FWEA-Admin')||'').trim();const tok=(env.ADMIN_API_TOKEN||'').trim();if(!hdr||!tok)return false;return hdr===tok}catch{return false}}

function getWorkerBase(env, request) {
  try {
    const origin = new URL(request.url).origin;
    const u = new URL(origin);
    return 'https://' + u.host;
  } catch {
    return '';
  }
}

// HMAC signing for R2 keys
async function hmacSHA256(message, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  const b64 = btoa(String.fromCharCode(...new Uint8Array(sigBuf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  return b64;
}
async function signR2Key(key, env, ttlSeconds = 15 * 60) {
  if (!env.AUDIO_URL_SECRET) return { exp: 0, sig: '' };
  const exp = Math.floor(Date.now()/1000) + ttlSeconds;
  const msg = `${key}:${exp}`;
  const sig = await hmacSHA256(msg, env.AUDIO_URL_SECRET);
  return { exp, sig };
}
async function verifySignedUrl(key, exp, sig, env) {
  if (!env.AUDIO_URL_SECRET) return true;
  if (!exp || !sig) return false;
  const now = Math.floor(Date.now()/1000);
  if (Number(exp) <= now) return false;
  const msg = `${key}:${exp}`;
  const expected = await hmacSHA256(msg, env.AUDIO_URL_SECRET);
  return expected === sig;
}

// ---------- Audio download ----------
async function handleAudioDownload(request, env, corsHeaders) {
  const url = new URL(request.url);
  const key = decodeURIComponent(url.pathname.replace(/^\/audio\//, ''));
  if (!key) return new Response('Bad Request', { status: 400, headers: corsHeaders });
  if (!env.AUDIO_STORAGE) return json({ error:'Storage not configured' }, 404, corsHeaders);

  const exp = url.searchParams.get('exp'); const sig = url.searchParams.get('sig');
  const ok = await verifySignedUrl(key, exp, sig, env);
  if (!ok) return json({ error:'Invalid or expired link' }, 403, corsHeaders);

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

// ---------- Stripe webhook (ack only; add DB logic if needed) ----------
async function handleStripeWebhook(request, env, corsHeaders) {
  if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405, headers: corsHeaders });
  const sig = request.headers.get('Stripe-Signature');
  const secret = env.STRIPE_WEBHOOK_SECRET;
  if (!secret) return new Response('OK', { status: 200, headers: corsHeaders });
  try {
    const payload = await request.text();
    console.log('stripe webhook len', payload.length, 'sig?', !!sig);
    return new Response('OK', { status: 200, headers: corsHeaders });
  } catch (e) {
    console.error('webhook error', e);
    return new Response('Bad payload', { status: 400, headers: corsHeaders });
  }
}

// ---------- /activate-access ----------
async function handleAccessActivation(request, env, corsHeaders) {
  try {
    const { fingerprint, sessionId } = await request.json();
    if (!fingerprint || !sessionId) return json({ success:false, error:'Missing fingerprint or sessionId' }, 400, corsHeaders);
    if (!env.STRIPE_SECRET_KEY) return json({ success:false, error:'Stripe not configured' }, 500, corsHeaders);

    const stripe = new Stripe(env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20', httpClient: Stripe.createFetchHttpClient() });
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    const paid = (session.payment_status === 'paid') || (session.status === 'complete');
    if (!paid) return json({ success:false, error:'Payment not completed' }, 402, corsHeaders);

    const rec = await getStateKV(env, `latest:${fingerprint}`);
    if (!rec || !rec.fullKey) return json({ success:true, message:'Payment verified, awaiting full audio generation.' }, 200, corsHeaders);

    const { exp, sig } = await signR2Key(rec.fullKey, env, 60 * 60);
    const base = getWorkerBase(env, request);
    const fullUrl = sig ? `${base}/audio/${encodeURIComponent(rec.fullKey)}?exp=${exp}&sig=${sig}` : `${base}/audio/${encodeURIComponent(rec.fullKey)}`;
    return json({ success:true, downloadUrl: fullUrl }, 200, corsHeaders);
  } catch (e) {
    console.error('activate error', e);
    return json({ success:false, error:'Activation failed', details:e.message }, 500, corsHeaders);
  }
}

// ---------- Misc smaller endpoints ----------
async function handleSubscriptionValidation(request, env, corsHeaders) { return json({ valid: true }, 200, corsHeaders); }
async function handleSendVerification(request, env, corsHeaders)     { return json({ success: true }, 200, corsHeaders); }
async function handleEmailVerification(request, env, corsHeaders)    { return json({ valid: true }, 200, corsHeaders); }
async function handleEventTracking(request, env, corsHeaders)        { return json({ success: true }, 200, corsHeaders); }

async function handleRedeemDownload(request, env, corsHeaders) {
  const url = new URL(request.url);
  const fingerprint = url.searchParams.get('fingerprint') || '';
  if (!fingerprint) return json({ error: 'Missing fingerprint' }, 400, corsHeaders);
  const rec = await getStateKV(env, `latest:${fingerprint}`);
  if (!rec?.fullKey) return json({ error: 'No full audio available yet' }, 404, corsHeaders);
  const { exp, sig } = await signR2Key(rec.fullKey, env, 60 * 60);
  const base = getWorkerBase(env, request);
  const fullUrl = sig ? `${base}/audio/${encodeURIComponent(rec.fullKey)}?exp=${exp}&sig=${sig}` : `${base}/audio/${encodeURIComponent(rec.fullKey)}`;
  return json({ downloadUrl: fullUrl }, 200, corsHeaders);
}

async function handleDownloadPage(request, env, corsHeaders) {
  const url = new URL(request.url);
  const sessionId = url.searchParams.get('session_id') || '';
  const fingerprint = url.searchParams.get('fingerprint') || '';
  const rec = fingerprint ? await getStateKV(env, `latest:${fingerprint}`) : null;
  let link = '';
  if (rec?.fullKey) {
    const { exp, sig } = await signR2Key(rec.fullKey, env, 60 * 60);
    const base = getWorkerBase(env, request);
    link = sig ? `${base}/audio/${encodeURIComponent(rec.fullKey)}?exp=${exp}&sig=${sig}` : `${base}/audio/${encodeURIComponent(rec.fullKey)}`;
  }
  const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"/><title>FWEA-I Download</title></head>
  <body style="font-family:system-ui,-apple-system,Segoe UI,Inter,sans-serif;background:#0a0a0f;color:#e5e7eb;display:grid;place-items:center;min-height:100vh;">
    <main style="text-align:center;max-width:720px;padding:24px;">
      <h1 style="margin:0 0 8px;">Payment Successful</h1>
      <p style="opacity:.8;">Session: ${sessionId || 'N/A'}</p>
      ${link ? `<a href="${link}" style="display:inline-block;margin-top:16px;padding:12px 18px;border-radius:999px;background:#00f5ff;color:#0f172a;font-weight:700;text-decoration:none;">Download Full Audio</a>`
             : `<p style="margin-top:16px;opacity:.8;">Your audio is still processing. Refresh later for the download link.</p>`}
    </main>
  </body></html>`;
  return new Response(html, { status: 200, headers: { ...corsHeaders, 'Content-Type': 'text/html; charset=utf-8' } });
}

// ---------- Stubs / Notes ----------
async function storeProcessingResult(){/* optional: your DB */}
async function updateUsageStats(){/* optional: your DB */}
async function storePaymentIntent(){/* optional: your DB */}
