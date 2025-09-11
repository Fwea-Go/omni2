// worker.js
// FWEA-I Backend — Cloudflare Worker (modules syntax, end-to-end)

// ---------- Imports (Edge-compatible Stripe) ----------
import Stripe from "stripe";

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

    if (method === "GET") {
      const key = url.searchParams.get("key");
      if (!key) return new Response("Missing key", { status: 400 });
      if (this.cache.has(key)) return new Response(this.cache.get(key) ?? "null");
      const v = await this.state.storage.get(key);
      if (v != null) this.cache.set(key, JSON.stringify(v));
      return new Response(v != null ? JSON.stringify(v) : "null");
    }

    if (method === "PUT") {
      const { key, value } = await request.json().catch(() => ({}));
      if (!key) return new Response("Missing key", { status: 400 });
      await this.state.storage.put(key, value);
      this.cache.set(key, JSON.stringify(value));
      return new Response("OK");
    }

    if (method === "DELETE") {
      const key = url.searchParams.get("key");
      if (!key) return new Response("Missing key", { status: 400 });
      await this.state.storage.delete(key);
      this.cache.delete(key);
      return new Response("OK");
    }

    return new Response("Method Not Allowed", { status: 405 });
  }
}

// ---------- Small helpers ----------
function j(body, status = 200, cors = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...cors }
  });
}
function escapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function dedupeOverlaps(arr){arr.sort((a,b)=>a.start-b.start||b.end-a.end);const out=[];let last=-1;for(const m of arr){if(m.start>=last){out.push(m);last=m.end}}return out}
function normalizeLangs(langs=[]){const map={english:"en",spanish:"es",french:"fr",german:"de",portuguese:"pt",italian:"it",russian:"ru",chinese:"zh",arabic:"ar",japanese:"ja",korean:"ko",hindi:"hi",turkish:"tr",indonesian:"id",swahili:"sw"};const out=new Set();for(const l of langs){const k=String(l||"").toLowerCase();out.add(map[k]||k.slice(0,2))}return[...out]}
function generateProcessId(){return Date.now().toString(36)+Math.random().toString(36).slice(2)}
function generateWatermarkId(fp){return `${fp}_${Date.now().toString(36)}`}

// DO access
async function getProcessingStub(env, name = "global") {
  if (!env?.PROCESSING_STATE_V2) return null;
  try { const id = env.PROCESSING_STATE_V2.idFromName(name); return env.PROCESSING_STATE_V2.get(id); }
  catch { return null; }
}
async function putStateKV(env, key, value) {
  const stub = await getProcessingStub(env); if (!stub) return false;
  try {
    await stub.fetch("https://state/put", { method: "PUT", body: JSON.stringify({ key, value }) });
    return true;
  } catch { return false; }
}
async function getStateKV(env, key) {
  const stub = await getProcessingStub(env); if (!stub) return null;
  try {
    const res = await stub.fetch(`https://state/get?key=${encodeURIComponent(key)}`);
    const txt = await res.text();
    return txt && txt !== "null" ? JSON.parse(txt) : null;
  } catch { return null; }
}

// Signed URLs for R2 keys
async function hmacSHA256(message, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  const b64 = btoa(String.fromCharCode(...new Uint8Array(sigBuf))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
  return b64;
}
async function signR2Key(key, env, ttlSeconds = 15 * 60) {
  if (!env.AUDIO_URL_SECRET) return { exp: 0, sig: "" };
  const exp = Math.floor(Date.now()/1000) + ttlSeconds;
  const sig = await hmacSHA256(`${key}:${exp}`, env.AUDIO_URL_SECRET);
  return { exp, sig };
}
async function verifySignedUrl(key, exp, sig, env) {
  if (!env.AUDIO_URL_SECRET) return true; // unsigned allowed if secret not set
  if (!exp || !sig) return false;
  if (Number(exp) <= Math.floor(Date.now()/1000)) return false;
  const expected = await hmacSHA256(`${key}:${exp}`, env.AUDIO_URL_SECRET);
  return expected === sig;
}

function getWorkerBase(env, request) {
  try { return new URL(request.url).origin; } catch { return ""; }
}
function getPreviewDuration(plan){const d={free:30,single_track:45,day_pass:45,dj_pro:45,studio_elite:60};return d[plan]||30}
function getQualityForPlan(plan){const q={free:"Standard",single_track:"HD",day_pass:"HD",dj_pro:"HD+",studio_elite:"Studio Grade"};return q[plan]||"Standard"}

// ---------- Profanity matching (KV-backed wordlists) ----------
const PROF_CACHE = new Map();
function normalizeForProfanity(s=""){
  s = s.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g,"");
  const rep = {'@':'a','4':'a','0':'o','1':'i','l':'i','|':'i','$':'s','5':'s','3':'e','7':'t','¢':'c','ß':'ss'};
  for (const [from,to] of Object.entries(rep)) s = s.replaceAll(from,to);
  s = s.replace(/(.)\1{2,}/g,'$1$1').replace(/[^\p{L}\p{N}\s]/gu,' ').replace(/\s+/g,' ').trim();
  return s;
}
async function getProfanityTrieFor(lang, env) {
  const key = `lists/${lang}.json`;
  if (PROF_CACHE.has(key)) return PROF_CACHE.get(key);
  let words = await env.PROFANITY_LISTS?.get(key, { type: "json" });
  if (!Array.isArray(words)) words = [];
  const patterns = words.map(w => ({ original: w, normalized: normalizeForProfanity(String(w)) })).filter(p => p.normalized.length>0);
  const pack = { patterns, words };
  PROF_CACHE.set(key, pack);
  return pack;
}
async function matchProfanity(text, lang, env) {
  const pack = await getProfanityTrieFor(lang, env);
  const norm = normalizeForProfanity(text || "");
  if (!pack.patterns || !norm) return [];
  const hits = [];
  for (const p of pack.patterns) {
    const re = new RegExp(`\\b${escapeRegex(p.normalized)}\\b`, "gi");
    let m; while ((m = re.exec(norm)) !== null) hits.push({ word: p.original, start: m.index, end: m.index+m[0].length, confidence: 0.9 });
  }
  return dedupeOverlaps(hits);
}

// ---------- Transcriber proxy/help ----------
async function callTranscriberWithFile(audioFile, env) {
  if (!env.TRANSCRIBE_ENDPOINT) throw new Error("TRANSCRIBE_ENDPOINT not set");
  const fd = new FormData();
  fd.set("file", audioFile, audioFile.name || "audio.mp3");
  fd.set("audio", audioFile, audioFile.name || "audio.mp3");
  if (env.ASR_MODEL)   fd.set("model", env.ASR_MODEL);
  if (env.ASR_COMPUTE) fd.set("compute", env.ASR_COMPUTE);

  const resp = await fetch(env.TRANSCRIBE_ENDPOINT.replace(/\/+$/,"") + "/transcribe", {
    method: "POST",
    body: fd,
    headers: { "X-API-Token": env.TRANSCRIBE_TOKEN || "" }
  });

  const ct = resp.headers.get("content-type") || "";
  const isJSON = ct.includes("application/json");
  const data = isJSON ? await resp.json().catch(() => ({})) : { text: await resp.text() };

  if (!resp.ok) throw new Error(`Transcriber ${resp.status}: ${data?.detail || data?.error || "error"}`);
  if (!data?.text) throw new Error("Transcriber returned no text");
  if (!Array.isArray(data.segments)) data.segments = [{ start: 0, end: 30, text: String(data.text), confidence: 0.9 }];
  return data;
}

// ---------- Routing entry ----------
export default {
  async fetch(request, env, ctx) {
    try {
      return await route(request, env, ctx);
    } catch (err) {
      console.error("Worker fatal error:", err);
      return j({ error: "Internal Server Error", details: String(err?.message || err) }, 500);
    }
  }
};

async function route(request, env, ctx) {
  const url = new URL(request.url);

  // CORS allow-list
  const allowList = [
    env.FRONTEND_URL && env.FRONTEND_URL.replace(/\/+$/, ''),
    env.WIX_SITE_URL && env.WIX_SITE_URL.replace(/\/+$/, ''),
    'https://omni2-8d2.pages.dev',
    'https://fwea-i.com',
    'https://www.fwea-i.com',
    'http://localhost:3000',
    'http://127.0.0.1:3000',
  ].filter(Boolean);

  const reqOrigin   = request.headers.get('Origin') || '';
  const allowOrigin = allowList.includes(reqOrigin) ? reqOrigin : '';
  const cors = {
    'Access-Control-Allow-Origin': allowOrigin || '*',
    'Vary': 'Origin',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers':
      'Content-Type, Authorization, X-Stripe-Signature, Range, X-FWEA-Admin, X-Requested-With',
    'Access-Control-Expose-Headers':
      'Content-Range, Accept-Ranges, Content-Length, ETag, Content-Type, Last-Modified',
    'Access-Control-Max-Age': '86400',
  };

  // Preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }

  // Signed audio streaming
  if (url.pathname.startsWith('/audio/')) {
    return handleAudioDownload(request, env, cors);
  }

  // Routes
  try {
    switch (url.pathname) {
      case '/transcribe':            return await handleTranscribe(request, env, cors);
      case '/process-audio':         return await handleAudioProcessing(request, env, cors);
      case '/create-payment':        return await handlePaymentCreation(request, env, cors);
      case '/webhook':               return await handleStripeWebhook(request, env, cors);
      case '/activate-access':       return await handleAccessActivation(request, env, cors);
      case '/validate-subscription': return j({ valid: true }, 200, cors);
      case '/send-verification':     return j({ success: true }, 200, cors);
      case '/verify-email-code':     return j({ valid: true }, 200, cors);
      case '/track-event':           return j({ success: true }, 200, cors);
      case '/redeem-download':       return await handleRedeemDownload(request, env, cors);
      case '/download-page':         return await handleDownloadPage(request, env, cors);
      case '/debug-env':             return j({ ok: true, envKeys: Object.keys(env) }, 200, cors);
      case '/health':
        return j({
          status: 'healthy',
          version: '2.1.1',
          timestamp: Date.now(),
          services: {
            r2: Boolean(env.AUDIO_STORAGE),
            database: Boolean(env.DB),
            ai: Boolean(env.AI),
            profanity_lists: Boolean(env.PROFANITY_LISTS),
            stripe: Boolean(env.STRIPE_SECRET_KEY),
            transcriber_cfg: Boolean(env.TRANSCRIBE_ENDPOINT),
          },
        }, 200, cors);
      default:
        return new Response('Not Found', { status: 404, headers: cors });
    }
  } catch (err) {
    console.error('Route error:', err);
    return j({ error: 'Internal Server Error', details: String(err?.message || err) }, 500, cors);
  }
}


// ---------- Handlers ----------
async function handleTranscribe(request, env, cors) {
  if (request.method !== "POST") return j({ error: "Method not allowed" }, 405, cors);
  if (!env.TRANSCRIBE_ENDPOINT)     return j({ error: "TRANSCRIBE_ENDPOINT not configured" }, 500, cors);

  try {
    const ct = request.headers.get("content-type") || "";
    let resp;

    if (ct.includes("multipart/form-data")) {
      const fd = await request.formData();
      if (!fd.get("model") && env.ASR_MODEL) fd.set("model", env.ASR_MODEL);
      if (!fd.get("compute") && env.ASR_COMPUTE) fd.set("compute", env.ASR_COMPUTE);

      resp = await fetch(env.TRANSCRIBE_ENDPOINT.replace(/\/+$/,"") + "/transcribe", {
        method: "POST",
        body: fd,
        headers: { "X-API-Token": env.TRANSCRIBE_TOKEN || "" }
      });
    } else {
      const body = await request.json().catch(() => ({}));
      resp = await fetch(env.TRANSCRIBE_ENDPOINT.replace(/\/+$/,"") + "/transcribe", {
        method: "POST",
        headers: { "content-type": "application/json", "X-API-Token": env.TRANSCRIBE_TOKEN || "" },
        body: JSON.stringify(body)
      });
    }

    const outCT = resp.headers.get("content-type") || "application/json";
    const buf = await resp.arrayBuffer();
    return new Response(buf, { status: resp.status, headers: { ...cors, "content-type": outCT } });
  } catch (e) {
    console.error("Transcribe proxy error:", e);
    return j({ error: "Transcription proxy failed", details: e.message }, 502, cors);
  }
}

async function handleAudioProcessing(request, env, cors) {
  if (request.method !== "POST") return j({ error: "Method not allowed" }, 405, cors);

  try {
    const fd          = await request.formData();
    const audioFile   = fd.get("audio") || fd.get("file");
    const fingerprint = fd.get("fingerprint") || "anonymous";
    const planType    = fd.get("planType") || "free";

    const admin = (request.headers.get("X-FWEA-Admin") || "") === (env.ADMIN_API_TOKEN || "");
    const effectivePlan = admin ? "studio_elite" : planType;

    if (!env.AUDIO_STORAGE) return j({ success:false, error:"Storage not configured", hint:"Bind R2 bucket" }, 503, cors);
    if (!audioFile)         return j({ success:false, error:"No audio file provided", hint:'Send FormData "audio" (or "file")' }, 400, cors);

    const maxSizes = { free: 50*1024*1024, single_track: 100*1024*1024, day_pass: 100*1024*1024, dj_pro: 200*1024*1024, studio_elite: 500*1024*1024 };
    if (audioFile.size > (maxSizes[effectivePlan] || maxSizes.free)) {
      return j({ success:false, error:"File too large", maxSize: maxSizes[effectivePlan] || maxSizes.free, currentSize: audioFile.size }, 413, cors);
    }

    const res = await processAudioWithAI(audioFile, effectivePlan, fingerprint, env, request);

    try {
      await putStateKV(env, `latest:${fingerprint}`, res._persist || {});
    } catch {}

    return j({ success: true, ...res.public }, 200, cors);
  } catch (e) {
    console.error("Audio processing error:", e);
    return j({ success:false, error:"Audio processing failed", details:e.message }, 500, cors);
  }
}

async function processAudioWithAI(audioFile, planType, fingerprint, env, request) {
  const audioBuffer = await audioFile.arrayBuffer();

  // 1) Transcribe
  const transcription = await callTranscriberWithFile(audioFile, env);

  // 2) Language guess
  const detectedLanguages = extractLanguagesFromTranscription(transcription.text);
  const normLangs = normalizeLangs(detectedLanguages);

  // 3) Profanity timestamps
  const timestamps = [];
  for (const seg of transcription.segments || []) {
    for (const lc of normLangs) {
      const matches = await matchProfanity(seg.text || "", lc, env);
      for (const m of matches) timestamps.push({ start: seg.start || 0, end: seg.end || 30, word: m.word, language: lc, confidence: m.confidence || 0.8 });
    }
  }

  // 4) Store preview/full to R2 and sign
  const out = await generateAudioOutputs(audioBuffer, { timestamps }, planType, getPreviewDuration(planType), fingerprint, env, audioFile.type, audioFile.name, request);

  const publicPayload = {
    previewUrl: out.previewUrl,
    fullAudioUrl: out.fullAudioUrl,
    languages: normLangs,
    profanityFound: timestamps.length,
    transcription: planType !== "free" ? transcription : null,
    quality: getQualityForPlan(planType),
    watermarkId: out.watermarkId
  };

  const persist = { processId: out.processId, previewKey: out.previewKey, fullKey: out.fullKey, originalName: audioFile.name, planType };

  return { public: publicPayload, _persist: persist };
}

async function generateAudioOutputs(audioBuffer, profanityResults, planType, previewDuration, fingerprint, env, mimeType, originalName, request) {
  const processId = generateProcessId();
  const base = getWorkerBase(env, request);

  // PREVIEW
  const previewKey = `previews/${processId}_preview.mp3`;
  const approxBytes = Math.min(audioBuffer.byteLength, previewDuration * 44100 * 2); // crude
  const previewSlice = audioBuffer.slice(0, approxBytes);
  try {
    await env.AUDIO_STORAGE.put(previewKey, previewSlice, {
      httpMetadata: { contentType: "audio/mpeg" },
      customMetadata: { plan: planType, fingerprint, originalName, previewMs: String(previewDuration * 1000) }
    });
  } catch (e) { console.warn("R2 put preview failed:", e?.message || e); }

  const { exp: pexp, sig: psig } = await signR2Key(previewKey, env, 15 * 60);
  const previewUrl = `${base}/audio/${encodeURIComponent(previewKey)}${psig ? `?exp=${pexp}&sig=${psig}` : ""}`;

  // FULL (if paid)
  let fullAudioUrl = null, fullKey = null;
  if (planType !== "free") {
    fullKey = `full/${processId}_full.mp3`;
    try {
      await env.AUDIO_STORAGE.put(fullKey, audioBuffer, {
        httpMetadata: { contentType: "audio/mpeg" },
        customMetadata: { plan: planType, fingerprint, originalName }
      });
    } catch (e) { console.warn("R2 put full failed:", e?.message || e); }
    const { exp: fexp, sig: fsig } = await signR2Key(fullKey, env, 60 * 60);
    fullAudioUrl = `${base}/audio/${encodeURIComponent(fullKey)}${fsig ? `?exp=${fexp}&sig=${fsig}` : ""}`;
  }

  return { previewUrl, fullAudioUrl, watermarkId: generateWatermarkId(fingerprint), processId, previewKey, fullKey };
}

function extractLanguagesFromTranscription(text="") {
  const pats = { Spanish:/[ñáéíóúü¿¡]/i, French:/[àâäéèêëïîôùûüÿç]/i, German:/[äöüß]/i };
  const out = ["English"];
  for (const [lang,re] of Object.entries(pats)) if (re.test(text)) out.push(lang);
  return [...new Set(out)];
}

async function handleAudioDownload(request, env, cors) {
  const url = new URL(request.url);
  const key = decodeURIComponent(url.pathname.replace(/^\/audio\//, ""));
  if (!key) return new Response("Bad Request", { status: 400, headers: cors });
  if (!env.AUDIO_STORAGE) return j({ error: "Storage not configured" }, 404, cors);

  const exp = url.searchParams.get("exp");
  const sig = url.searchParams.get("sig");
  const ok = await verifySignedUrl(key, exp, sig, env);
  if (!ok) return j({ error: "Invalid or expired link" }, 403, cors);

  const obj = await env.AUDIO_STORAGE.get(key);
  if (!obj) return new Response("Not found", { status: 404, headers: cors });

  const headers = {
    ...cors,
    "content-type": "audio/mpeg",
    "content-length": String(obj.size),
    "accept-ranges": "bytes",
    "cache-control": key.startsWith("previews/") ? "public, max-age=3600" : "private, max-age=7200"
  };
  return new Response(obj.body, { status: 200, headers });
}

// ---------- Payments ----------
const STRIPE_PRICE_IDS = {
  SINGLE_TRACK: "price_1S4NnmJ2Iq1764pCjA9xMnrn",
  DJ_PRO:       "price_1S4NpzJ2Iq1764pCcZISuhug",
  STUDIO_ELITE: "price_1S4Nr3J2Iq1764pCzHY4zIWr",
  DAY_PASS:     "price_1S4NsTJ2Iq1764pCCbru0Aao"
};

async function handlePaymentCreation(request, env, cors) {
  if (request.method !== "POST") return j({ error: "Method not allowed" }, 405, cors);

  try {
    const { priceId, type, fileName, email, fingerprint } = await request.json();

    if (!env.STRIPE_SECRET_KEY) return j({ error:"Stripe not configured" }, 500, cors);
    if (!env.FRONTEND_URL)      return j({ error:"Frontend URL not configured" }, 500, cors);

    const validPriceIds = Object.values(STRIPE_PRICE_IDS);
    if (!validPriceIds.includes(priceId)) return j({ error:"Invalid price ID" }, 400, cors);
    if (!["single_track","day_pass","dj_pro","studio_elite"].includes(type)) return j({ error:"Invalid plan type" }, 400, cors);

    const stripe = new Stripe(env.STRIPE_SECRET_KEY, { apiVersion: "2024-06-20", httpClient: Stripe.createFetchHttpClient() });
    const isSubscription = (type === "dj_pro" || type === "studio_elite");

    const session = await stripe.checkout.sessions.create({
      mode: isSubscription ? "subscription" : "payment",
      line_items: [{ price: priceId, quantity: 1 }],
      // in worker.js
      success_url: `${env.FRONTEND_URL.replace(/\/+$/,'')}/omni3?success=true&session_id=\${CHECKOUT_SESSION_ID}`,
      cancel_url:  `${env.FRONTEND_URL.replace(/\/+$/,'')}/omni3?canceled=true`,
      customer_email: email || undefined,
      allow_promotion_codes: true,
      automatic_tax: { enabled: true },
      customer_creation: "if_required",
      payment_method_types: ["card","link"],
      metadata: {
        type: type || "",
        fileName: fileName || "",
        fingerprint: fingerprint || "unknown",
        processingType: "audio_cleaning",
        ts: String(Date.now())
      }
    });

    return j({ success: true, sessionId: session.id, url: session.url }, 200, cors);
  } catch (e) {
    console.error("Payment creation error:", e);
    return j({ error:"Payment creation failed", details:e.message }, 500, cors);
  }
}

async function handleStripeWebhook(request, env, cors) {
  if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405, headers: cors });
  // Minimal ACK; verify & expand if you wire a webhook secret
  try {
    await request.text(); // read to drain body
    return new Response("OK", { status: 200, headers: cors });
  } catch (e) {
    return new Response("Bad payload", { status: 400, headers: cors });
  }
}

async function handleAccessActivation(request, env, cors) {
  try {
    const { fingerprint, sessionId } = await request.json();
    if (!fingerprint || !sessionId) return j({ success:false, error:"Missing fingerprint or sessionId" }, 400, cors);
    if (!env.STRIPE_SECRET_KEY)     return j({ success:false, error:"Stripe not configured" }, 500, cors);

    const stripe = new Stripe(env.STRIPE_SECRET_KEY, { apiVersion: "2024-06-20", httpClient: Stripe.createFetchHttpClient() });
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    const paid = (session.payment_status === "paid") || (session.status === "complete");
    if (!paid) return j({ success:false, error:"Payment not completed" }, 402, cors);

    const rec = await getStateKV(env, `latest:${fingerprint}`);
    if (!rec?.fullKey) return j({ success:true, message:"Payment verified, awaiting full audio generation." }, 200, cors);

    const { exp, sig } = await signR2Key(rec.fullKey, env, 60 * 60);
    const base = getWorkerBase(env, request);
    const fullUrl = `${base}/audio/${encodeURIComponent(rec.fullKey)}${sig ? `?exp=${exp}&sig=${sig}` : ""}`;
    return j({ success:true, downloadUrl: fullUrl }, 200, cors);
  } catch (e) {
    console.error("Activation error:", e);
    return j({ success:false, error:"Activation failed", details:e.message }, 500, cors);
  }
}

async function handleRedeemDownload(request, env, cors) {
  const url = new URL(request.url);
  const fingerprint = url.searchParams.get("fingerprint") || "";
  if (!fingerprint) return j({ error: "Missing fingerprint" }, 400, cors);
  const rec = await getStateKV(env, `latest:${fingerprint}`);
  if (!rec?.fullKey) return j({ error: "No full audio available yet" }, 404, cors);
  const { exp, sig } = await signR2Key(rec.fullKey, env, 60 * 60);
  const base = getWorkerBase(env, request);
  const fullUrl = `${base}/audio/${encodeURIComponent(rec.fullKey)}${sig ? `?exp=${exp}&sig=${sig}` : ""}`;
  return j({ downloadUrl: fullUrl }, 200, cors);
}

async function handleDownloadPage(request, env, cors) {
  const url = new URL(request.url);
  const sessionId = url.searchParams.get("session_id") || "";
  const fingerprint = url.searchParams.get("fingerprint") || "";
  const rec = fingerprint ? await getStateKV(env, `latest:${fingerprint}`) : null;

  let link = "";
  if (rec?.fullKey) {
    const { exp, sig } = await signR2Key(rec.fullKey, env, 60 * 60);
    const base = getWorkerBase(env, request);
    link = `${base}/audio/${encodeURIComponent(rec.fullKey)}${sig ? `?exp=${exp}&sig=${sig}` : ""}`;
  }

  const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>FWEA-I Download</title></head>
  <body style="font-family:system-ui,-apple-system,Inter,Segoe UI,sans-serif;background:#0a0a0f;color:#e5e7eb;display:grid;place-items:center;min-height:100vh;">
    <main style="text-align:center;max-width:720px;padding:24px;">
      <h1 style="margin:0 0 8px;">Payment Successful</h1>
      <p style="opacity:.8;">Session: ${sessionId || "N/A"}</p>
      ${link ? `<a href="${link}" style="display:inline-block;margin-top:16px;padding:12px 18px;border-radius:999px;background:#00f5ff;color:#0f172a;font-weight:700;text-decoration:none;">Download Full Audio</a>`
             : `<p style="margin-top:16px;opacity:.8;">Your audio is still processing. Refresh later for the download link.</p>`}
    </main>
  </body></html>`;
  return new Response(html, { status: 200, headers: { ...cors, "content-type": "text/html; charset=utf-8" } });
}
