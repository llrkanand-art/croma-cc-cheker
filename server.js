const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const fetch = require('node-fetch'); // Ensure npm install node-fetch

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_FILE = 'session.json';

app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// ---------- PING ----------
app.get('/api/ping', (req, res) => {
  res.json({ ok: true, time: Date.now() });
});

// ---------- Session Storage ----------
let session = null;
try { session = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8')); } catch {}

function saveSession() {
  try { fs.writeFileSync(SESSION_FILE, JSON.stringify(session)); } catch {}
}

// ---------- Encryption (RSA Desalt Logic) ----------
function b64ToStr(s) {
  const clean = String(s).replace(/\s/g, '');
  return Buffer.from(clean.slice(0, clean.length - clean.length % 4), 'base64').toString('utf8');
}

function desaltPublicKey(stored) {
  let token = String(stored || '');
  try { if (token.startsWith('"')) token = JSON.parse(token); } catch {}
  let salted = b64ToStr(token);
  let i = salted.indexOf('|'); 
  if (i === -1) return stored; 
  
  const trimEnd = parseInt(salted.slice(0, i)); salted = salted.slice(i + 1);
  i = salted.indexOf('|'); 
  if (i === -1) return stored;

  const trimStart = parseInt(salted.slice(0, i)); salted = salted.slice(i + 1);
  i = salted.indexOf('|');
  if (i === -1) return stored;

  const keyLength = parseInt(salted.slice(0, i)); salted = salted.slice(i + 1);
  i = salted.indexOf('|');
  if (i === -1) return stored;

  const removeLength = parseInt(salted.slice(0, i)); salted = salted.slice(i + 1);
  
  salted = salted.slice(0, salted.length - trimEnd - 18);
  let key = b64ToStr(salted).slice(trimStart);
  return key.slice(0, keyLength) + key.slice(keyLength + removeLength);
}

function encryptBody(inCallResponse, bodyStr) {
  if (!inCallResponse) return '';
  try {
    const pem = desaltPublicKey(inCallResponse);
    const b64 = pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, '').replace(/\s+/g, '');
    const key = `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`;
    const digestHex = crypto.createHash('sha256').update(bodyStr).digest('hex');
    return crypto.publicEncrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(digestHex, 'utf8')).toString('base64');
  } catch (e) { return ''; }
}

// ---------- Cookie Helper ----------
function parseCookies(cookieArray) {
  if (!Array.isArray(cookieArray)) return '';
  return cookieArray
    .map(c => `${c.name}=${c.value}`)
    .join('; ');
}

// ---------- Cart Fetch (To get Product Names) ----------
async function fetchCartDetails() {
  if (!session?.template?.cartUrl) return null;
  try {
    // Construct GET URL to fetch cart summary
    const url = session.template.cartUrl.replace(/\/cart-modification.*/, '/cart-summary') || session.template.cartUrl;
    const cookieHeader = parseCookies(session.config?.cookies);
    
    const headers = {
        'Content-Type': 'application/json',
        'Cookie': cookieHeader,
        'Origin': 'https://www.croma.com',
        'Referer': 'https://www.croma.com/cart/'
    };
    
    // Attempt to fetch (Simple GET might not work if API is locked, but we try)
    // If we have the POST URL, we can sometimes GET it to see summary
    const res = await fetch(url, { method: 'GET', headers, timeout: 10000 });
    if (res.ok) {
        const data = await res.json();
        if (data && data.entries) {
            return data.entries.map(e => `${e.product?.name || 'Item'} x${e.quantity || 1}`).join(', ');
        }
    }
    // Fallback if direct get fails, try to parse url
    return "Cart URL Loaded (Products check pending)";
  } catch (e) {
    return null;
  }
}

// ---------- API Request ----------
async function requestCoupon(bodyObj) {
  if (!session?.template?.cartUrl) throw new Error('Session API URL missing');
  
  const bodyStr = JSON.stringify(bodyObj);
  const cookieHeader = parseCookies(session.config?.cookies);
  
  const headers = { 
      'Content-Type': 'application/json',
      'Cookie': cookieHeader,
      'Origin': 'https://www.croma.com',
      'Referer': 'https://www.croma.com/cart/'
  };
  
  // Add encryption header
  if (session.config?.inCallResponse) {
      const encHeader = encryptBody(session.config.inCallResponse, bodyStr);
      if(encHeader) headers.InCallReqHeader = encHeader;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const res = await fetch(session.template.cartUrl, { method: 'POST', headers, body: bodyStr, signal: controller.signal });
    let data = {}; try { data = await res.json(); } catch {}
    
    if (!res.ok) {
        if(400 <= res.status && res.status < 500) data.status = 'user_error';
        throw new Error(data.message || `HTTP ${res.status}`);
    }
    return data;
  } finally { clearTimeout(timer); }
}

function readResult(code, data) {
  const list = Array.isArray(data?.cromaCustomerAppliedCouponDataList) ? data.cromaCustomerAppliedCouponDataList : [];
  const item = list.find(v => String(v?.couponId || v?.couponCode || '').toUpperCase() === code);
  const valid = item?.isApplied === true;
  const discount = valid ? Number(data?.orderDiscounts?.value || data?.totalDiscounts?.value || 0) : 0;
  return { code, valid, discount, message: item?.customerDisplayText || item?.responseMessage || (valid ? 'Applied' : 'Not Applicable') };
}

// ---------- APIs ----------
app.post('/api/session', async (req, res) => {
  const config = req.body || {};
  // Validate structure
  if (!config.cookies || !config.url || !config.inCallResponse) {
      return res.status(400).json({ ok: false, error: 'JSON format ghalat hai. (cookies, url, inCallResponse zaroori hain)' });
  }
  
  // Save Session
  session = { 
      template: { cartUrl: config.url }, 
      config: config,
      savedAt: Date.now() 
  };
  saveSession();
  
  // Try loading cart names
  const cartNames = await fetchCartDetails();
  res.json({ ok: true, cartNames: cartNames });
});

app.get('/api/session', (req, res) => {
  if (!session?.template?.cartUrl) return res.json({ ok: true, live: false });
  let names = 'Cart loaded';
  if (session.cartNames) names = session.cartNames;
  res.json({ ok: true, live: true, cartNames: names, savedAt: session.savedAt });
});

// ---------- Job Runner with Pause Logic ----------
const jobs = new Map();
let jobCounter = 1;

function pushResult(job, res) {
  if (res.error) job.counts.errors++;
  else if (res.valid) { job.counts.valid++; job.valid.push(`${res.code} | Rs. ${res.discount} | ${res.message}`); job.newValid = true; }
  else job.counts.na++;
  job.counts.checked++;
  job.results.push(res);
  job.log.push(`[${new Date().toLocaleTimeString()}] ${res.code}: ${res.valid ? '✔' : (res.error ? '✖' : '-')} ${res.message}`);
  if (job.log.length > 200) job.log.shift();
}

async function runJob(job) {
  const concurrency = 5; // Safe default
  
  try {
    // Loop through coupons
    for (let s = 0; s < job.codes.length && !job.stopRequested; s += concurrency) {
        // Check Error Threshold (Hold on Error)
        if (job.pauseOnError && job.counts.errors >= 3 && job.status === 'running') {
            job.status = 'paused';
            job.pauseReason = "Too many errors (3+). Paused manually.";
            // Wait for user signal
            while(job.status === 'paused' && !job.stopRequested) {
                await new Promise(r => setTimeout(r, 1000));
            }
            if(job.stopRequested) break;
        }

        const group = job.codes.slice(s, s + concurrency);
        
        const settled = await Promise.all(group.map(async code => {
            try { 
                const d = await requestCoupon({ toBeAppliedCouponsList: [code] }); 
                return { code, result: readResult(code, d), data }; 
            } catch (e) { return { code, error: String(e.message || e) }; }
        }));

        // Process Results
        for (const x of settled) {
            if (job.stopRequested) break;
            let res = x.result;
            if (!res && x.data) res = readResult(x.code, x.data);
            if (!res && x.error) res = { code: x.code, error: x.error, valid: false, discount: 0, message: "API Error" };
            pushResult(job, res);
        }
    }

    job.status = job.stopRequested ? 'stopped' : 'done';
  } catch (e) { job.status = 'error'; job.error = String(e.message || e); }
}

app.post('/api/check', (req, res) => {
  const raw = String(req.body?.codes || '');
  const codes = [...new Set(raw.split(/[\n,;\t]+/).map(c => c.trim().toUpperCase()).filter(Boolean))];
  if (!codes.length) return res.status(400).json({ ok: false, error: 'Coupons khali hai' });
  if (!session?.template?.cartUrl) return res.status(400).json({ old: false, error: 'Session sync nahi hai. JSON paste karo!' });
  
  const id = 'job' + (jobCounter++);
  const job = { 
      id, codes, results: [], valid: [], log: [], 
      status: 'running', stopRequested: false, 
      counts: { checked: 0, valid: 0, na: 0, errors: 0 }, 
      total: codes.length, newValid: false, 
      startedAt: Date.now(),
      pauseOnError: Boolean(req.body?.pauseOnError) || true // Default ON
  };
  jobs.set(id, job);
  runJob(job);
  res.json({ ok: true, jobId: id });
});

app.post('/api/stop', (req, res) => {
  const job = jobs.get(req.body?.jobId);
  if (job) job.stopRequested = true;
  res.json({ ok: true });
});

app.post('/api/resume', (req, res) => {
    const job = jobs.get(req.body?.jobId);
    if (job && job.status === 'paused') {
        job.status = 'running';
        runJob(job); // Restart loop
    }
    res.json({ ok: true });
});

app.get('/api/result', (req, res) => {
  const job = jobs.get(String(req.query.jobId || ''));
  if (!job) return res.status(404).json({ ok: false, error: 'Job nahi mila' });
  const newValid = job.newValid; job.newValid = false;
  res.json({ 
      ok: true, status: job.status, counts: job.counts, total: job.total, 
      valid: job.valid, 
      results: job.results.slice(req.query.from ? Number(req.query.from) : 0),
      newValidBeep: newValid, log: job.log.slice(-20) 
  });
});

app.listen(PORT, () => console.log(`Server live on port ${PORT}`));
