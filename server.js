const express = require('express');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_FILE = 'session.json';

app.use(express.json({ limit: '3mb' }));
app.use(express.static('public'));

// ---------- PING (public, keep-alive) ----------
app.get('/api/ping', (req, res) => {
  res.json({ ok: true, time: Date.now() });
});

// ---------- Session storage ----------
let session = null;
try { session = JSON.parse(fs.readFileSync(SESSION_FILE, 'utf8')); } catch {}

function saveSession() {
  try { fs.writeFileSync(SESSION_FILE, JSON.stringify(session)); } catch {}
}

// ---------- InCallReqHeader encryption (Croma RSA scheme) ----------
function b64ToStr(s) {
  const clean = String(s).replace(/\s/g, '');
  return Buffer.from(clean.slice(0, clean.length - clean.length % 4), 'base64').toString('utf8');
}
function desaltPublicKey(stored) {
  let token = String(stored || '');
  try { if (token.startsWith('"')) token = JSON.parse(token); } catch {}
  let salted = b64ToStr(token);
  let i = salted.indexOf('|'); const trimEnd = parseInt(salted.slice(0, i)); salted = salted.slice(i + 1);
  i = salted.indexOf('|'); const trimStart = parseInt(salted.slice(0, i)); salted = salted.slice(i + 1);
  i = salted.indexOf('|'); const keyLength = parseInt(salted.slice(0, i)); salted = salted.slice(i + 1);
  i = salted.indexOf('|'); const removeLength = parseInt(salted.slice(0, i)); salted = salted.slice(i + 1);
  salted = salted.slice(0, salted.length - trimEnd - 18);
  let key = b64ToStr(salted).slice(trimStart);
  return key.slice(0, keyLength) + key.slice(keyLength + removeLength);
}
function encryptBody(inCallResponse, bodyStr) {
  const pem = desaltPublicKey(inCallResponse);
  const b64 = pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, '').replace(/\s+/g, '');
  const key = `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`;
  const digestHex = crypto.createHash('sha256').update(bodyStr).digest('hex');
  return crypto.publicEncrypt({ key, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(digestHex, 'utf8')).toString('base64');
}

// ---------- Croma API request ----------
async function requestCoupon(bodyObj) {
  const tpl = session.template;
  if (!tpl?.url) throw new Error('Session synced nahi hai');
  const bodyStr = JSON.stringify(bodyObj);
  const headers = { ...(tpl.headers || {}), 'Content-Type': 'application/json' };
  if (!headers.Origin) headers.Origin = 'https://www.croma.com';
  if (!headers.Referer) headers.Referer = 'https://www.croma.com/cart/';
  if (session.cookie && !headers.Cookie) headers.Cookie = session.cookie;
  try { headers.InCallReqHeader = encryptBody(session.inCallResponse, bodyStr); } catch {}

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const res = await fetch(tpl.url, { method: 'POST', headers, body: bodyStr, signal: controller.signal });
    let data = {}; try { data = await res.json(); } catch {}
    if (!res.ok) throw new Error(data.message || ('HTTP ' + res.status));
    return data;
  } finally { clearTimeout(timer); }
}

function readResult(code, data, httpStatus) {
  const list = Array.isArray(data?.cromaCustomerAppliedCouponDataList) ? data.cromaCustomerAppliedCouponDataList : [];
  const item = list.find(v => String(v?.couponId || v?.couponCode || '').toUpperCase() === code);
  const valid = item?.isApplied === true;
  const discount = valid ? Number(data?.orderDiscounts?.value || data?.totalDiscounts?.value || 0) : 0;
  return { code, valid, discount, httpStatus, message: item?.customerDisplayText || item?.responseMessage || (valid ? 'Coupon applied' : 'Coupon not applicable') };
}

// ---------- Session API ----------
app.post('/api/session', (req, res) => {
  const { template, cart, inCallResponse, cookie, originalCoupons } = req.body || {};
  if (!template?.url) return res.status(400).json({ ok: false, error: 'Template missing' });
  session = { template, cart: cart || null, inCallResponse: inCallResponse || null, cookie: cookie || '', originalCoupons: originalCoupons || [], savedAt: Date.now() };
  saveSession();
  res.json({ ok: true });
});

app.get('/api/session', (req, res) => {
  if (!session?.template?.url) return res.json({ ok: true, live: false });
  const names = (session.cart?.entries || []).map(e => `${e.product?.name || 'Product'} x${e.quantity || 1}`);
  res.json({ ok: true, live: true, cart: names.length ? names.join(' | ') : 'Cart detail nahi mila', pincode: (session.template.url.match(/pincode(\d{6})/i) || [])[1] || '', savedAt: session.savedAt });
});

// ---------- Job runner ----------
const jobs = new Map();
let jobCounter = 1;

function pushResult(job, res) {
  if (res.error) job.counts.errors++;
  else if (res.valid) { job.counts.valid++; job.valid.push(`${res.code} | Rs. ${res.discount} | ${res.message}`); job.newValid = true; }
  else job.counts.na++;
  job.counts.checked++;
  job.results.push(res);
  job.log.push(`[${new Date().toLocaleTimeString('en-IN', { hour12: false })}] ${res.code}: ${res.error ? 'ERROR | ' + res.error : (res.valid ? 'VALID | ' + res.message + ' | Rs. ' + res.discount : 'NOT APPLICABLE')}`);
  if (job.log.length > 400) job.log.shift();
}

async function runJob(job, concurrency) {
  try {
    for (const c of (session.originalCoupons || [])) { try { await requestCoupon({ toBeRemovedCouponsList: [c] }); } catch {} }

    for (let s = 0; s < job.codes.length && !job.stopRequested; s += concurrency) {
      const group = job.codes.slice(s, s + concurrency);
      job.log.push(`Batch: ${group[0]} ... ${group[group.length - 1]}`);
      const settled = await Promise.all(group.map(async code => {
        try { const d = await requestCoupon({ toBeAppliedCouponsList: [code] }); return { code, result: readResult(code, d) }; }
        catch (e) { return { code, error: String(e.message || e) }; }
      }));
      const hasValid = settled.some(x => x.result?.valid);
      const hasError = settled.some(x => x.error);

      if (hasValid || hasError) {
        for (const x of settled) if (x.result?.valid) { try { await requestCoupon({ toBeRemovedCouponsList: [x.code] }); } catch {} }
        for (const x of settled) {
          if (job.stopRequested) break;
          try {
            const d = await requestCoupon({ toBeAppliedCouponsList: [x.code] });
            const res = readResult(x.code, d);
            try { await requestCoupon({ toBeRemovedCouponsList: [x.code] }); } catch {}
            pushResult(job, res);
          } catch (e) {
            pushResult(job, x.result ? x.result : { code: x.code, error: String(e.message || e), valid: false, discount: 0 });
          }
        }
      } else settled.forEach(x => pushResult(job, x.result));
    }

    if ((session.originalCoupons || []).length) { try { await requestCoupon({ toBeAppliedCouponsList: session.originalCoupons }); } catch {} }
    job.status = job.stopRequested ? 'stopped' : 'done';
  } catch (e) { job.status = 'error'; job.error = String(e.message || e); }
}

app.post('/api/check', (req, res) => {
  const raw = String(req.body?.codes || '');
  const codes = [...new Set(raw.split(/[\n,;\t]+/).map(c => c.trim().toUpperCase()).filter(Boolean))];
  if (!codes.length) return res.status(400).json({ ok: false, error: 'Coupons khaali hai' });
  if (!session?.template?.url) return res.status(400).json({ ok: false, error: 'Pehle croma.com/cart pe Bookmarklet se sync karo!' });
  const concurrency = Math.max(1, Math.min(50, Number(req.body?.concurrency) || 25));
  const id = 'job' + (jobCounter++);
  const job = { id, codes, results: [], valid: [], log: [], status: 'running', stopRequested: false, counts: { checked: 0, valid: 0, na: 0, errors: 0 }, total: codes.length, newValid: false, startedAt: Date.now() };
  jobs.set(id, job);
  for (const [k, v] of jobs) if (Date.now() - v.startedAt > 3 * 3600 * 1000) jobs.delete(k);
  runJob(job, concurrency);
  res.json({ ok: true, jobId: id });
});

app.post('/api/stop', (req, res) => {
  const job = jobs.get(req.body?.jobId);
  if (job) { job.stopRequested = true; job.status = 'stopping'; }
  res.json({ ok: true });
});

app.get('/api/result', (req, res) => {
  const job = jobs.get(String(req.query.jobId || ''));
  if (!job) return res.status(404).json({ ok: false, error: 'Job nahi mila (server sleep hua tha?)' });
  const newValid = job.newValid; job.newValid = false;
  res.json({ ok: true, status: job.status, counts: job.counts, total: job.total, valid: job.valid,
    results: job.results.slice(req.query.from ? Number(req.query.from) : 0),
    newValidBeep: newValid, log: job.log.slice(-30), error: job.error || null });
});

app.listen(PORT, () => console.log('Server live on port', PORT));
