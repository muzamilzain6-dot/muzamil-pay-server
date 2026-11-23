'use strict';
/**
 * test-self.js — Built-in self-test for the JazzCash server.
 *
 * Run:  node test-self.js
 * Exits 0 if all checks pass, 1 otherwise.
 *
 * Uses dummy credentials in-process only (never written to disk) and an
 * in-memory order store. Verifies the JazzCash hash against an
 * independent re-implementation, and exercises the full local flow:
 * start page -> signed checkout form -> signed return -> download page,
 * plus tamper rejection and replay protection.
 */

const assert = require('assert');
const http = require('http');
const fs = require('fs');
const path = require('path');

// --- Load the server with a fixed test port ------------------------------
process.env.PORT = '3311';
process.env.BASE_URL = 'http://127.0.0.1:3311';
process.env.JAZZCASH_MERCHANT_ID = 'MC12345';
process.env.JAZZCASH_PASSWORD = 'testpassword';
process.env.JAZZCASH_INTEGRITY_SALT = 'testsalt123';
process.env.JAZZCASH_ENV = 'sandbox';
process.env.SETUP_TOKEN = 'testtoken';

let serverMod;
try {
  serverMod = require('./server.js');
} catch (e) {
  console.error('FATAL: could not load server.js:', e && e.message);
  process.exit(1);
}
const srv = serverMod; // { app, server, config, ... }

let passed = 0;
let failed = 0;
const failures = [];
function check(name, fn) {
  try {
    const r = fn();
    if (r && typeof r.then === 'function') return r.then(() => { passed++; }).catch((e) => { failed++; failures.push(name + ': ' + (e && e.message)); });
    passed++;
  } catch (e) {
    failed++;
    failures.push(name + ': ' + (e && e.message));
  }
}
async function checkAsync(name, fn) {
  try { await fn(); passed++; } catch (e) { failed++; failures.push(name + ': ' + (e && e.message)); }
}

// --- Small HTTP helper ----------------------------------------------------
function httpReq(pathname, method, body, headers) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port: 3311, path: pathname, method: method || 'GET',
      headers: headers || {},
    }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}
function formBody(obj) {
  return Object.keys(obj).map((k) => encodeURIComponent(k) + '=' + encodeURIComponent(obj[k])).join('&');
}
function parseForm(html) {
  // Extract hidden inputs from a form page.
  const out = {};
  const re = /<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"/g;
  let m;
  while ((m = re.exec(html)) !== null) out[m[1]] = m[2];
  const action = /<form[^>]*action="([^"]+)"/.exec(html);
  return { fields: out, action: action ? action[1] : null };
}

(async () => {
  await srv.ready; // wait for the server to listen
  const crypto = require('crypto');
  const cfg = srv.config;

  // --- 1. Config loads from env ------------------------------------------
  check('config loads merchantId from env', () => assert.strictEqual(cfg.merchantId, 'MC12345'));
  check('config defaults env to sandbox', () => assert.strictEqual(cfg.env, 'sandbox'));
  check('config is marked configured', () => assert.strictEqual(cfg.configured, true));

  // --- 2. Hash matches an independent re-implementation ------------------
  function independentHash(fields, salt) {
    const keys = Object.keys(fields).filter((k) => k.indexOf('pp_') === 0 && fields[k] !== '' && fields[k] !== null && fields[k] !== undefined).sort();
    const str = salt + '&' + keys.map((k) => fields[k]).join('&');
    return crypto.createHmac('sha256', salt).update(str).digest('hex').toUpperCase();
  }
  const sample = {
    pp_Version: '1.1', pp_TxnType: '', pp_Language: 'EN', pp_MerchantID: 'MC12345',
    pp_SubMerchantID: '', pp_Password: 'testpassword', pp_BankID: '', pp_ProductID: 't20-wc-2024-patch',
    pp_TxnRefNo: 'T20260101120000001', pp_Amount: '20000', pp_TxnCurrency: 'PKR',
    pp_TxnDateTime: '20260101120000', pp_TxnExpiryDateTime: '20260101123000',
    pp_BillReference: 'invoice001', pp_Description: 'Test product', pp_ReturnURL: 'http://127.0.0.1:3311/pay/return',
    pp_SecureHash: '', ppmpf_1: '', ppmpf_2: '', ppmpf_3: '', ppmpf_4: '', ppmpf_5: '',
  };
  const expected = independentHash(sample, 'testsalt123');
  check('hash matches independent implementation', () => assert.strictEqual(srv.computeSecureHash(sample, 'testsalt123'), expected));
  check('hash is 64 uppercase hex chars', () => assert.ok(/^[0-9A-F]{64}$/.test(expected)));

  // --- 3. Empty pp_ fields excluded; changing a field breaks hash --------
  check('empty pp_ fields excluded from hash', () => {
    const a = Object.assign({}, sample); a.pp_TxnType = '';
    const b = Object.assign({}, sample); delete b.pp_TxnType;
    assert.strictEqual(srv.computeSecureHash(a, 'testsalt123'), srv.computeSecureHash(b, 'testsalt123'));
  });
  check('changing one field breaks verification', () => {
    const good = srv.computeSecureHash(sample, 'testsalt123');
    const tampered = Object.assign({}, sample, { pp_Amount: '19999' });
    assert.notStrictEqual(srv.computeSecureHash(tampered, 'testsalt123'), good);
    assert.strictEqual(srv.verifyReturn(Object.assign({}, sample, { pp_SecureHash: good, pp_ResponseCode: '000' }), cfg), true);
    assert.strictEqual(srv.verifyReturn(Object.assign({}, tampered, { pp_SecureHash: good, pp_ResponseCode: '000' }), cfg), false);
  });

  // --- 4. /health ----------------------------------------------------------
  await checkAsync('GET /health returns ok + configured', async () => {
    const r = await httpReq('/health');
    assert.strictEqual(r.status, 200);
    const j = JSON.parse(r.body);
    assert.strictEqual(j.ok, true);
    assert.strictEqual(j.configured, true);
  });

  // --- 5. Index lists both products --------------------------------------
  await checkAsync('GET / lists both products', async () => {
    const r = await httpReq('/');
    assert.strictEqual(r.status, 200);
    assert.ok(r.body.indexOf('t20-wc-2024-patch') !== -1);
    assert.ok(r.body.indexOf('wi-2026-kit') !== -1);
    assert.ok(r.body.indexOf('Rs. 200') !== -1);
  });

  // --- 6. Pay start page ---------------------------------------------------
  await checkAsync('GET /pay/t20-wc-2024-patch shows product + Rs. 200', async () => {
    const r = await httpReq('/pay/t20-wc-2024-patch');
    assert.strictEqual(r.status, 200);
    assert.ok(r.body.indexOf('ICC Mens T20 WorldCup Patch 2024') !== -1);
    assert.ok(r.body.indexOf('Rs. 200') !== -1);
    assert.ok(r.body.indexOf('JazzCash') !== -1);
  });
  await checkAsync('GET /pay/unknown-product returns 404', async () => {
    const r = await httpReq('/pay/nope');
    assert.strictEqual(r.status, 404);
  });

  // --- 7. Checkout form: signed, amount 20000 paisas, sandbox host -------
  let formFields = null;
  await checkAsync('POST /pay/t20-wc-2024-patch returns signed form to sandbox host', async () => {
    const r = await httpReq('/pay/t20-wc-2024-patch', 'POST', '', { 'Content-Type': 'application/x-www-form-urlencoded' });
    assert.strictEqual(r.status, 200);
    const parsed = parseForm(r.body);
    assert.ok(parsed.action && parsed.action.indexOf('sandbox.jazzcash.com.pk') !== -1, 'form action is sandbox host');
    assert.strictEqual(parsed.fields.pp_Amount, '20000');
    assert.strictEqual(parsed.fields.pp_TxnCurrency, 'PKR');
    assert.ok(/^[0-9A-F]{64}$/.test(parsed.fields.pp_SecureHash));
    assert.strictEqual(parsed.fields.pp_ReturnURL, 'http://127.0.0.1:3311/pay/return');
    assert.strictEqual(parsed.fields.pp_MerchantID, 'MC12345');
    formFields = parsed.fields;
    // The hash in the form must verify against the same fields.
    assert.strictEqual(srv.verifyReturn(Object.assign({}, parsed.fields, { pp_ResponseCode: '000' }), cfg), true);
  });

  // --- 8. Simulated signed return unlocks the download -------------------
  await checkAsync('signed return (code 000) unlocks download page', async () => {
    const ret = Object.assign({}, formFields, { pp_ResponseCode: '000', pp_ResponseMessage: 'Approved', pp_AuthCode: 'AUTH1', pp_RetreivalReferenceNo: 'RRN1' });
    ret.pp_SecureHash = srv.computeSecureHash(ret, 'testsalt123');
    const r = await httpReq('/pay/return', 'POST', formBody(ret), { 'Content-Type': 'application/x-www-form-urlencoded' });
    assert.strictEqual(r.status, 200);
    assert.ok(r.body.indexOf('Payment Successful') !== -1, 'success heading');
    assert.ok(r.body.indexOf('https://clksz.com/MUZAMIL') !== -1, 'download link present');
    assert.ok(r.body.indexOf('MUZAMILx2024') !== -1, 'password present');
  });

  // --- 9. Tampered return rejected ----------------------------------------
  await checkAsync('tampered return (amount changed) shows failure, no link', async () => {
    const ret = Object.assign({}, formFields, { pp_ResponseCode: '000', pp_ResponseMessage: 'Approved' });
    ret.pp_SecureHash = srv.computeSecureHash(ret, 'testsalt123');
    ret.pp_Amount = '100'; // tamper AFTER signing
    const r = await httpReq('/pay/return', 'POST', formBody(ret), { 'Content-Type': 'application/x-www-form-urlencoded' });
    assert.strictEqual(r.status, 200);
    assert.ok(r.body.indexOf('Payment Successful') === -1, 'no success heading');
    assert.ok(r.body.indexOf('https://clksz.com/MUZAMIL') === -1, 'no download link');
  });

  // --- 10. Non-000 response code shows failure -----------------------------
  await checkAsync('return with pp_ResponseCode 124 shows failed page', async () => {
    const ret = Object.assign({}, formFields, { pp_ResponseCode: '124', pp_ResponseMessage: 'Insufficient Funds' });
    ret.pp_SecureHash = srv.computeSecureHash(ret, 'testsalt123');
    const r = await httpReq('/pay/return', 'POST', formBody(ret), { 'Content-Type': 'application/x-www-form-urlencoded' });
    assert.strictEqual(r.status, 200);
    assert.ok(r.body.indexOf('Payment') !== -1);
    assert.ok(r.body.indexOf('https://clksz.com/MUZAMIL') === -1);
  });

  // --- 11. Replay cannot downgrade a paid order ---------------------------
  await checkAsync('forged replay cannot downgrade paid order', async () => {
    const r = await httpReq('/pay/status/' + formFields.pp_TxnRefNo);
    assert.strictEqual(r.status, 200);
    const j = JSON.parse(r.body);
    assert.strictEqual(j.order && j.order.status, 'paid', 'order stays paid');
  });

  // --- 12. /pay/status for unknown txn -------------------------------------
  await checkAsync('GET /pay/status/unknown returns 404-ish JSON', async () => {
    const r = await httpReq('/pay/status/T99999999999999999');
    assert.ok(r.status === 404 || r.status === 200);
    const j = JSON.parse(r.body);
    assert.ok(j.error || j.order);
  });

  // --- 13. /admin/setup token gating ---------------------------------------
  await checkAsync('GET /admin/setup without token is refused', async () => {
    const r = await httpReq('/admin/setup');
    assert.ok(r.status === 401 || r.status === 403);
  });
  await checkAsync('GET /admin/setup with token renders the form', async () => {
    const r = await httpReq('/admin/setup?token=testtoken');
    assert.strictEqual(r.status, 200);
    assert.ok(r.body.indexOf('Merchant ID') !== -1);
  });
  await checkAsync('POST /admin/setup without token is refused', async () => {
    const r = await httpReq('/admin/setup', 'POST', formBody({ merchantId: 'X', password: 'Y', integritySalt: 'Z', env: 'sandbox', baseUrl: 'http://x' }), { 'Content-Type': 'application/x-www-form-urlencoded' });
    assert.ok(r.status === 401 || r.status === 403);
  });

  // --- 14. WI kit: successful payment shows WhatsApp fallback -------------
  await checkAsync('WI kit success page shows WhatsApp fallback (no invented link)', async () => {
    const r0 = await httpReq('/pay/wi-2026-kit', 'POST', '', { 'Content-Type': 'application/x-www-form-urlencoded' });
    const parsed = parseForm(r0.body);
    const ret = Object.assign({}, parsed.fields, { pp_ResponseCode: '000', pp_ResponseMessage: 'Approved' });
    ret.pp_SecureHash = srv.computeSecureHash(ret, 'testsalt123');
    const r = await httpReq('/pay/return', 'POST', formBody(ret), { 'Content-Type': 'application/x-www-form-urlencoded' });
    assert.strictEqual(r.status, 200);
    assert.ok(r.body.indexOf('Payment Successful') !== -1);
    assert.ok(r.body.indexOf('wa.me') !== -1 || r.body.indexOf('WhatsApp') !== -1, 'WhatsApp fallback present');
  });

  // --- 15. No credentials or hashes leak into logs/pages --------------------
  await checkAsync('server pages do not contain the integrity salt', async () => {
    const r = await httpReq('/pay/t20-wc-2024-patch');
    assert.ok(r.body.indexOf('testsalt123') === -1);
    assert.ok(r.body.indexOf('testpassword') === -1);
  });

  // --- 16. products.json sanity --------------------------------------------
  await checkAsync('products.json has 2 products at Rs. 200', async () => {
    const p = JSON.parse(fs.readFileSync(path.join(__dirname, 'products.json'), 'utf8'));
    assert.strictEqual(p.products.length, 2);
    assert.ok(p.products.every((x) => x.pricePkr === 200));
  });

  // --- Summary --------------------------------------------------------------
  srv.server.close();
  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  if (failed) {
    failures.forEach((f) => console.log('  FAIL: ' + f));
    process.exit(1);
  }
  process.exit(0);
})().catch((e) => {
  console.error('FATAL self-test error:', e);
  try { srv.server.close(); } catch (_) {}
  process.exit(1);
});
