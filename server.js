'use strict';
/**
 * server.js — MUZAMIL STUFF JazzCash payment server.
 *
 * Pure Node.js, zero npm dependencies (built-in http/crypto/fs only).
 *
 * What it does:
 *   - Serves a payment-start page per product (GET /pay/:productId).
 *   - Builds a SIGNED JazzCash hosted-checkout form and auto-submits the
 *     buyer to JazzCash (POST /pay/:productId).
 *   - Receives JazzCash's return (POST /pay/return), VERIFIES the
 *     pp_SecureHash with the Integrity Salt, checks the response code and
 *     the amount, and only then shows the download link.
 *   - Optional server-to-server notification (POST /pay/notify).
 *   - Transaction status check via the JazzCash Payment Inquiry API
 *     (GET /pay/status/:txnRefNo).
 *   - One-time credential setup page (GET/POST /admin/setup), protected
 *     by a random token printed ONLY to this server's console at startup.
 *
 * The Integrity Salt NEVER leaves this server. It is never in page
 * JavaScript, never in a log, never in a URL, never in this repo.
 * Amounts always come from products.json on this server — the browser
 * is never trusted for a price.
 *
 * Run:  node server.js          (reads env vars or server-config.json)
 * Test: node test-self.js
 */
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const querystring = require('querystring');
const {
  loadConfig,
  saveConfigFile,
  configFileExists,
  merchantFormUrl,
  inquiryUrl,
} = require('./config');

// ------------------------------------------------------------------ setup
let config = loadConfig();
const PORT = config.port;

// Setup token: random per process, printed ONLY to this server's console.
// (An env var SETUP_TOKEN may override it, e.g. on a deploy host.)
const SETUP_TOKEN =
  config.setupTokenEnv || crypto.randomBytes(24).toString('hex');

const PRODUCTS = loadProducts();
const ORDERS_FILE = path.join(__dirname, 'orders.json');
let orders = loadOrders();

function loadProducts() {
  try {
    const raw = fs.readFileSync(path.join(__dirname, 'products.json'), 'utf8');
    const data = JSON.parse(raw);
    const list = Array.isArray(data.products) ? data.products : [];
    const map = {};
    for (const p of list) {
      if (p && p.id) map[p.id] = p;
    }
    return map;
  } catch (e) {
    console.error('[products] could not load products.json:', e.message);
    return {};
  }
}

function loadOrders() {
  try {
    if (!fs.existsSync(ORDERS_FILE)) return {};
    const data = JSON.parse(fs.readFileSync(ORDERS_FILE, 'utf8'));
    return data && typeof data === 'object' ? data : {};
  } catch (e) {
    return {};
  }
}

function saveOrders() {
  try {
    fs.writeFileSync(ORDERS_FILE, JSON.stringify(orders, null, 2) + '\n', 'utf8');
  } catch (e) {
    console.error('[orders] could not save orders.json:', e.message);
  }
}
// ------------------------------------------------------- JazzCash hashing
/**
 * JazzCash pp_SecureHash (documented algorithm):
 *   1. Take all request fields whose names start with "pp_", EXCLUDING
 *      pp_SecureHash itself, and drop fields with empty values.
 *   2. Sort them alphabetically by field name (ASCII).
 *   3. Concatenate the VALUES with "&" between them.
 *   4. Prepend the Integrity Salt:  salt + "&" + concatenatedValues.
 *   5. HMAC-SHA256 of that string, keyed by the Integrity Salt (UTF-8),
 *      rendered as UPPERCASE hex.
 */
function computeSecureHash(fields, salt) {
  const keys = Object.keys(fields)
    .filter((k) => k.indexOf('pp_') === 0 && k !== 'pp_SecureHash')
    .filter((k) => fields[k] !== undefined && fields[k] !== null && String(fields[k]) !== '')
    .sort();
  const joined = keys.map((k) => String(fields[k])).join('&');
  const dataToHash = salt + '&' + joined;
  return crypto
    .createHmac('sha256', Buffer.from(salt, 'utf8'))
    .update(Buffer.from(dataToHash, 'utf8'))
    .digest('hex')
    .toUpperCase();
}

function verifySecureHash(fields, salt) {
  const received = fields.pp_SecureHash;
  if (!received || !salt) return false;
  const expected = computeSecureHash(fields, salt);
  const a = Buffer.from(String(received).toUpperCase(), 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(a, b);
  } catch (e) {
    return false;
  }
}

// ------------------------------------------------------------------ utils
function txnDateTime(date) {
  const d = date || new Date();
  const p = (n) => String(n).padStart(2, '0');
  return (
    d.getFullYear() +
    p(d.getMonth() + 1) +
    p(d.getDate()) +
    p(d.getHours()) +
    p(d.getMinutes()) +
    p(d.getSeconds())
  );
}

function newTxnRefNo() {
  // Unique, alphanumeric, short enough for JazzCash (kept <= 20 chars).
  return (
    'MS' +
    Date.now().toString(36).toUpperCase() +
    crypto.randomBytes(3).toString('hex').toUpperCase()
  ).slice(0, 20);
}

function escapeHtml(s) {
  return String(s === undefined || s === null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function readBody(req, limitBytes) {
  const limit = limitBytes || 64 * 1024;
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function parseFormBody(body, contentType) {
  if ((contentType || '').indexOf('application/json') !== -1) {
    try {
      const obj = JSON.parse(body || '{}');
      return obj && typeof obj === 'object' ? obj : {};
    } catch (e) {
      return {};
    }
  }
  return querystring.parse(body || '');
}

function sendHtml(res, status, html) {
  const buf = Buffer.from(html, 'utf8');
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': buf.length,
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(buf);
}

function sendJson(res, status, obj) {
  const buf = Buffer.from(JSON.stringify(obj), 'utf8');
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': buf.length,
  });
  res.end(buf);
}

// ------------------------------------------------------------- page shells
function pageShell(title, inner) {
  return (
    '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1.0">' +
    '<title>' + escapeHtml(title) + ' | Muzamil Stuff</title>' +
    '<style>body{font-family:Arial,sans-serif;background:#0a0f0d;color:#e8e8e8;margin:0;padding:20px 12px}' +
    '.wrap{max-width:620px;margin:0 auto;background:#121815;border:1px solid #1f2a24;border-radius:16px;padding:26px 22px}' +
    'h1{font-size:22px;color:#fff;margin:0 0 10px}h2{font-size:17px;color:#f5c518}' +
    'p,li{font-size:15px;line-height:1.7;color:#c9d2cc}' +
    '.price{font-size:30px;font-weight:800;color:#00e676;margin:10px 0}' +
    '.btn{display:block;text-align:center;background:#00e676;color:#062b16;font-size:18px;font-weight:800;padding:14px;border:0;border-radius:12px;cursor:pointer;width:100%;text-decoration:none;margin-top:14px}' +
    '.btn.wa{background:#25D366;color:#fff}' +
    '.btn.ghost{background:#1f2a24;color:#e8e8e8}' +
    '.ok{color:#00e676}.bad{color:#ff5252}' +
    '.dl{display:block;text-align:center;background:#f5c518;color:#111;font-size:18px;font-weight:800;padding:15px;border-radius:12px;text-decoration:none;margin-top:14px}' +
    'code{background:#0a0f0d;border:1px solid #2a3a30;border-radius:6px;padding:2px 7px;color:#f5c518;font-size:14px}' +
    '.note{font-size:13px;color:#8a938d;margin-top:14px;line-height:1.6}' +
    'input,select{width:100%;padding:12px;margin:8px 0;border-radius:8px;border:1px solid #2a3a30;background:#0a0f0d;color:#fff;font-size:15px;box-sizing:border-box}' +
    'label{font-size:14px;color:#c9d2cc}</style></head><body><div class="wrap">' +
    inner +
    '<p class="note">© Muzamil Stuff — Secure payment via JazzCash</p>' +
    '</div></body></html>'
  );
}

function whatsappLink(productId, txnRefNo) {
  const product = PRODUCTS[productId] || null;
  const phone = (product && product.whatsapp) || '+923132366228';
  const text =
    'Assalam-o-Alaikum, maine payment kar di hai. Product: ' +
    (product ? product.name : productId) +
    (txnRefNo ? ' | Order: ' + txnRefNo : '');
  return 'https://api.whatsapp.com/send/?phone=%2B' + phone.replace(/[^0-9]/g, '') +
    '&text=' + encodeURIComponent(text);
}
// ------------------------------------------------------------- order logic
function createOrder(product) {
  const txnRefNo = newTxnRefNo();
  const now = new Date();
  const order = {
    txnRefNo,
    productId: product.id,
    productName: product.name,
    amountPkr: product.pricePkr,
    amountPaisas: product.pricePkr * 100,
    currency: product.currency || 'PKR',
    billReference: 'MS-' + txnRefNo,
    status: 'pending', // pending | paid | failed | cancelled
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
    ppResponseCode: null,
    jazzcashTxnRefNo: null,
  };
  orders[txnRefNo] = order;
  saveOrders();
  return order;
}

function markOrder(order, status, extra) {
  order.status = status;
  order.updatedAt = new Date().toISOString();
  if (extra) {
    if (extra.ppResponseCode !== undefined) order.ppResponseCode = extra.ppResponseCode;
    if (extra.jazzcashTxnRefNo) order.jazzcashTxnRefNo = extra.jazzcashTxnRefNo;
  }
  orders[order.txnRefNo] = order;
  saveOrders();
  // Log the outcome only — never credentials, never hashes, never full payloads.
  console.log(
    '[order] ' + order.txnRefNo + ' ' + order.productId + ' Rs.' + order.amountPkr +
    ' -> ' + status + ' at ' + order.updatedAt
  );
}

/**
 * Shared verification for JazzCash return / notification posts.
 * Returns { ok, order, reason } — ok only when hash verifies, response
 * code is "000", the txn ref matches a known order, and the amount matches.
 */
function handleJazzCashCallback(fields) {
  const txnRefNo = String(fields.pp_TxnRefNo || '').trim();
  const order = orders[txnRefNo];
  if (!order) {
    return { ok: false, order: null, reason: 'unknown-order' };
  }
  // A paid order is terminal: later callbacks (duplicates, replays or
  // forged posts) must never downgrade it back to failed/cancelled.
  if (order.status === 'paid') {
    const stillValid =
      verifySecureHash(fields, config.integritySalt) &&
      String(fields.pp_ResponseCode || '').trim() === '000' &&
      String(fields.pp_Amount || '').trim() === String(order.amountPaisas);
    return { ok: stillValid, order, reason: 'already-paid' };
  }
  if (!verifySecureHash(fields, config.integritySalt)) {
    markOrder(order, 'failed', { ppResponseCode: fields.pp_ResponseCode || null });
    return { ok: false, order, reason: 'bad-hash' };
  }
  const code = String(fields.pp_ResponseCode || '').trim();
  const amountOk = String(fields.pp_Amount || '').trim() === String(order.amountPaisas);
  if (code !== '000') {
    markOrder(order, code === '121' || code === '124' ? 'cancelled' : 'failed', {
      ppResponseCode: code,
      jazzcashTxnRefNo: fields.pp_TxnRefNo || null,
    });
    return { ok: false, order, reason: 'response-code-' + code };
  }
  if (!amountOk) {
    markOrder(order, 'failed', { ppResponseCode: code });
    return { ok: false, order, reason: 'amount-mismatch' };
  }
  markOrder(order, 'paid', {
    ppResponseCode: code,
    jazzcashTxnRefNo: fields.pp_TxnRefNo || null,
  });
  return { ok: true, order, reason: 'paid' };
}

function downloadPageHtml(order, product) {
  let inner = '<h1 class="ok">Payment Successful ✓</h1>' +
    '<p>Shukriya! Aapki payment verify ho gayi hai.</p>' +
    '<p>Product: <b>' + escapeHtml(product.name) + '</b><br>Order: <code>' +
    escapeHtml(order.txnRefNo) + '</code></p>';
  if (product.downloadUrl) {
    inner += '<a class="dl" href="' + escapeHtml(product.downloadUrl) +
      '" target="_blank" rel="noopener">Download Now</a>';
    if (product.filePassword) {
      inner += '<p>File password: <code>' + escapeHtml(product.filePassword) + '</code></p>';
    }
    inner += '<p class="note">Link ko mehfooz rakhein. Kisi bhi masle par WhatsApp par rabta karein.</p>';
  } else {
    inner += '<p>Is product ka download link abhi server par save nahi hai. ' +
      'Apna order number WhatsApp par bhej dein — link foran mil jayega.</p>' +
      '<a class="btn wa" href="' + escapeHtml(whatsappLink(product.id, order.txnRefNo)) +
      '" target="_blank" rel="noopener">WhatsApp par Order Bhejein</a>';
  }
  return pageShell('Payment Successful', inner);
}

function failurePageHtml(order, reason) {
  const ref = order ? order.txnRefNo : '';
  const productId = order ? order.productId : '';
  const retry = productId
    ? '<a class="btn" href="/pay/' + escapeHtml(productId) + '">Try Again — Pay with JazzCash</a>'
    : '';
  const inner = '<h1 class="bad">Payment Failed / Cancelled</h1>' +
    '<p>Aapki payment mukammal nahi ho saki. Koi paisa katne par JazzCash app me status check karein — ' +
    'agar payment kat gayi hai to screenshot WhatsApp par bhej dein.</p>' +
    (ref ? '<p>Order: <code>' + escapeHtml(ref) + '</code></p>' : '') +
    '<p class="note">Reason: ' + escapeHtml(reason || 'unknown') + '</p>' +
    retry +
    '<a class="btn wa" href="' + escapeHtml(whatsappLink(productId || 't20-wc-2024-patch', ref)) +
    '" target="_blank" rel="noopener">WhatsApp par Rabta Karein</a>';
  return pageShell('Payment Failed', inner);
}

// ------------------------------------------------------- inquiry (server)
function inquiryTransaction(txnRefNo) {
  return new Promise((resolve) => {
    const fields = {
      pp_MerchantID: config.merchantId,
      pp_Password: config.password,
      pp_TxnRefNo: txnRefNo,
    };
    fields.pp_SecureHash = computeSecureHash(fields, config.integritySalt);
    const body = JSON.stringify(fields);
    const url = new URL(inquiryUrl(config.env));
    const req = https.request(
      {
        hostname: url.hostname,
        path: url.pathname,
        method: 'POST',
        timeout: 15000,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          try {
            resolve({ ok: true, httpStatus: res.statusCode, data: JSON.parse(text) });
          } catch (e) {
            resolve({ ok: true, httpStatus: res.statusCode, raw: text });
          }
        });
      }
    );
    req.on('timeout', () => {
      req.destroy(new Error('inquiry timed out'));
    });
    req.on('error', (e) => resolve({ ok: false, error: e.message }));
    req.write(body);
    req.end();
  });
}
// ------------------------------------------------------------------ routes
function handleRequest(req, res) {
  const url = new URL(req.url || '/', 'http://localhost');
  const pathname = url.pathname;

  // Home
  if (req.method === 'GET' && pathname === '/') {
    const items = Object.values(PRODUCTS)
      .map(
        (p) =>
          '<li><b>' + escapeHtml(p.name) + '</b> — Rs. ' + escapeHtml(p.pricePkr) +
          ' — <a style="color:#00e676" href="/pay/' + escapeHtml(p.id) + '">Buy with JazzCash</a></li>'
      )
      .join('');
    return sendHtml(
      res,
      200,
      pageShell(
        'Muzamil Stuff — Payments',
        '<h1>Muzamil Stuff — Payments</h1><p>Secure JazzCash checkout for paid downloads.</p><ul>' +
          items +
          '</ul><p class="note">Environment: <code>' + escapeHtml(config.env) +
          '</code> | Credentials configured: <code>' + (config.configured ? 'yes' : 'no') +
          '</code></p>'
      )
    );
  }

  // Health
  if (req.method === 'GET' && pathname === '/health') {
    return sendJson(res, 200, { ok: true, env: config.env, configured: config.configured });
  }

  // ---- GET /pay/:productId (start page)
  // NOTE: "return", "notify" and "status" are reserved endpoint names,
  // not product IDs — they must not fall through to the product handler.
  let m = pathname.match(/^\/pay\/([A-Za-z0-9\-_]+)$/);
  const reservedPayWord = m && ['return', 'notify', 'status'].indexOf(m[1]) !== -1;
  if (req.method === 'GET' && m && !reservedPayWord) {
    const product = PRODUCTS[m[1]];
    if (!product) {
      return sendHtml(res, 404, pageShell('Not found', '<h1>Product nahi mila</h1><p>Is ID ka koi product nahi hai.</p>'));
    }
    const inner =
      '<h1>' + escapeHtml(product.name) + '</h1>' +
      '<div class="price">Rs. ' + escapeHtml(product.pricePkr) + ' <span style="font-size:14px;color:#9aa5a0">one-time</span></div>' +
      '<p>Payment JazzCash ke secure page par hogi. Payment verify hote hi download link isi screen par milega.</p>' +
      (config.configured
        ? '<form method="POST" action="/pay/' + escapeHtml(product.id) + '">' +
          '<button class="btn" type="submit">Pay Rs. ' + escapeHtml(product.pricePkr) + ' with JazzCash</button></form>'
        : '<p class="bad">Payments abhi setup nahi hain. Owner ko /admin/setup par credentials daalne hain.</p>') +
      '<p class="note">Agar JazzCash payment fail ho jaye to manual payment ka option bhi hai — WhatsApp par screenshot bhej dein.</p>';
    return sendHtml(res, 200, pageShell(product.name, inner));
  }

  // ---- POST /pay/:productId (build signed JazzCash form, auto-submit)
  if (req.method === 'POST' && m && !reservedPayWord) {
    const product = PRODUCTS[m[1]];
    if (!product) {
      return sendHtml(res, 404, pageShell('Not found', '<h1>Product nahi mila</h1>'));
    }
    if (!config.configured) {
      return sendHtml(
        res,
        503,
        pageShell(
          'Payments not set up',
          '<h1>Payments abhi setup nahi hain</h1><p>Owner ko pehle /admin/setup par JazzCash credentials daalne hain.</p>' +
            '<a class="btn wa" href="' + escapeHtml(whatsappLink(product.id, '')) +
            '" target="_blank" rel="noopener">WhatsApp par Rabta Karein</a>'
        )
      );
    }
    const order = createOrder(product);
    const now = new Date();
    const expiry = new Date(now.getTime() + 30 * 60 * 1000);
    const fields = {
      pp_MerchantID: config.merchantId,
      pp_Password: config.password,
      pp_TxnRefNo: order.txnRefNo,
      pp_Amount: String(order.amountPaisas),
      pp_TxnCurrency: order.currency,
      pp_TxnDateTime: txnDateTime(now),
      pp_TxnExpiryDateTime: txnDateTime(expiry),
      pp_BillReference: order.billReference,
      pp_Description: product.name,
      pp_ReturnURL: config.baseUrl.replace(/\/$/, '') + '/pay/return',
    };
    fields.pp_SecureHash = computeSecureHash(fields, config.integritySalt);
    const inputs = Object.keys(fields)
      .map(
        (k) =>
          '<input type="hidden" name="' + escapeHtml(k) + '" value="' + escapeHtml(fields[k]) + '">'
      )
      .join('\n');
    const html =
      '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Redirecting to JazzCash…</title></head>' +
      '<body style="font-family:Arial;background:#0a0f0d;color:#e8e8e8;text-align:center;padding:60px 20px">' +
      '<p>JazzCash secure payment page khul rahi hai…</p>' +
      '<form id="jc" method="POST" action="' + escapeHtml(merchantFormUrl(config.env)) + '">' +
      inputs +
      '</form><script>document.getElementById("jc").submit();</script></body></html>';
    return sendHtml(res, 200, html);
  }
  // ---- POST /pay/return (JazzCash redirect back)
  if (req.method === 'POST' && pathname === '/pay/return') {
    readBody(req)
      .then((body) => {
        const fields = parseFormBody(body, req.headers['content-type']);
        const result = handleJazzCashCallback(fields);
        if (result.ok) {
          const product = PRODUCTS[result.order.productId];
          return sendHtml(res, 200, downloadPageHtml(result.order, product));
        }
        return sendHtml(res, 200, failurePageHtml(result.order, result.reason));
      })
      .catch(() => sendHtml(res, 400, pageShell('Error', '<h1>Invalid request</h1>')));
    return;
  }

  // ---- POST /pay/notify (server-to-server notification)
  if (req.method === 'POST' && pathname === '/pay/notify') {
    readBody(req)
      .then((body) => {
        const fields = parseFormBody(body, req.headers['content-type']);
        const result = handleJazzCashCallback(fields);
        return sendJson(res, 200, {
          ok: result.ok,
          txnRefNo: result.order ? result.order.txnRefNo : null,
          status: result.order ? result.order.status : 'unknown',
          reason: result.reason,
        });
      })
      .catch(() => sendJson(res, 400, { ok: false, error: 'invalid-body' }));
    return;
  }

  // ---- GET /pay/status/:txnRefNo (Payment Inquiry API)
  m = pathname.match(/^\/pay\/status\/([A-Za-z0-9\-_]+)$/);
  if (req.method === 'GET' && m) {
    const txnRefNo = m[1];
    const order = orders[txnRefNo];
    if (!order) {
      return sendJson(res, 404, { ok: false, error: 'unknown-order', txnRefNo });
    }
    if (!config.configured) {
      return sendJson(res, 503, { ok: false, error: 'not-configured' });
    }
    inquiryTransaction(txnRefNo).then((result) => {
      if (!result.ok) {
        // Live inquiry unavailable (no network / JazzCash down): still
        // report the LOCAL order status — that is what the buyer needs.
        return sendJson(res, 200, {
          ok: true,
          txnRefNo,
          localStatus: order.status,
          jazzcash: null,
          warning: 'live-inquiry-unavailable: ' + (result.error || 'unknown'),
        });
      }
      const data = result.data || {};
      // If JazzCash confirms payment, mark the order paid (same checks).
      if (data.pp_ResponseCode === '000' && String(data.pp_Amount || '') === String(order.amountPaisas)) {
        if (order.status !== 'paid') markOrder(order, 'paid', { ppResponseCode: '000' });
      }
      return sendJson(res, 200, {
        ok: true,
        txnRefNo,
        localStatus: order.status,
        jazzcash: data,
      });
    });
    return;
  }

  // ---- GET /admin/setup (form) — token protected
  if (req.method === 'GET' && pathname === '/admin/setup') {
    const token = url.searchParams.get('token') || '';
    if (token !== SETUP_TOKEN) {
      return sendHtml(
        res,
        403,
        pageShell(
          'Setup locked',
          '<h1>Setup token chahiye</h1><p>Ye page sirf setup token ke saath khulta hai. ' +
            'Token sirf server ke console/log me likha hota hai (server start hote waqt).</p>'
        )
      );
    }
    const already = configFileExists() || config.fromFile;
    const inner =
      '<h1>JazzCash Setup</h1>' +
      '<p><b>Credentials sirf isi server par save hongi</b> — na chat me, na kisi file share me, na page ke code me. ' +
      'Ye form server ke apne config me likhta hai (0600 permissions).</p>' +
      (already
        ? '<p class="note">Credentials pehle se save hain. Naye values daalne par purani overwrite ho jayengi.</p>'
        : '') +
      '<form method="POST" action="/admin/setup">' +
      '<input type="hidden" name="token" value="' + escapeHtml(token) + '">' +
      '<label>Merchant ID</label><input name="merchantId" required autocomplete="off" placeholder="e.g. MC12345">' +
      '<label>Merchant Password</label><input type="password" name="password" required autocomplete="off">' +
      '<label>Integrity Salt</label><input type="password" name="integritySalt" required autocomplete="off">' +
      '<label>Environment</label><select name="env"><option value="sandbox">Sandbox (testing)</option>' +
      '<option value="production">Production (live payments)</option></select>' +
      '<label>Public server URL (Return URL ke liye — misal: https://pay.example.com)</label>' +
      '<input name="baseUrl" required placeholder="https://your-server-url" value="' +
      escapeHtml(config.baseUrl) + '">' +
      '<button class="btn" type="submit">Save Credentials</button></form>' +
      '<p class="note">Save karne ke baad apne JazzCash merchant portal me Return URL register karein: ' +
      '<code>' + escapeHtml((config.baseUrl || '').replace(/\/$/, '') + '/pay/return') + '</code></p>';
    return sendHtml(res, 200, pageShell('JazzCash Setup', inner));
  }

  // ---- POST /admin/setup (save)
  if (req.method === 'POST' && pathname === '/admin/setup') {
    readBody(req)
      .then((body) => {
        const f = parseFormBody(body, req.headers['content-type']);
        if ((f.token || '') !== SETUP_TOKEN) {
          return sendHtml(res, 403, pageShell('Setup locked', '<h1>Ghalat ya missing token</h1>'));
        }
        const merchantId = String(f.merchantId || '').trim();
        const password = String(f.password || '').trim();
        const integritySalt = String(f.integritySalt || '').trim();
        const baseUrl = String(f.baseUrl || '').trim();
        if (!merchantId || !password || !integritySalt || !baseUrl) {
          return sendHtml(res, 400, pageShell('Missing fields', '<h1>Sab fields zaroori hain</h1><p>Merchant ID, Password, Integrity Salt aur public server URL — koi bhi khali na chhorein.</p>'));
        }
        saveConfigFile({
          merchantId,
          password,
          integritySalt,
          env: f.env === 'production' ? 'production' : 'sandbox',
          baseUrl,
        });
        config = loadConfig();
        // NOTE: the values themselves are never printed or logged.
        console.log('[setup] credentials saved (env=' + config.env + '). Configured: ' + config.configured);
        return sendHtml(
          res,
          200,
          pageShell(
            'Setup saved',
            '<h1 class="ok">Credentials save ho gayi ✓</h1>' +
              '<p>Environment: <code>' + escapeHtml(config.env) + '</code></p>' +
              '<p>Ab JazzCash merchant portal me Return URL register karein:</p>' +
              '<p><code>' + escapeHtml(config.baseUrl.replace(/\/$/, '') + '/pay/return') + '</code></p>' +
              '<p>Phir test payment karein: <a style="color:#00e676" href="/pay/t20-wc-2024-patch">T20 World Cup Patch</a></p>'
          )
        );
      })
      .catch(() => sendHtml(res, 400, pageShell('Error', '<h1>Invalid request</h1>')));
    return;
  }

  // ---- 404
  sendHtml(res, 404, pageShell('Not found', '<h1>Page nahi mila</h1><p><a style="color:#00e676" href="/">Home</a></p>'));
}

if (require.main === module) {
  const server = http.createServer(handleRequest);
  server.listen(PORT, () => {
    console.log('------------------------------------------------------------');
    console.log('MUZAMIL STUFF JazzCash payment server');
    console.log('Listening on port ' + PORT);
    console.log('Environment : ' + config.env + ' (' + (config.env === 'production' ? 'payments' : 'sandbox') + '.jazzcash.com.pk)');
    console.log('Configured  : ' + (config.configured ? 'YES (credentials loaded)' : 'NO — open /admin/setup with the token below'));
    console.log('Base URL    : ' + config.baseUrl);
    console.log('Products    : ' + Object.keys(PRODUCTS).join(', '));
    console.log('------------------------------------------------------------');
    console.log('SETUP TOKEN (console only — kisi ko na bhejein): ' + SETUP_TOKEN);
    console.log('Setup page  : /admin/setup?token=<token>');
    console.log('------------------------------------------------------------');
  });
}

module.exports = { computeSecureHash, verifySecureHash, txnDateTime };
