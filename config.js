'use strict';
/**
 * config.js — JazzCash credential + settings loader.
 *
 * Precedence: environment variables win over server-config.json.
 * NEVER put real credentials in this file, in products.json, or in any
 * file in this directory. Credentials live only in:
 *   1. environment variables on the deploy host, or
 *   2. server-config.json (0600 permissions), written by /admin/setup.
 *
 * server-config.json is gitignored and must never be committed, copied
 * into chat, or pasted into a page.
 */
const fs = require('fs');
const path = require('path');

const CONFIG_FILE = path.join(__dirname, 'server-config.json');

function readConfigFile() {
  try {
    if (!fs.existsSync(CONFIG_FILE)) return {};
    const raw = fs.readFileSync(CONFIG_FILE, 'utf8');
    const data = JSON.parse(raw);
    return data && typeof data === 'object' ? data : {};
  } catch (e) {
    return {};
  }
}

function loadConfig() {
  const file = readConfigFile();
  const cfg = {
    merchantId: process.env.JAZZCASH_MERCHANT_ID || file.merchantId || '',
    password: process.env.JAZZCASH_PASSWORD || file.password || '',
    integritySalt: process.env.JAZZCASH_INTEGRITY_SALT || file.integritySalt || '',
    env: (process.env.JAZZCASH_ENV || file.env || 'sandbox').toLowerCase(),
    baseUrl:
      process.env.BASE_URL ||
      file.baseUrl ||
      ('http://localhost:' + (process.env.PORT || 3000)),
    port: parseInt(process.env.PORT || '3000', 10),
    setupTokenEnv: process.env.SETUP_TOKEN || '',
  };
  if (cfg.env !== 'sandbox' && cfg.env !== 'production') cfg.env = 'sandbox';
  cfg.configured = Boolean(cfg.merchantId && cfg.password && cfg.integritySalt);
  cfg.fromFile = Boolean(file.merchantId || file.password || file.integritySalt);
  return cfg;
}

function configFileExists() {
  return fs.existsSync(CONFIG_FILE);
}

/** Save credentials to server-config.json with 0600 permissions. */
function saveConfigFile(data) {
  const toSave = {
    merchantId: String(data.merchantId || '').trim(),
    password: String(data.password || '').trim(),
    integritySalt: String(data.integritySalt || '').trim(),
    env: data.env === 'production' ? 'production' : 'sandbox',
    baseUrl: String(data.baseUrl || '').trim(),
  };
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(toSave, null, 2) + '\n', {
    encoding: 'utf8',
    mode: 0o600,
  });
  // Enforce 0600 even if the file already existed with looser perms.
  try {
    fs.chmodSync(CONFIG_FILE, 0o600);
  } catch (e) {
    /* ignore */
  }
  return toSave;
}

const HOSTS = {
  sandbox: 'sandbox.jazzcash.com.pk',
  production: 'payments.jazzcash.com.pk',
};

function jazzcashHost(env) {
  return HOSTS[env] || HOSTS.sandbox;
}

function merchantFormUrl(env) {
  return 'https://' + jazzcashHost(env) + '/CustomerPortal/transactionmanagement/merchantform/';
}

function inquiryUrl(env) {
  return 'https://' + jazzcashHost(env) + '/ApplicationAPI/API/PaymentInquiry/Inquire';
}

module.exports = {
  loadConfig,
  saveConfigFile,
  configFileExists,
  jazzcashHost,
  merchantFormUrl,
  inquiryUrl,
  CONFIG_FILE,
};
