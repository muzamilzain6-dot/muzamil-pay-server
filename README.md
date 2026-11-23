# MUZAMIL STUFF — JazzCash Payment Server

A tiny payment server for the blog's paid downloads. Pure **Node.js with
zero npm dependencies** (only built-in `http` / `crypto` / `fs`), so it
runs anywhere Node runs.

**Why a server is needed:** the blog pages are static HTML. The JazzCash
Integrity Salt must never be in page JavaScript — anyone could read it
and forge "paid" confirmations. This server builds the signed payment
form and verifies JazzCash's reply, using the salt only on the server.

## Products (Rs. 200 each — price comes from `products.json`, never the browser)

| Product ID | Product | Download |
|---|---|---|
| `t20-wc-2024-patch` | ICC Mens T20 WorldCup Patch 2024 — EA Cricket 07 | https://clksz.com/MUZAMIL (password `MUZAMILx2024`) |
| `wi-2026-kit` | West Indies 2026 Kit — Buy & Download | **Not on file yet** — see note below |

> **wi-2026-kit download URL:** the existing demo page
> (`auto-delivery-page.html`) never contained a download link — it
> expected the backend to supply it. No URL has been invented here.
> After a successful payment for this product, the buyer sees a
> WhatsApp message instead of a download button until the owner adds
> the real URL to `products.json` (`downloadUrl` field).

## Files

| File | What it is |
|---|---|
| `server.js` | The server (endpoints, hashing, order handling, setup page). |
| `config.js` | Loads credentials from env vars or `server-config.json`. |
| `products.json` | The two products, prices, download links. No credentials. |
| `test-self.js` | Built-in self-test — `node test-self.js` (30 checks). |
| `.env.example` | Placeholder values only. Never real credentials. |
| `.gitignore` | Keeps `server-config.json`, `orders.json`, `.env` out of git. |

`server-config.json` and `orders.json` are created at runtime and are
**not** part of the delivery — they hold secrets / order history.

## Endpoints

| Endpoint | What it does |
|---|---|
| `GET /` | Product list with Buy links. |
| `GET /health` | `{ ok, env, configured }` — quick check the server is up. |
| `GET /pay/:productId` | Payment-start page (name, Rs. 200, JazzCash button). |
| `POST /pay/:productId` | Creates the order and auto-submits a **signed** form to JazzCash's hosted checkout (sandbox or production by config). Amount is always 20000 paisas from `products.json`. |
| `POST /pay/return` | JazzCash redirects the buyer here. Verifies `pp_SecureHash`, checks `pp_ResponseCode` = `000` and the amount against the order. Success → download page (link + file password). Failure → failed/cancelled page with a retry link. |
| `POST /pay/notify` | Optional server-to-server notification from JazzCash. Same verification, returns JSON. |
| `GET /pay/status/:txnRefNo` | Checks a transaction with the JazzCash Payment Inquiry API and returns JSON. If the live inquiry is unreachable it still reports the local order status. |
| `GET /admin/setup?token=…` | One-time credential setup page (see below). |
| `POST /admin/setup` | Saves credentials to `server-config.json` (0600 permissions). |

Orders are logged to `orders.json` (txn ref, product, amount, status,
timestamp). **Credentials and hashes are never logged.**

## Run locally

```bash
cd jazzcash-server
node server.js
# Listening on port 3000 — open http://localhost:3000
```

With no credentials configured the server still starts; payment pages
show "payments not set up" until credentials are entered.

Run the self-test (uses dummy credentials in-process only, never
written to disk):

```bash
node test-self.js
# 30 passed, 0 failed
```

What the self-test proves:
- The hash function matches JazzCash's documented algorithm, checked
  against an independent re-implementation (sorted `pp_` fields,
  values joined with `&`, Integrity Salt prepended, HMAC-SHA256,
  UPPERCASE hex) — including that empty fields are excluded and that
  changing one field breaks verification.
- The full local flow: start page → signed checkout form (amount
  20000 paisas, ReturnURL pointing at the server) → a simulated
  signed JazzCash return unlocks the download page with the correct
  link and password → a tampered return is rejected with no link.
- A forged replay cannot downgrade an already-paid order.
- `/admin/setup` refuses without the token and renders with it.

## Deploy (Render free tier — primary example)

Render's free web service sleeps when idle; for a low-traffic blog
that is acceptable (first visit after sleep takes ~30–60s to wake).

1. Put these files in a GitHub repo (do **not** include
   `server-config.json` / `orders.json` — they are gitignored).
2. Render dashboard → **New +** → **Web Service** → pick the repo.
3. Runtime: **Node**. Build command: *(leave empty — no dependencies)*.
   Start command: `node server.js`.
4. Environment variables (Render → Environment):
   - `JAZZCASH_ENV` = `sandbox` (test first), later `production`
   - `BASE_URL` = `https://<your-service>.onrender.com` (your public URL)
   - `PORT` = Render sets this itself; the server reads it.
   - Do **not** put credentials in env vars on a shared screen — use
     `/admin/setup` below instead (or set them as secret env vars).
5. Deploy. Note the public URL, e.g. `https://muzamil-pay.onrender.com`.

**Any free Node host works the same way** (Railway, Fly.io, a VPS):
Node 18+, these files, `node server.js`, a public HTTPS URL.

## Enter credentials — /admin/setup (never in chat)

1. Start the server. It prints a random **setup token to its own
   console/log only** (and nowhere else).
2. Open `https://<your-server>/admin/setup?token=<token>`.
3. Enter **Merchant ID, Password, Integrity Salt** and pick the
   environment (**sandbox** first), plus the public server URL.
4. Save. Credentials are written to `server-config.json` on that
   server only, with 0600 permissions. The page refuses to run once
   credentials are saved unless the current startup token is
   presented again.
5. To change credentials later, restart the server (new token is
   printed) and open the setup page again.

## Register the Return URL in the JazzCash merchant portal

JazzCash only returns buyers to a pre-registered URL. In the JazzCash
merchant portal, register:

```
https://<your-server>/pay/return
```

Use the sandbox portal/host for sandbox testing, the production
portal for live payments. The server will not work with a Return URL
JazzCash does not recognise.

## Test before going live

1. Set `JAZZCASH_ENV=sandbox` and enter the **sandbox** merchant
   credentials (from the JazzCash portal) via `/admin/setup`.
2. Open `https://<your-server>/pay/t20-wc-2024-patch` and pay with a
   JazzCash sandbox test wallet.
3. You must land on the download page with the link and password.
4. Only then switch to `production` and re-enter the **production**
   credentials.

**Sandbox test credentials:** no officially published JazzCash sandbox
test Merchant ID / Password / Salt were found in the public JazzCash
documentation checked while building this. Unofficial guides floating
around show sample values — do not treat those as real credentials.
Use the sandbox credentials issued for your own merchant account
(JazzCash portal), and rely on `node test-self.js` for local
verification without them.

## Wiring the blog pages (comes after deployment — not done here)

Once the server is deployed and tested, each paid page's **Buy Now**
button points at the server instead of opening a payment sheet:

```
T20 World Cup Patch page :  <server-url>/pay/t20-wc-2024-patch
West Indies Kit page     :  <server-url>/pay/wi-2026-kit
```

The existing auto-delivery page already expects this shape — its
`BACKEND_URL` becomes the server URL (its `/create-payment` flow is
replaced by a plain link/redirect to `/pay/<productId>` when the pages
are rewired). The T20 patch product page (preview artifact) gets the
same treatment. **Neither page has been edited here** — wiring is a
separate step after the server is live, and publishing to the live
blog still needs the owner's Blogger login.

## Honest limits

- **Manual WhatsApp fallback remains.** If a buyer's JazzCash payment
  fails, times out, or JazzCash is down, the buyer gets a failure page
  with a WhatsApp link. The owner confirms the payment from the
  JazzCash app / screenshot and shares the link manually — exactly
  like the current manual flow.
- **Render free tier sleeps.** First payment attempt after idle can
  take ~30–60s to wake the server. A paid tier (or a VPS) removes this.
- **Refunds / disputes** are handled in the JazzCash merchant portal,
  not by this server. This server only records orders in `orders.json`.
- **Return URL must be HTTPS and pre-registered** — JazzCash rejects
  unknown return URLs.
- **PGW v1.1 note:** JazzCash's newer gateway docs require a
  `pp_SubMerchantName` field (letters only, no spaces) in transaction
  requests. The classic hosted form used here does not require it. If
  JazzCash returns an error asking for it, add `pp_SubMerchantName`
  (e.g. `MuzamilStuff`) to the form fields in `server.js` — it is
  automatically included in the hash because it starts with `pp_`.

## Security notes

- The Integrity Salt and merchant Password are used only inside
  `server.js` / `config.js`. They are never sent to a browser, never
  logged, never written to `products.json`, and never appear in any URL.
- Amounts are taken from `products.json` on the server. A buyer cannot
  change the price by editing the page or the request.
- The download link is only shown after hash verification, response
  code `000`, and an amount match against a real pending order.
- Keep `server-config.json` (0600) and `orders.json` on the server
  only. Never email, chat, or commit them.
