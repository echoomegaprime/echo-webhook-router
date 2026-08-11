# Security policy

Echo Webhook Router is a Cloudflare Worker (D1 + KV + Analytics Engine) that is the fleet's
single inbound gateway for external webhooks from GitHub, Vercel, Stripe, Cloudflare,
Telegram, Slack, WhatsApp, Messenger, LinkedIn, Twilio, and custom sources. It verifies
signatures, then routes and delivers the payload to internal Worker service bindings.

## Fixed in this consolidation pass

1. **Every signature/token comparison used a raw `===`/`!==`.** This is a timing side channel
   in general, but a more severe one here than the usual internal-API-key case: these are
   internet-facing HMAC signature checks (GitHub `x-hub-signature-256`, Stripe
   `stripe-signature`, Slack `x-slack-signature`, Meta `x-hub-signature-256` for
   WhatsApp/Messenger, Vercel `x-vercel-signature`, Telegram's secret token, the WhatsApp/Meta
   GET verification-challenge token) with no IP restriction, reachable by anyone on the
   internet. Replaced all of them, plus the management `X-Echo-API-Key` check, with a
   constant-time `timingSafeEqual`.
2. **Real logic bug: the reject-on-failure gate only covered `github`/`stripe`/`slack`.**
   `verifyWebhook()` correctly verifies every source with a configurable secret (Telegram,
   WhatsApp/Messenger via `META_APP_SECRET`, Vercel included), and a failed verification is
   logged as a warning -- but the code that actually returns `401` on failure
   (`const hasSecret = ...`) only checked three of the six secret-bearing sources. A forged
   Telegram/WhatsApp/Messenger/Vercel webhook, with a wrong or missing signature, was logged
   as "verification failed" and then **delivered and routed anyway**, even when the operator
   had correctly configured `TELEGRAM_WEBHOOK_SECRET` / `META_APP_SECRET` /
   `VERCEL_WEBHOOK_SECRET` specifically to prevent that. Extended the gate to cover all six
   sources. Sources with no secret configured at all continue to pass through unverified --
   that part of the design (secrets are optional, provisioned per source over time) is
   unchanged and intentional.

## Supported version

Security fixes target the current `main` branch. Historical commits are retained for evidence
and are not patched in place.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability. Send a private report to
`security@echo-op.com` with:

- affected source/endpoint and exact revision;
- reproduction steps and expected impact (this service is the fleet's single point of entry
  for inbound webhooks and fans out to a dozen internal Worker service bindings -- treat any
  signature-verification bypass as high severity);
- safe contact details for follow-up.

Never include a live `ECHO_API_KEY` or any per-source webhook secret in a report.
