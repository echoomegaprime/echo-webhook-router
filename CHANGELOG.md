# Changelog

## Unreleased -- consolidation pass (2026-08-11)

### Fixed
- Constant-time comparison for every signature/token check (GitHub, Stripe, Slack, Telegram,
  Meta/WhatsApp/Messenger, Vercel, plus the management `X-Echo-API-Key`) -- previously all raw
  `===`/`!==`, a timing side channel on internet-facing HMAC verification.
- The `hasSecret` reject-on-failure gate only covered github/stripe/slack; a configured
  `TELEGRAM_WEBHOOK_SECRET`, `META_APP_SECRET` (whatsapp/messenger), or
  `VERCEL_WEBHOOK_SECRET` was verified but never enforced -- a forged webhook for those four
  sources was accepted and routed even when the secret was correctly configured. Now enforced
  for all six secret-bearing sources.

### Added
- `tests/auth.test.mjs` -- 12 tests covering the management-API auth gate, per-source
  signature enforcement (positive and negative cases for GitHub/Telegram/WhatsApp/Vercel), the
  unconfigured-secret pass-through contract (unchanged, intentional), and the WhatsApp GET
  verification challenge.
- Full governance set (README, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, LICENSE, CI).

## 1.1.0 -- original release

Universal inbound webhook hub: 12+ source integrations, D1-backed delivery/route/stats
logging, exponential-backoff retry queue, hourly retry cron + daily log pruning.
