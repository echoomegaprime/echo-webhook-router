# Echo Webhook Router

Universal inbound event hub for the ECHO OMEGA PRIME fleet -- Cloudflare Worker (D1 + KV +
Analytics Engine). Single entry point for external webhooks (GitHub, Vercel, Stripe,
Cloudflare, Telegram, Slack, WhatsApp, Messenger, LinkedIn, Twilio, and custom sources):
verifies signatures, normalizes payloads, routes to the correct internal worker binding,
logs every delivery, and retries failures with exponential backoff.

Not to be confused with **echo-webhook-relay** -- a separate, architecturally distinct
service (fanout + subscriber management, its own `echo.webhookrelay.*` SDK namespace) with
its own live FORGE deployment. This repo (`echo-webhook-router`) has no SDK namespace
collision; see `.echo/sdk.json`.

## Endpoints

| Access | Method | Path | Description |
|---|---|---|---|
| Public | GET | `/`, `/health` | Service info / health + pending-retry count |
| Public | POST | `/hook/:source/:channel` | Inbound webhook (see Authentication below) |
| Public | GET | `/hook/:source` | Verification challenges (WhatsApp/Messenger `hub.challenge`) |
| Authenticated | GET/POST | `/routes`, `/routes/delete` | Manage custom routing rules |
| Authenticated | GET | `/logs/webhooks`, `/logs/deliveries`, `/logs/failed` | Delivery history |
| Authenticated | GET | `/stats`, `/stats/daily` | Per-source delivery stats |
| Authenticated | POST | `/retry`, `/test` | Trigger a retry cycle / send a synthetic test webhook |

## Authentication

Management endpoints require `X-Echo-API-Key`, compared to `env.ECHO_API_KEY` in constant
time. Inbound webhooks are verified per-source (HMAC-SHA256 for GitHub/Stripe/Slack/Meta,
HMAC-SHA1 for Vercel, a shared secret token for Telegram, all constant-time comparisons) --
**a source is only rejected on a bad signature when its secret is actually configured**; an
unconfigured source passes through unverified by design (secrets are optional, added per
source as they're provisioned). See [SECURITY.md](SECURITY.md) for what changed in this
consolidation pass -- every source with a configurable secret is now actually enforced.

## Verify

```powershell
npm install
npm test
```

## Security

This service is the fleet's single inbound webhook gateway. See [SECURITY.md](SECURITY.md)
to report a vulnerability -- never as a public issue.

## License

See [LICENSE](LICENSE). Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md).
