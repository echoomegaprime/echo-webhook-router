# Contributing

Thank you for improving Echo Webhook Router. This is a public, proprietary infrastructure
project: contributions are welcome for review, but repository visibility does not grant a
general use or redistribution license.

## Development path

1. Open an issue describing the behavior being changed.
2. Create a focused branch from current `main`.
3. Add a failing test before changing any signature-verification function, `timingSafeEqual`,
   or the `hasSecret` reject gate in `handleWebhook()` -- see SECURITY.md for exactly what is
   enforced per source and why.
4. Validate before opening a pull request:

   ```powershell
   npm install
   npm test
   ```

5. Open a pull request using the repository template and include exact test output.

## Pull-request requirements

- No secrets (`ECHO_API_KEY`, any `*_WEBHOOK_SECRET`/`*_APP_SECRET`) are included.
- No stubs, placeholders, or self-asserted readiness -- this service is the fleet's single
  inbound webhook gateway.
- Any change to signature verification, `timingSafeEqual`, or which sources are enforced when
  their secret is configured is called out explicitly in the pull request description.
