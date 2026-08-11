import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/index.ts';

function makeD1() {
  const stmt = {
    bind() { return stmt; },
    async run() { return { success: true }; },
    async all() { return { results: [] }; },
    async first() { return { count: 0 }; },
  };
  return { prepare() { return stmt; } };
}

function makeEnv(overrides = {}) {
  return {
    DB: makeD1(),
    CACHE: { get: async () => null, put: async () => {}, delete: async () => {} },
    SHARED_BRAIN: { fetch: async () => new Response('ok') },
    SWARM_BRAIN: { fetch: async () => new Response('ok') },
    X_BOT: { fetch: async () => new Response('ok') },
    LINKEDIN: { fetch: async () => new Response('ok') },
    TELEGRAM: { fetch: async () => new Response('ok') },
    SLACK: { fetch: async () => new Response('ok') },
    REDDIT: { fetch: async () => new Response('ok') },
    INSTAGRAM: { fetch: async () => new Response('ok') },
    WHATSAPP: { fetch: async () => new Response('ok') },
    MESSENGER: { fetch: async () => new Response('ok') },
    QA_TESTER: { fetch: async () => new Response('ok') },
    ANALYTICS: { fetch: async () => new Response('ok') },
    FLEET_COMMANDER: { fetch: async () => new Response('ok') },
    DAEMON: { fetch: async () => new Response('ok') },
    BUILD_ORCHESTRATOR: { fetch: async () => new Response('ok') },
    ECHO_API_KEY: 'test-echo-webhook-router-key-4b7e',
    ...overrides,
  };
}

const ctx = { waitUntil() {}, passThroughOnException() {} };

async function hmacSha256(key, data) {
  const cryptoKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(data));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

test('management endpoints require the API key', async () => {
  const env = makeEnv();
  const req = new Request('https://x/routes', { method: 'GET' });
  const res = await worker.fetch(req, env, ctx);
  assert.equal(res.status, 401);
});

test('management endpoints reject the wrong key', async () => {
  const env = makeEnv();
  const req = new Request('https://x/routes', { method: 'GET', headers: { 'X-Echo-API-Key': 'wrong' } });
  const res = await worker.fetch(req, env, ctx);
  assert.equal(res.status, 401);
});

test('management endpoints pass with the correct key', async () => {
  const env = makeEnv();
  const req = new Request('https://x/routes', { method: 'GET', headers: { 'X-Echo-API-Key': 'test-echo-webhook-router-key-4b7e' } });
  const res = await worker.fetch(req, env, ctx);
  assert.notEqual(res.status, 401);
});

test('GET /health and / need no auth (unchanged public contract)', async () => {
  const env = makeEnv();
  for (const p of ['/', '/health']) {
    const res = await worker.fetch(new Request('https://x' + p), env, ctx);
    assert.notEqual(res.status, 401);
  }
});

test('a Telegram webhook with a WRONG secret token is now rejected when TELEGRAM_WEBHOOK_SECRET is configured', async () => {
  const env = makeEnv({ TELEGRAM_WEBHOOK_SECRET: 'real-secret' });
  const req = new Request('https://x/hook/telegram/message', {
    method: 'POST',
    headers: { 'x-telegram-bot-api-secret-token': 'forged' },
    body: JSON.stringify({ test: true }),
  });
  const res = await worker.fetch(req, env, ctx);
  assert.equal(res.status, 401, 'a configured telegram secret must actually be enforced, not just logged');
});

test('a WhatsApp/Meta webhook with a WRONG signature is now rejected when META_APP_SECRET is configured', async () => {
  const env = makeEnv({ META_APP_SECRET: 'real-secret' });
  const req = new Request('https://x/hook/whatsapp/message', {
    method: 'POST',
    headers: { 'x-hub-signature-256': 'sha256=forged' },
    body: JSON.stringify({ test: true }),
  });
  const res = await worker.fetch(req, env, ctx);
  assert.equal(res.status, 401, 'a configured META_APP_SECRET must actually be enforced for whatsapp, not just logged');
});

test('a Vercel webhook with a WRONG signature is now rejected when VERCEL_WEBHOOK_SECRET is configured', async () => {
  const env = makeEnv({ VERCEL_WEBHOOK_SECRET: 'real-secret' });
  const req = new Request('https://x/hook/vercel/deployment', {
    method: 'POST',
    headers: { 'x-vercel-signature': 'forged' },
    body: JSON.stringify({ test: true }),
  });
  const res = await worker.fetch(req, env, ctx);
  assert.equal(res.status, 401, 'a configured vercel secret must actually be enforced, not just logged');
});

test('a GitHub webhook with the CORRECT signature is accepted when GITHUB_WEBHOOK_SECRET is configured', async () => {
  const secret = 'real-secret';
  const env = makeEnv({ GITHUB_WEBHOOK_SECRET: secret });
  const body = JSON.stringify({ repository: { full_name: 'x/y' }, ref: 'refs/heads/main', commits: [] });
  const sig = 'sha256=' + await hmacSha256(secret, body);
  const req = new Request('https://x/hook/github/push', {
    method: 'POST',
    headers: { 'x-hub-signature-256': sig, 'x-github-event': 'push' },
    body,
  });
  const res = await worker.fetch(req, env, ctx);
  assert.notEqual(res.status, 401);
  const json = await res.json();
  assert.equal(json.received, true);
});

test('a GitHub webhook with a WRONG signature is rejected when GITHUB_WEBHOOK_SECRET is configured', async () => {
  const env = makeEnv({ GITHUB_WEBHOOK_SECRET: 'real-secret' });
  const req = new Request('https://x/hook/github/push', {
    method: 'POST',
    headers: { 'x-hub-signature-256': 'sha256=forged', 'x-github-event': 'push' },
    body: JSON.stringify({ repository: { full_name: 'x/y' } }),
  });
  const res = await worker.fetch(req, env, ctx);
  assert.equal(res.status, 401);
});

test('a webhook source with NO secret configured still passes through unverified (unchanged graceful-degradation contract)', async () => {
  const env = makeEnv();
  const req = new Request('https://x/hook/telegram/message', {
    method: 'POST',
    headers: {},
    body: JSON.stringify({ test: true }),
  });
  const res = await worker.fetch(req, env, ctx);
  assert.notEqual(res.status, 401, 'without a configured secret, telegram must still be accepted (secret is optional)');
});

test('WhatsApp GET verification challenge still uses constant-time comparison and still works for the correct token', async () => {
  const env = makeEnv({ WHATSAPP_VERIFY_TOKEN: 'verify-me' });
  const req = new Request('https://x/hook/whatsapp?hub.mode=subscribe&hub.verify_token=verify-me&hub.challenge=echo123');
  const res = await worker.fetch(req, env, ctx);
  assert.equal(res.status, 200);
  const text = await res.text();
  assert.equal(text, 'echo123');
});

test('WhatsApp GET verification challenge rejects the wrong token', async () => {
  const env = makeEnv({ WHATSAPP_VERIFY_TOKEN: 'verify-me' });
  const req = new Request('https://x/hook/whatsapp?hub.mode=subscribe&hub.verify_token=wrong&hub.challenge=echo123');
  const res = await worker.fetch(req, env, ctx);
  assert.equal(res.status, 403);
});
