/**
 * ECHO WEBHOOK ROUTER v1.1.0
 * Universal Inbound Event Hub for Echo Omega Prime
 *
 * Single entry point for ALL external webhooks. Verifies signatures,
 * normalizes payloads, routes to correct internal workers, logs everything,
 * retries failed deliveries, provides unified webhook management.
 *
 * Supported Sources: GitHub, Vercel, Stripe, Cloudflare, Telegram, Slack,
 *   WhatsApp, Messenger, LinkedIn, Discord, Twilio, SendGrid, Custom
 *
 * Pattern: POST /hook/:source/:channel → verify → normalize → route → log
 */

export interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  SHARED_BRAIN: Fetcher;
  SWARM_BRAIN: Fetcher;
  X_BOT: Fetcher;
  LINKEDIN: Fetcher;
  TELEGRAM: Fetcher;
  SLACK: Fetcher;
  REDDIT: Fetcher;
  INSTAGRAM: Fetcher;
  WHATSAPP: Fetcher;
  MESSENGER: Fetcher;
  QA_TESTER: Fetcher;
  ANALYTICS: Fetcher;
  FLEET_COMMANDER: Fetcher;
  DAEMON: Fetcher;
  BUILD_ORCHESTRATOR: Fetcher;
  ECHO_API_KEY: string;
  // Webhook verification secrets (per source)
  GITHUB_WEBHOOK_SECRET?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  SLACK_SIGNING_SECRET?: string;
  TELEGRAM_WEBHOOK_SECRET?: string;
  WHATSAPP_VERIFY_TOKEN?: string;
  META_APP_SECRET?: string;
  VERCEL_WEBHOOK_SECRET?: string;
}

// ── Logging ──────────────────────────────────────────────────────────────────

function log(level: string, msg: string, data?: Record<string, unknown>): void {
  const entry = { ts: new Date().toISOString(), level, service: 'echo-webhook-router', msg, ...data };
  if (level === 'error') console.error(JSON.stringify(entry));
  else console.log(JSON.stringify(entry));
}

// ── Types ────────────────────────────────────────────────────────────────────

interface WebhookRoute {
  source: string;
  channel: string;
  targetBinding: string;
  targetPath: string;
  verifyMethod: 'hmac-sha256' | 'hmac-sha1' | 'bearer' | 'challenge-response' | 'none';
  secretKey?: string;
  headerName?: string;
  active: boolean;
  description: string;
}

interface DeliveryLog {
  webhookId: string;
  source: string;
  channel: string;
  target: string;
  status: 'delivered' | 'failed' | 'retrying' | 'dropped';
  statusCode: number;
  latencyMs: number;
  retryCount: number;
  error?: string;
}

// ── Schema ───────────────────────────────────────────────────────────────────

async function ensureSchema(db: D1Database): Promise<void> {
  const stmts = [
    `CREATE TABLE IF NOT EXISTS webhook_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      webhook_id TEXT NOT NULL UNIQUE,
      source TEXT NOT NULL,
      channel TEXT NOT NULL,
      method TEXT NOT NULL,
      path TEXT NOT NULL,
      headers TEXT DEFAULT '{}',
      body_hash TEXT,
      body_size INTEGER DEFAULT 0,
      ip TEXT,
      user_agent TEXT,
      verified INTEGER DEFAULT 0,
      received_at TEXT DEFAULT (datetime('now'))
    )`,
    `CREATE INDEX IF NOT EXISTS idx_wh_source ON webhook_log(source, received_at DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_wh_time ON webhook_log(received_at DESC)`,

    `CREATE TABLE IF NOT EXISTS delivery_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      webhook_id TEXT NOT NULL,
      source TEXT NOT NULL,
      channel TEXT NOT NULL,
      target_binding TEXT NOT NULL,
      target_path TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      status_code INTEGER DEFAULT 0,
      latency_ms INTEGER DEFAULT 0,
      retry_count INTEGER DEFAULT 0,
      error TEXT,
      response_preview TEXT,
      delivered_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(webhook_id) REFERENCES webhook_log(webhook_id)
    )`,
    `CREATE INDEX IF NOT EXISTS idx_del_status ON delivery_log(status, delivered_at DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_del_webhook ON delivery_log(webhook_id)`,

    `CREATE TABLE IF NOT EXISTS routes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source TEXT NOT NULL,
      channel TEXT NOT NULL,
      target_binding TEXT NOT NULL,
      target_path TEXT NOT NULL,
      verify_method TEXT DEFAULT 'none',
      secret_env_key TEXT,
      header_name TEXT,
      active INTEGER DEFAULT 1,
      description TEXT DEFAULT '',
      priority INTEGER DEFAULT 0,
      transform TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      UNIQUE(source, channel, target_binding)
    )`,
    `CREATE INDEX IF NOT EXISTS idx_routes_source ON routes(source, channel, active)`,

    `CREATE TABLE IF NOT EXISTS failed_deliveries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      webhook_id TEXT NOT NULL,
      source TEXT NOT NULL,
      channel TEXT NOT NULL,
      target_binding TEXT NOT NULL,
      target_path TEXT NOT NULL,
      body TEXT NOT NULL,
      headers TEXT DEFAULT '{}',
      retry_count INTEGER DEFAULT 0,
      max_retries INTEGER DEFAULT 3,
      next_retry_at TEXT,
      error TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )`,
    `CREATE INDEX IF NOT EXISTS idx_failed_retry ON failed_deliveries(next_retry_at, retry_count)`,

    `CREATE TABLE IF NOT EXISTS stats (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source TEXT NOT NULL,
      date TEXT NOT NULL,
      received INTEGER DEFAULT 0,
      delivered INTEGER DEFAULT 0,
      failed INTEGER DEFAULT 0,
      avg_latency_ms REAL DEFAULT 0,
      UNIQUE(source, date)
    )`,
    `CREATE INDEX IF NOT EXISTS idx_stats_date ON stats(date DESC, source)`,
  ];

  for (const sql of stmts) {
    try { await db.prepare(sql).run(); } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      if (!msg.includes('already exists')) log('error', 'Schema error', { sql: sql.slice(0, 80), error: msg });
    }
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
    },
  });
}

function timingSafeEqual(a: string | undefined | null, b: string | undefined | null): boolean {
  if (!a || !b) return false;
  const enc = new TextEncoder();
  const bufA = enc.encode(a);
  const bufB = enc.encode(b);
  const len = Math.max(bufA.length, bufB.length, 1);
  const padA = new Uint8Array(len);
  const padB = new Uint8Array(len);
  padA.set(bufA);
  padB.set(bufB);
  let diff = bufA.length ^ bufB.length;
  for (let i = 0; i < len; i++) diff |= padA[i] ^ padB[i];
  return diff === 0;
}

function generateId(): string {
  return `wh_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

async function sha256(data: string): Promise<string> {
  const buffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
  return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacSha256(key: string, data: string): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(data));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacSha1(key: string, data: string): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(key), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(data));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Signature Verification ───────────────────────────────────────────────────

async function verifyGitHub(body: string, signature: string | null, secret: string): Promise<boolean> {
  if (!signature) return false;
  const expected = 'sha256=' + await hmacSha256(secret, body);
  return timingSafeEqual(expected, signature);
}

async function verifyStripe(body: string, sigHeader: string | null, secret: string): Promise<boolean> {
  if (!sigHeader) return false;
  const parts = sigHeader.split(',').reduce((acc, p) => {
    const [k, v] = p.split('=');
    acc[k] = v;
    return acc;
  }, {} as Record<string, string>);

  const timestamp = parts.t;
  const sig = parts.v1;
  if (!timestamp || !sig) return false;

  // Check timestamp freshness (5 minute tolerance)
  const age = Math.abs(Date.now() / 1000 - parseInt(timestamp));
  if (age > 300) return false;

  const payload = `${timestamp}.${body}`;
  const expected = await hmacSha256(secret, payload);
  return timingSafeEqual(expected, sig);
}

async function verifySlack(body: string, timestamp: string | null, signature: string | null, secret: string): Promise<boolean> {
  if (!timestamp || !signature) return false;
  const age = Math.abs(Date.now() / 1000 - parseInt(timestamp));
  if (age > 300) return false;

  const baseString = `v0:${timestamp}:${body}`;
  const expected = 'v0=' + await hmacSha256(secret, baseString);
  return timingSafeEqual(expected, signature);
}

function verifyTelegram(secretToken: string | null, expected: string): boolean {
  return timingSafeEqual(secretToken, expected);
}

async function verifyMeta(body: string, signature: string | null, secret: string): Promise<boolean> {
  if (!signature) return false;
  const expected = 'sha256=' + await hmacSha256(secret, body);
  return timingSafeEqual(expected, signature);
}

async function verifyVercel(body: string, signature: string | null, secret: string): Promise<boolean> {
  if (!signature) return false;
  const expected = await hmacSha1(secret, body);
  return timingSafeEqual(expected, signature);
}

async function verifyWebhook(source: string, request: Request, body: string, env: Env): Promise<boolean> {
  switch (source) {
    case 'github':
      return env.GITHUB_WEBHOOK_SECRET
        ? verifyGitHub(body, request.headers.get('x-hub-signature-256'), env.GITHUB_WEBHOOK_SECRET)
        : true;
    case 'stripe':
      return env.STRIPE_WEBHOOK_SECRET
        ? verifyStripe(body, request.headers.get('stripe-signature'), env.STRIPE_WEBHOOK_SECRET)
        : true;
    case 'slack':
      return env.SLACK_SIGNING_SECRET
        ? verifySlack(body, request.headers.get('x-slack-request-timestamp'), request.headers.get('x-slack-signature'), env.SLACK_SIGNING_SECRET)
        : true;
    case 'telegram':
      return env.TELEGRAM_WEBHOOK_SECRET
        ? verifyTelegram(request.headers.get('x-telegram-bot-api-secret-token'), env.TELEGRAM_WEBHOOK_SECRET)
        : true;
    case 'whatsapp':
    case 'messenger':
      return env.META_APP_SECRET
        ? verifyMeta(body, request.headers.get('x-hub-signature-256'), env.META_APP_SECRET)
        : true;
    case 'vercel':
      return env.VERCEL_WEBHOOK_SECRET
        ? verifyVercel(body, request.headers.get('x-vercel-signature'), env.VERCEL_WEBHOOK_SECRET)
        : true;
    default:
      return true; // Unknown sources pass through (custom routes handle their own auth)
  }
}

// ── Default Route Registry ───────────────────────────────────────────────────

const DEFAULT_ROUTES: WebhookRoute[] = [
  // GitHub → Shared Brain (ingest as context)
  // Note: x-github-event header overrides URL channel, so push/issues/PR all work from same URL
  { source: 'github', channel: 'push', targetBinding: 'SHARED_BRAIN', targetPath: '/ingest', verifyMethod: 'hmac-sha256', headerName: 'x-hub-signature-256', active: true, description: 'GitHub push events to shared brain' },
  { source: 'github', channel: 'issues', targetBinding: 'SHARED_BRAIN', targetPath: '/ingest', verifyMethod: 'hmac-sha256', active: true, description: 'GitHub issues to shared brain' },
  { source: 'github', channel: 'pull_request', targetBinding: 'SHARED_BRAIN', targetPath: '/ingest', verifyMethod: 'hmac-sha256', active: true, description: 'GitHub PRs to shared brain' },
  { source: 'github', channel: 'ping', targetBinding: 'SHARED_BRAIN', targetPath: '/ingest', verifyMethod: 'hmac-sha256', active: true, description: 'GitHub ping (webhook registration confirmation)' },

  // Vercel → fleet + analytics
  { source: 'vercel', channel: 'deployment', targetBinding: 'FLEET_COMMANDER', targetPath: '/webhook/vercel', verifyMethod: 'hmac-sha1', active: true, description: 'Vercel deploys to fleet commander' },
  { source: 'vercel', channel: 'deployment', targetBinding: 'ANALYTICS', targetPath: '/event', verifyMethod: 'hmac-sha1', active: true, description: 'Vercel deploys to analytics' },

  // Stripe → analytics
  { source: 'stripe', channel: 'payment', targetBinding: 'ANALYTICS', targetPath: '/event', verifyMethod: 'hmac-sha256', active: true, description: 'Stripe payment events to analytics' },

  // Telegram → telegram bot
  { source: 'telegram', channel: 'message', targetBinding: 'TELEGRAM', targetPath: '/webhook', verifyMethod: 'bearer', active: true, description: 'Telegram messages to telegram bot' },

  // Slack → slack bot
  { source: 'slack', channel: 'event', targetBinding: 'SLACK', targetPath: '/webhook', verifyMethod: 'hmac-sha256', active: true, description: 'Slack events to slack bot' },

  // WhatsApp → whatsapp worker
  { source: 'whatsapp', channel: 'message', targetBinding: 'WHATSAPP', targetPath: '/webhook', verifyMethod: 'hmac-sha256', active: true, description: 'WhatsApp messages to whatsapp worker' },

  // Messenger → messenger worker
  { source: 'messenger', channel: 'message', targetBinding: 'MESSENGER', targetPath: '/webhook', verifyMethod: 'hmac-sha256', active: true, description: 'Messenger messages to messenger worker' },

  // LinkedIn → linkedin bot
  { source: 'linkedin', channel: 'event', targetBinding: 'LINKEDIN', targetPath: '/webhook', verifyMethod: 'none', active: true, description: 'LinkedIn events to linkedin bot' },

  // Cloudflare → daemon
  { source: 'cloudflare', channel: 'notification', targetBinding: 'DAEMON', targetPath: '/webhook/cloudflare', verifyMethod: 'none', active: true, description: 'Cloudflare notifications to daemon' },

  // Twilio → analytics + brain
  { source: 'twilio', channel: 'sms', targetBinding: 'ANALYTICS', targetPath: '/event', verifyMethod: 'none', active: true, description: 'Twilio SMS events to analytics' },
  { source: 'twilio', channel: 'voice', targetBinding: 'ANALYTICS', targetPath: '/event', verifyMethod: 'none', active: true, description: 'Twilio voice events to analytics' },

  // Custom → brain (catch-all for custom integrations)
  { source: 'custom', channel: 'default', targetBinding: 'SHARED_BRAIN', targetPath: '/webhook/custom', verifyMethod: 'none', active: true, description: 'Custom webhook catch-all to shared brain' },
];

// ── Route Resolution ─────────────────────────────────────────────────────────

async function getRoutes(db: D1Database, cache: KVNamespace, source: string, channel: string): Promise<WebhookRoute[]> {
  // Check KV cache first
  const cacheKey = `routes:${source}:${channel}`;
  const cached = await cache.get(cacheKey, 'json') as WebhookRoute[] | null;
  if (cached) return cached;

  // Check D1 for custom routes
  const rows = await db.prepare(
    `SELECT * FROM routes WHERE source = ? AND (channel = ? OR channel = '*') AND active = 1 ORDER BY priority DESC`
  ).bind(source, channel).all<Record<string, unknown>>();

  let routes: WebhookRoute[] = [];

  if (rows.results && rows.results.length > 0) {
    routes = rows.results.map(r => ({
      source: r.source as string,
      channel: r.channel as string,
      targetBinding: r.target_binding as string,
      targetPath: r.target_path as string,
      verifyMethod: (r.verify_method as WebhookRoute['verifyMethod']) || 'none',
      secretKey: r.secret_env_key as string | undefined,
      headerName: r.header_name as string | undefined,
      active: true,
      description: r.description as string || '',
    }));
  }

  // Fall back to defaults if no custom routes
  if (routes.length === 0) {
    routes = DEFAULT_ROUTES.filter(r => r.source === source && (r.channel === channel || r.channel === '*'));
  }

  // Also check for wildcard source routes
  if (routes.length === 0) {
    routes = DEFAULT_ROUTES.filter(r => r.source === source && r.channel === 'default');
  }

  // Cache for 5 minutes
  if (routes.length > 0) {
    await cache.put(cacheKey, JSON.stringify(routes), { expirationTtl: 300 });
  }

  return routes;
}

// ── Delivery ─────────────────────────────────────────────────────────────────

function getBinding(env: Env, bindingName: string): Fetcher | null {
  const map: Record<string, Fetcher> = {
    SHARED_BRAIN: env.SHARED_BRAIN,
    SWARM_BRAIN: env.SWARM_BRAIN,
    X_BOT: env.X_BOT,
    LINKEDIN: env.LINKEDIN,
    TELEGRAM: env.TELEGRAM,
    SLACK: env.SLACK,
    REDDIT: env.REDDIT,
    INSTAGRAM: env.INSTAGRAM,
    WHATSAPP: env.WHATSAPP,
    MESSENGER: env.MESSENGER,
    QA_TESTER: env.QA_TESTER,
    ANALYTICS: env.ANALYTICS,
    FLEET_COMMANDER: env.FLEET_COMMANDER,
    DAEMON: env.DAEMON,
    BUILD_ORCHESTRATOR: env.BUILD_ORCHESTRATOR,
  };
  return map[bindingName] || null;
}

// ── Payload Transformer ──────────────────────────────────────────────────────
// Converts raw webhook payloads into the format the target endpoint expects.

function transformForIngest(source: string, channel: string, rawBody: string, headers: Record<string, string>): string {
  try {
    const payload = JSON.parse(rawBody);
    const event = headers['x-github-event'] || channel;

    if (source === 'github') {
      const repo = payload.repository?.full_name || 'unknown';
      let content = '';
      let importance = 3;
      const tags = ['webhook', 'github', event];

      if (event === 'push') {
        const branch = (payload.ref || '').replace('refs/heads/', '');
        const commits = payload.commits || [];
        const commitMsgs = commits.map((c: Record<string, unknown>) => `- ${(c.message as string || '').split('\n')[0]}`).join('\n');
        content = `[GitHub Push] ${repo} → ${branch} (${commits.length} commit${commits.length !== 1 ? 's' : ''})\n${commitMsgs}`;
        importance = branch === 'main' ? 5 : 3;
        tags.push(branch);
      } else if (event === 'issues') {
        const action = payload.action || 'unknown';
        const title = payload.issue?.title || '';
        content = `[GitHub Issue] ${repo} — ${action}: ${title}`;
        importance = 4;
      } else if (event === 'pull_request') {
        const action = payload.action || 'unknown';
        const title = payload.pull_request?.title || '';
        content = `[GitHub PR] ${repo} — ${action}: ${title}`;
        importance = 4;
      } else if (event === 'ping') {
        content = `[GitHub Ping] Webhook registered for ${repo}`;
        importance = 2;
      } else {
        content = `[GitHub ${event}] ${repo} — ${JSON.stringify(payload).slice(0, 500)}`;
      }

      return JSON.stringify({ content, source: 'webhook-router', instance_id: 'webhook-router', importance, tags });
    }

    if (source === 'stripe') {
      const type = payload.type || 'unknown';
      const amount = payload.data?.object?.amount ? `$${(payload.data.object.amount / 100).toFixed(2)}` : '';
      return JSON.stringify({
        content: `[Stripe] ${type} ${amount}`.trim(),
        source: 'webhook-router', instance_id: 'webhook-router',
        importance: type.includes('succeeded') ? 7 : 4,
        tags: ['webhook', 'stripe', 'revenue', type],
      });
    }

    if (source === 'vercel') {
      const name = payload.payload?.deployment?.name || payload.name || 'unknown';
      const state = payload.payload?.deployment?.readyState || payload.type || 'unknown';
      return JSON.stringify({
        content: `[Vercel Deploy] ${name} → ${state}`,
        source: 'webhook-router', instance_id: 'webhook-router',
        importance: 4,
        tags: ['webhook', 'vercel', 'deploy', name],
      });
    }

    // Default: wrap raw payload
    return JSON.stringify({
      content: `[Webhook ${source}/${channel}] ${rawBody.slice(0, 1000)}`,
      source: 'webhook-router', instance_id: 'webhook-router',
      importance: 3,
      tags: ['webhook', source, channel],
    });
  } catch {
    return JSON.stringify({
      content: `[Webhook ${source}/${channel}] ${rawBody.slice(0, 1000)}`,
      source: 'webhook-router', instance_id: 'webhook-router',
      importance: 3,
      tags: ['webhook', source, channel],
    });
  }
}

async function deliverWebhook(
  env: Env,
  route: WebhookRoute,
  webhookId: string,
  body: string,
  headers: Record<string, string>,
): Promise<DeliveryLog> {
  const start = Date.now();

  const binding = getBinding(env, route.targetBinding);
  if (!binding) {
    return {
      webhookId,
      source: route.source,
      channel: route.channel,
      target: `${route.targetBinding}${route.targetPath}`,
      status: 'failed',
      statusCode: 0,
      latencyMs: 0,
      retryCount: 0,
      error: `Unknown binding: ${route.targetBinding}`,
    };
  }

  // Transform payload for /ingest endpoints (Shared Brain format)
  const deliveryBody = route.targetPath === '/ingest'
    ? transformForIngest(route.source, route.channel, body, headers)
    : body;

  try {
    const resp = await binding.fetch(`https://worker${route.targetPath}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Echo-API-Key': env.ECHO_API_KEY,
        'X-Webhook-Id': webhookId,
        'X-Webhook-Source': route.source,
        'X-Webhook-Channel': route.channel,
        // Forward relevant original headers
        ...(headers['x-github-event'] ? { 'X-GitHub-Event': headers['x-github-event'] } : {}),
        ...(headers['x-github-delivery'] ? { 'X-GitHub-Delivery': headers['x-github-delivery'] } : {}),
        ...(headers['stripe-signature'] ? { 'Stripe-Signature': headers['stripe-signature'] } : {}),
      },
      body: deliveryBody,
    });

    const latency = Date.now() - start;
    const preview = resp.ok ? '' : await resp.text().catch(() => '');

    return {
      webhookId,
      source: route.source,
      channel: route.channel,
      target: `${route.targetBinding}${route.targetPath}`,
      status: resp.ok ? 'delivered' : 'failed',
      statusCode: resp.status,
      latencyMs: latency,
      retryCount: 0,
      error: resp.ok ? undefined : `HTTP ${resp.status}: ${preview.slice(0, 200)}`,
    };
  } catch (e: unknown) {
    return {
      webhookId,
      source: route.source,
      channel: route.channel,
      target: `${route.targetBinding}${route.targetPath}`,
      status: 'failed',
      statusCode: 0,
      latencyMs: Date.now() - start,
      retryCount: 0,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

// ── Rate Limiting ────────────────────────────────────────────────────────────

async function checkRateLimit(cache: KVNamespace, source: string, ip: string): Promise<boolean> {
  const key = `rl:${source}:${ip}:${Math.floor(Date.now() / 60000)}`;
  const current = parseInt(await cache.get(key) || '0');
  if (current > 100) return false; // 100 per minute per source per IP
  await cache.put(key, String(current + 1), { expirationTtl: 120 });
  return true;
}

// ── Webhook Handling ─────────────────────────────────────────────────────────

async function handleWebhook(
  request: Request,
  source: string,
  channel: string,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  const webhookId = generateId();
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';

  // Rate limit check
  const allowed = await checkRateLimit(env.CACHE, source, ip);
  if (!allowed) {
    log('warn', 'Rate limited', { source, ip, webhookId });
    return json({ error: 'Rate limited' }, 429);
  }

  // Handle GET verification challenges (Telegram, Meta, Slack)
  if (request.method === 'GET') {
    return handleVerificationChallenge(request, source, env);
  }

  if (request.method !== 'POST') {
    return json({ error: 'Method not allowed' }, 405);
  }

  // Read body
  const body = await request.text();
  const bodyHash = await sha256(body);
  const headers: Record<string, string> = {};
  request.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });

  // Verify signature
  const verified = await verifyWebhook(source, request, body, env);
  if (!verified) {
    log('warn', 'Signature verification failed', { source, channel, webhookId, ip });
    // Log but don't reject — some sources don't have secrets configured yet.
    // Only reject for sources where we HAVE the secret configured (every
    // source with a configurable secret, not just github/stripe/slack --
    // telegram/whatsapp/messenger/vercel were verified above but never
    // actually enforced here, so a configured secret for those sources was
    // silently ignored on failure and a forged webhook still got routed).
    const hasSecret = (source === 'github' && env.GITHUB_WEBHOOK_SECRET)
      || (source === 'stripe' && env.STRIPE_WEBHOOK_SECRET)
      || (source === 'slack' && env.SLACK_SIGNING_SECRET)
      || (source === 'telegram' && env.TELEGRAM_WEBHOOK_SECRET)
      || ((source === 'whatsapp' || source === 'messenger') && env.META_APP_SECRET)
      || (source === 'vercel' && env.VERCEL_WEBHOOK_SECRET);
    if (hasSecret) {
      return json({ error: 'Invalid signature' }, 401);
    }
  }

  // Log incoming webhook
  await env.DB.prepare(
    `INSERT INTO webhook_log (webhook_id, source, channel, method, path, headers, body_hash, body_size, ip, user_agent, verified)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    webhookId, source, channel, request.method, new URL(request.url).pathname,
    JSON.stringify(Object.fromEntries(
      ['content-type', 'user-agent', 'x-github-event', 'x-github-delivery', 'stripe-signature'].map(h => [h, headers[h] || ''])
    )),
    bodyHash, body.length, ip, headers['user-agent'] || '', verified ? 1 : 0,
  ).run();

  // Detect channel from payload/headers — for GitHub, always prefer x-github-event header
  // because all events arrive at the same URL (/hook/github/push) but have different event types
  const resolvedChannel = (source === 'github' && headers['x-github-event'])
    ? headers['x-github-event']
    : (channel || detectChannel(source, body, headers));

  // Get routes
  const routes = await getRoutes(env.DB, env.CACHE, source, resolvedChannel);
  if (routes.length === 0) {
    log('info', 'No routes for webhook', { source, channel: resolvedChannel, webhookId });
    return json({ received: true, webhookId, routes: 0 });
  }

  // Deliver to all matching routes in parallel
  const deliveries = await Promise.allSettled(
    routes.map(route => deliverWebhook(env, route, webhookId, body, headers))
  );

  const results: DeliveryLog[] = [];
  for (const d of deliveries) {
    if (d.status === 'fulfilled') results.push(d.value);
  }

  // Log deliveries and queue failures for retry
  ctx.waitUntil((async () => {
    for (const result of results) {
      await env.DB.prepare(
        `INSERT INTO delivery_log (webhook_id, source, channel, target_binding, target_path, status, status_code, latency_ms, retry_count, error, response_preview)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        result.webhookId, result.source, result.channel,
        result.target.split('/')[0], '/' + result.target.split('/').slice(1).join('/'),
        result.status, result.statusCode, result.latencyMs, result.retryCount, result.error || null, null,
      ).run();

      // Queue failed deliveries for retry
      if (result.status === 'failed') {
        const route = routes.find(r => `${r.targetBinding}${r.targetPath}` === result.target);
        if (route) {
          const nextRetry = new Date(Date.now() + 60000).toISOString(); // Retry in 1 minute
          await env.DB.prepare(
            `INSERT INTO failed_deliveries (webhook_id, source, channel, target_binding, target_path, body, headers, next_retry_at, error)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(webhookId, source, resolvedChannel, route.targetBinding, route.targetPath, body, JSON.stringify(headers), nextRetry, result.error || null).run();
        }
      }
    }

    // Update daily stats
    const d = new Date().toISOString().split('T')[0];
    const delivered = results.filter(r => r.status === 'delivered').length;
    const failed = results.filter(r => r.status === 'failed').length;
    const avgLatency = results.length > 0 ? results.reduce((sum, r) => sum + r.latencyMs, 0) / results.length : 0;

    await env.DB.prepare(
      `INSERT INTO stats (source, date, received, delivered, failed, avg_latency_ms)
       VALUES (?, ?, 1, ?, ?, ?)
       ON CONFLICT(source, date) DO UPDATE SET
         received = received + 1,
         delivered = delivered + excluded.delivered,
         failed = failed + excluded.failed,
         avg_latency_ms = (avg_latency_ms * received + excluded.avg_latency_ms) / (received + 1)`
    ).bind(source, d, delivered, failed, avgLatency).run();
  })());

  log('info', 'Webhook processed', {
    webhookId, source, channel: resolvedChannel,
    routes: routes.length,
    delivered: results.filter(r => r.status === 'delivered').length,
    failed: results.filter(r => r.status === 'failed').length,
  });

  return json({
    received: true,
    webhookId,
    routes: routes.length,
    delivered: results.filter(r => r.status === 'delivered').length,
    failed: results.filter(r => r.status === 'failed').length,
  });
}

// ── Channel Detection ────────────────────────────────────────────────────────

function detectChannel(source: string, body: string, headers: Record<string, string>): string {
  try {
    switch (source) {
      case 'github':
        return headers['x-github-event'] || 'push';
      case 'stripe': {
        const data = JSON.parse(body);
        return data.type?.split('.')[0] || 'payment';
      }
      case 'slack': {
        const data = JSON.parse(body);
        return data.type === 'url_verification' ? 'verification' : data.event?.type || 'event';
      }
      case 'vercel': {
        const data = JSON.parse(body);
        return data.type || 'deployment';
      }
      case 'telegram':
        return 'message';
      case 'whatsapp':
      case 'messenger':
        return 'message';
      default:
        return 'default';
    }
  } catch {
    return 'default';
  }
}

// ── Verification Challenge Handling ──────────────────────────────────────────

function handleVerificationChallenge(request: Request, source: string, env: Env): Response {
  const params = new URL(request.url).searchParams;

  switch (source) {
    case 'whatsapp':
    case 'messenger': {
      const mode = params.get('hub.mode');
      const token = params.get('hub.verify_token');
      const challenge = params.get('hub.challenge');
      if (mode === 'subscribe' && timingSafeEqual(token, env.WHATSAPP_VERIFY_TOKEN)) {
        return new Response(challenge, { status: 200 });
      }
      return new Response('Forbidden', { status: 403 });
    }
    case 'telegram': {
      // Telegram doesn't use GET verification — this is a no-op
      return json({ ok: true });
    }
    default:
      return json({ error: 'No verification handler for this source' }, 400);
  }
}

// ── Retry Failed Deliveries ──────────────────────────────────────────────────

async function retryFailedDeliveries(env: Env): Promise<{ retried: number; succeeded: number; dropped: number }> {
  const now = new Date().toISOString();

  const failed = await env.DB.prepare(
    `SELECT * FROM failed_deliveries WHERE next_retry_at <= ? AND retry_count < max_retries ORDER BY created_at ASC LIMIT 50`
  ).bind(now).all<Record<string, unknown>>();

  let retried = 0;
  let succeeded = 0;
  let dropped = 0;

  for (const f of (failed.results || [])) {
    retried++;

    const binding = getBinding(env, f.target_binding as string);
    if (!binding) {
      dropped++;
      await env.DB.prepare(`DELETE FROM failed_deliveries WHERE id = ?`).bind(f.id).run();
      continue;
    }

    try {
      const resp = await binding.fetch(`https://worker${f.target_path}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Echo-API-Key': env.ECHO_API_KEY,
          'X-Webhook-Id': f.webhook_id as string,
          'X-Webhook-Retry': String((f.retry_count as number) + 1),
        },
        body: f.body as string,
      });

      if (resp.ok) {
        succeeded++;
        await env.DB.prepare(`DELETE FROM failed_deliveries WHERE id = ?`).bind(f.id).run();
        await env.DB.prepare(
          `UPDATE delivery_log SET status = 'delivered', status_code = ?, retry_count = ? WHERE webhook_id = ? AND target_binding = ?`
        ).bind(resp.status, (f.retry_count as number) + 1, f.webhook_id, f.target_binding).run();
      } else {
        // Schedule next retry with exponential backoff
        const nextDelay = Math.pow(2, (f.retry_count as number) + 1) * 60000; // 2^n minutes
        const nextRetry = new Date(Date.now() + nextDelay).toISOString();
        await env.DB.prepare(
          `UPDATE failed_deliveries SET retry_count = retry_count + 1, next_retry_at = ?, error = ? WHERE id = ?`
        ).bind(nextRetry, `HTTP ${resp.status}`, f.id).run();
      }
    } catch (e: unknown) {
      const retryCount = (f.retry_count as number) + 1;
      if (retryCount >= (f.max_retries as number)) {
        dropped++;
        await env.DB.prepare(`DELETE FROM failed_deliveries WHERE id = ?`).bind(f.id).run();
        await env.DB.prepare(
          `UPDATE delivery_log SET status = 'dropped', retry_count = ? WHERE webhook_id = ? AND target_binding = ?`
        ).bind(retryCount, f.webhook_id, f.target_binding).run();
      } else {
        const nextDelay = Math.pow(2, retryCount) * 60000;
        const nextRetry = new Date(Date.now() + nextDelay).toISOString();
        await env.DB.prepare(
          `UPDATE failed_deliveries SET retry_count = ?, next_retry_at = ?, error = ? WHERE id = ?`
        ).bind(retryCount, nextRetry, e instanceof Error ? e.message : String(e), f.id).run();
      }
    }
  }

  log('info', 'Retry cycle complete', { retried, succeeded, dropped });
  return { retried, succeeded, dropped };
}

// ── Cron Handler ─────────────────────────────────────────────────────────────

async function handleScheduled(event: ScheduledEvent, env: Env): Promise<void> {
  await ensureSchema(env.DB);

  const hour = new Date(event.scheduledTime).getUTCHours();

  // Hourly: retry failed deliveries
  await retryFailedDeliveries(env);

  // Daily 4am: prune old logs (keep 30 days)
  if (hour === 4) {
    const cutoff = new Date(Date.now() - 30 * 86400000).toISOString();
    await env.DB.prepare(`DELETE FROM webhook_log WHERE received_at < ?`).bind(cutoff).run();
    await env.DB.prepare(`DELETE FROM delivery_log WHERE delivered_at < ?`).bind(cutoff).run();
    await env.DB.prepare(`DELETE FROM failed_deliveries WHERE created_at < ? AND retry_count >= max_retries`).bind(cutoff).run();
    log('info', 'Pruned old logs', { cutoff });
  }
}

// ── HTTP Handler ─────────────────────────────────────────────────────────────

async function handleRequest(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  // CORS
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, X-Echo-API-Key, X-Hub-Signature-256, Stripe-Signature, X-Slack-Signature, X-Slack-Request-Timestamp, X-Telegram-Bot-Api-Secret-Token',
      },
    });
  }

  await ensureSchema(env.DB);

  // ── Webhook Ingress ──
  // Pattern: /hook/:source OR /hook/:source/:channel
  const hookMatch = path.match(/^\/hook\/([a-z0-9-]+)(?:\/([a-z0-9-]+))?$/);
  if (hookMatch) {
    const source = hookMatch[1];
    const channel = hookMatch[2] || '';
    return handleWebhook(request, source, channel, env, ctx);
  }

  // Health — no auth
    if (path === '/') return json({ service: 'echo-webhook-router', status: 'operational' });
if (path === '/health') {
    const pendingRetries = await env.DB.prepare(
      `SELECT COUNT(*) as count FROM failed_deliveries WHERE retry_count < max_retries`
    ).first<{ count: number }>();

    return json({
      status: 'ok',
      service: 'echo-webhook-router',
      version: '1.1.0',
      timestamp: new Date().toISOString(),
      defaultRoutes: DEFAULT_ROUTES.length,
      pendingRetries: pendingRetries?.count || 0,
      endpoints: 12,
    });
  }

  // Auth for management endpoints
  const apiKey = request.headers.get('X-Echo-API-Key');
  if (!timingSafeEqual(apiKey, env.ECHO_API_KEY)) {
    return json({ error: 'Unauthorized' }, 401);
  }

  switch (path) {
    // ── Route Management ──
    case '/routes': {
      if (request.method === 'GET') {
        const rows = await env.DB.prepare(`SELECT * FROM routes ORDER BY source, channel, priority DESC`).all();
        return json({ custom_routes: rows.results, default_routes: DEFAULT_ROUTES });
      }
      if (request.method === 'POST') {
        const body = await request.json() as { source: string; channel: string; target_binding: string; target_path: string; verify_method?: string; description?: string; priority?: number };
        if (!body.source || !body.channel || !body.target_binding || !body.target_path) {
          return json({ error: 'source, channel, target_binding, target_path required' }, 400);
        }
        await env.DB.prepare(
          `INSERT INTO routes (source, channel, target_binding, target_path, verify_method, description, priority)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(source, channel, target_binding) DO UPDATE SET
             target_path = excluded.target_path, verify_method = excluded.verify_method,
             description = excluded.description, priority = excluded.priority, updated_at = datetime('now')`
        ).bind(body.source, body.channel, body.target_binding, body.target_path, body.verify_method || 'none', body.description || '', body.priority || 0).run();

        // Invalidate cache
        await env.CACHE.delete(`routes:${body.source}:${body.channel}`);
        return json({ created: true });
      }
      return json({ error: 'Method not allowed' }, 405);
    }

    case '/routes/delete': {
      if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
      const body = await request.json() as { id: number };
      if (!body.id) return json({ error: 'id required' }, 400);
      await env.DB.prepare(`DELETE FROM routes WHERE id = ?`).bind(body.id).run();
      return json({ deleted: true });
    }

    // ── Logs ──
    case '/logs/webhooks': {
      const source = url.searchParams.get('source');
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 500);

      let query = 'SELECT * FROM webhook_log';
      const params: unknown[] = [];
      if (source) { query += ' WHERE source = ?'; params.push(source); }
      query += ' ORDER BY received_at DESC LIMIT ?';
      params.push(limit);

      const rows = await env.DB.prepare(query).bind(...params).all();
      return json({ count: rows.results?.length || 0, webhooks: rows.results });
    }

    case '/logs/deliveries': {
      const webhookId = url.searchParams.get('webhook_id');
      const status = url.searchParams.get('status');
      const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 500);

      let query = 'SELECT * FROM delivery_log';
      const conditions: string[] = [];
      const params: unknown[] = [];
      if (webhookId) { conditions.push('webhook_id = ?'); params.push(webhookId); }
      if (status) { conditions.push('status = ?'); params.push(status); }
      if (conditions.length) query += ' WHERE ' + conditions.join(' AND ');
      query += ' ORDER BY delivered_at DESC LIMIT ?';
      params.push(limit);

      const rows = await env.DB.prepare(query).bind(...params).all();
      return json({ count: rows.results?.length || 0, deliveries: rows.results });
    }

    case '/logs/failed': {
      const rows = await env.DB.prepare(
        `SELECT * FROM failed_deliveries ORDER BY created_at DESC LIMIT 100`
      ).all();
      return json({ count: rows.results?.length || 0, failed: rows.results });
    }

    // ── Stats ──
    case '/stats': {
      const days = parseInt(url.searchParams.get('days') || '7');
      const since = new Date(Date.now() - days * 86400000).toISOString().split('T')[0];

      const rows = await env.DB.prepare(
        `SELECT source, SUM(received) as total_received, SUM(delivered) as total_delivered,
                SUM(failed) as total_failed, AVG(avg_latency_ms) as avg_latency
         FROM stats WHERE date >= ? GROUP BY source ORDER BY total_received DESC`
      ).bind(since).all();

      const totals = await env.DB.prepare(
        `SELECT SUM(received) as received, SUM(delivered) as delivered, SUM(failed) as failed, AVG(avg_latency_ms) as avg_latency
         FROM stats WHERE date >= ?`
      ).bind(since).first();

      return json({ period: `${days} days`, totals, by_source: rows.results });
    }

    case '/stats/daily': {
      const source = url.searchParams.get('source');
      const days = parseInt(url.searchParams.get('days') || '30');
      const since = new Date(Date.now() - days * 86400000).toISOString().split('T')[0];

      let query = `SELECT * FROM stats WHERE date >= ?`;
      const params: unknown[] = [since];
      if (source) { query += ` AND source = ?`; params.push(source); }
      query += ` ORDER BY date DESC, source ASC`;

      const rows = await env.DB.prepare(query).bind(...params).all();
      return json({ count: rows.results?.length || 0, daily: rows.results });
    }

    // ── Retry Management ──
    case '/retry': {
      if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
      const result = await retryFailedDeliveries(env);
      return json(result);
    }

    // ── Test Webhook ──
    case '/test': {
      if (request.method !== 'POST') return json({ error: 'POST required' }, 405);
      const body = await request.json() as { source: string; channel: string; payload: unknown };
      if (!body.source) return json({ error: 'source required' }, 400);

      const testRequest = new Request('https://test/hook/' + body.source + '/' + (body.channel || 'test'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body.payload || { test: true, timestamp: new Date().toISOString() }),
      });

      return handleWebhook(testRequest, body.source, body.channel || 'test', env, { waitUntil: () => {} } as unknown as ExecutionContext);
    }

    default:
      return json({
        error: 'Not found',
        usage: 'POST /hook/:source/:channel to send webhooks',
        endpoints: [
          'POST /hook/:source/:channel — Inbound webhook',
          'GET  /health', 'GET  /routes', 'POST /routes',
          'POST /routes/delete', 'GET  /logs/webhooks',
          'GET  /logs/deliveries', 'GET  /logs/failed',
          'GET  /stats', 'GET  /stats/daily',
          'POST /retry', 'POST /test',
        ],
      }, 404);
  }
}

// ── Worker Export ─────────────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      return await handleRequest(request, env, ctx);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      log('error', 'Unhandled error', { error: msg, path: new URL(request.url).pathname });
      return json({ error: 'Internal error', message: msg }, 500);
    }
  },

  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(handleScheduled(event, env));
  },
};
