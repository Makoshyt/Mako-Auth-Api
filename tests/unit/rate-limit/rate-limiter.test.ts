import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { trustProxyOption } from '../../../src/app.js';
import type { AuditEventInput } from '../../../src/modules/audit/audit.recorder.js';
import {
  buildPolicies,
  type PolicyName,
} from '../../../src/modules/rate-limit/rate-limit.policies.js';
import type { RateLimitStore } from '../../../src/modules/rate-limit/rate-limit.store.js';
import {
  createRateLimiter,
  registerRateLimiting,
  type RateLimiter,
} from '../../../src/modules/rate-limit/rate-limiter.js';
import { registerErrorHandling } from '../../../src/shared/error-handler.js';
import { InMemoryRateLimitStore } from '../../helpers/in-memory-rate-limit-store.js';
import { testEnv } from '../../helpers/test-env.js';

/** Defaults de PRODUÇÃO (não relaxados): é exatamente isto que está sendo testado. */
const env = testEnv({}, { rateLimits: 'default' });
const policies = buildPolicies(env);
const SECRET = 'hmac-de-teste-unitario-com-32-caracteres-ou-mais';
const USER_A = '0190a000-0000-7000-8000-00000000000a';
const USER_B = '0190a000-0000-7000-8000-00000000000b';

let store: InMemoryRateLimitStore;
let events: AuditEventInput[];
let logs: string[];
let app: FastifyInstance;
let limiter: RateLimiter;

interface AppOptions {
  store?: RateLimitStore;
  trustProxy?: ReturnType<typeof trustProxyOption>;
  storeTimeoutMs?: number;
}

/** App mínimo: as rotas reais usam os mesmos hooks, nesta mesma ordem. */
async function buildMiniApp({
  store: customStore,
  trustProxy = false,
  storeTimeoutMs,
}: AppOptions = {}) {
  const instance = Fastify({
    trustProxy,
    logger: { level: 'trace', stream: { write: (line: string) => void logs.push(line) } },
  });
  registerErrorHandling(instance, { exposeStack: false });
  instance.decorate('audit', {
    record: (event: AuditEventInput) => {
      events.push(event);
      return Promise.resolve();
    },
  });
  instance.decorateRequest('auth', null);
  limiter = createRateLimiter({
    store: customStore ?? store,
    policies,
    hmacSecret: SECRET,
    keyPrefix: 'unit:rl',
    ...(storeTimeoutMs !== undefined && { storeTimeoutMs }),
  });
  registerRateLimiting(instance, limiter);

  // Autenticação falsa: só o teste define quem é o usuário (o real é o authenticate do JWT).
  const fakeAuth = async (request: FastifyRequest) => {
    const userId = request.headers['x-test-user'];
    if (typeof userId === 'string') request.auth = { userId, sessionId: 's', role: 'ADMIN' };
  };
  const ok = async () => ({ ok: true });
  const hook = (name: PolicyName) => instance.rateLimit.hook(name);

  instance.post('/login', { onRequest: hook('loginIp'), preHandler: hook('loginAccount') }, ok);
  instance.post('/register', { onRequest: hook('register') }, ok);
  instance.post('/refresh', { onRequest: hook('refresh') }, ok);
  instance.post('/logout', { onRequest: [fakeAuth, hook('logout')] }, ok);
  instance.post('/logout-all', { onRequest: [fakeAuth, hook('logoutAll')] }, ok);
  instance.patch('/me', { onRequest: [fakeAuth, hook('updateProfile')] }, ok);
  for (const [url, name] of [
    ['/admin/users', 'adminUsers'],
    ['/admin/users/:id', 'adminUserById'],
    ['/admin/audit-events', 'adminAuditEvents'],
  ] as const) {
    instance.get(
      url,
      { config: { rateLimit: name }, onRequest: [fakeAuth, instance.rateLimit.fromRouteConfig()] },
      ok,
    );
  }
  await instance.ready();
  return instance;
}

const login = (
  email: string,
  remoteAddress = '203.0.113.10',
  headers: Record<string, string> = {},
) => app.inject({ method: 'POST', url: '/login', payload: { email }, remoteAddress, headers });

/** Envia `count` requisições e devolve os status. */
async function burst(count: number, send: () => Promise<{ statusCode: number }>) {
  const statuses: number[] = [];
  for (let i = 0; i < count; i++) statuses.push((await send()).statusCode);
  return statuses;
}

const okThenBlocked = (allowed: number, total: number) => [
  ...Array<number>(allowed).fill(200),
  ...Array<number>(total - allowed).fill(429),
];

beforeEach(async () => {
  store = new InMemoryRateLimitStore();
  events = [];
  logs = [];
  app = await buildMiniApp();
});

afterEach(async () => {
  await app.close();
});

describe('políticas por endpoint (defaults de produção)', () => {
  it('login: 5 por IP em 15 min; a 6ª tentativa recebe 429', async () => {
    expect(await burst(7, () => login('ana@example.com'))).toEqual(okThenBlocked(5, 7));
  });

  it('cadastro: 5 por IP em 1 h', async () => {
    const send = () =>
      app.inject({ method: 'POST', url: '/register', remoteAddress: '203.0.113.20' });
    expect(await burst(6, send)).toEqual(okThenBlocked(5, 6));
    expect(store.windows.at(-1)).toBe(60 * 60_000);
  });

  it('refresh: 20 por IP em 15 min', async () => {
    const send = () =>
      app.inject({ method: 'POST', url: '/refresh', remoteAddress: '203.0.113.30' });
    expect(await burst(21, send)).toEqual(okThenBlocked(20, 21));
  });

  it.each([
    ['logout', 'POST', '/logout', 20],
    ['logout-all', 'POST', '/logout-all', 5],
    ['PATCH /users/me', 'PATCH', '/me', 10],
  ] as const)('%s: %i por usuário em 15 min', async (_label, method, url, max) => {
    const send = () => app.inject({ method, url, headers: { 'x-test-user': USER_A } });
    expect(await burst(max + 1, send)).toEqual(okThenBlocked(max, max + 1));
  });

  it.each([
    ['/admin/users', 60],
    ['/admin/users/0190a000-0000-7000-8000-000000000001', 60],
    ['/admin/audit-events', 30],
  ])('%s: %i por ADMIN por minuto', async (url, max) => {
    const send = () => app.inject({ method: 'GET', url, headers: { 'x-test-user': USER_A } });
    expect(await burst(max + 1, send)).toEqual(okThenBlocked(max, max + 1));
    expect(store.windows.at(-1)).toBe(60_000);
  });
});

describe('resposta 429', () => {
  it('formato padrão de erro, Retry-After e X-RateLimit-*, sem dados sensíveis', async () => {
    await burst(5, () => login('ana@example.com'));
    store.now += 60_000; // 1 min depois: faltam 14 min da janela

    const response = await login('ana@example.com');

    expect(response.statusCode).toBe(429);
    const body = response.json<{ error: { code: string; message: string; details: unknown } }>();
    expect(body.error).toMatchObject({
      code: 'RATE_LIMITED',
      message: 'Muitas requisições. Tente novamente em 840 s.',
      details: { retryAfterSeconds: 840 },
    });
    expect(response.headers['retry-after']).toBe('840');
    expect(response.headers['x-ratelimit-limit']).toBe('5');
    expect(response.headers['x-ratelimit-remaining']).toBe('0');
    expect(response.headers['x-ratelimit-reset']).toBe('840');
    expect(response.body).not.toMatch(/203\.0\.113|ana@example|unit:rl|[0-9a-f]{64}/);
  });

  it('X-RateLimit-Remaining diminui a cada requisição permitida', async () => {
    const remaining = [];
    for (let i = 0; i < 3; i++) {
      remaining.push((await login(`x${i}@example.com`)).headers['x-ratelimit-remaining']);
    }
    expect(remaining).toEqual(['4', '3', '2']);
  });

  it('o limite por conta não expõe X-RateLimit-* (não revela tentativas de terceiros)', async () => {
    const response = await login('ana@example.com');

    // Os cabeçalhos presentes são os do limite por IP (5), nunca os da conta (10).
    expect(response.headers['x-ratelimit-limit']).toBe('5');
  });
});

describe('TTL e expiração', () => {
  it('pede ao store a janela da política e libera de novo quando ela expira', async () => {
    await burst(5, () => login('ana@example.com'));
    expect((await login('ana@example.com')).statusCode).toBe(429);
    expect(store.windows[0]).toBe(15 * 60_000);

    store.now += 15 * 60_000;

    expect((await login('ana@example.com')).statusCode).toBe(200);
  });
});

describe('isolamento', () => {
  it('entre rotas: estourar o login não afeta o cadastro do mesmo IP', async () => {
    await burst(6, () => login('ana@example.com'));

    const register = await app.inject({
      method: 'POST',
      url: '/register',
      remoteAddress: '203.0.113.10',
    });

    expect(register.statusCode).toBe(200);
  });

  it('entre usuários: estourar o limite de A não afeta B', async () => {
    const as = (user: string) => () =>
      app.inject({ method: 'POST', url: '/logout-all', headers: { 'x-test-user': user } });
    await burst(6, as(USER_A));

    expect((await as(USER_B)()).statusCode).toBe(200);
  });

  it('entre IPs: outro IP tem o próprio contador', async () => {
    await burst(6, () => login('a@example.com', '203.0.113.10'));

    expect((await login('b@example.com', '203.0.113.11')).statusCode).toBe(200);
  });

  it('chaves distintas por política, escopo e identificador', () => {
    const keys = new Set([
      limiter.keyFor(policies.loginIp, 'ip', 'v4:1.2.3.4'),
      limiter.keyFor(policies.register, 'ip', 'v4:1.2.3.4'),
      limiter.keyFor(policies.loginAccount, 'account', 'v4:1.2.3.4'),
      limiter.keyFor(policies.loginIp, 'ip', 'v4:1.2.3.5'),
    ]);
    expect(keys.size).toBe(4);
  });
});

describe('proteção por conta no login', () => {
  it('10 tentativas por email em 1 h, mesmo vindas de IPs diferentes', async () => {
    const statuses = [];
    for (let i = 0; i < 11; i++)
      statuses.push((await login('alvo@example.com', `198.51.100.${i}`)).statusCode);

    expect(statuses).toEqual(okThenBlocked(10, 11));
  });

  it('a mesma resposta 429 para conta e IP (não revela qual limite, nem se a conta existe)', async () => {
    for (let i = 0; i < 10; i++) await login('alvo@example.com', `198.51.100.${i}`);
    const byAccount = await login('alvo@example.com', '198.51.100.99');
    await burst(5, () => login('outro@example.com', '192.0.2.1'));
    const byIp = await login('mais-um@example.com', '192.0.2.1');

    const shape = (body: string) => (JSON.parse(body) as { error: { code: string } }).error.code;
    expect(shape(byAccount.body)).toBe('RATE_LIMITED');
    expect(shape(byIp.body)).toBe('RATE_LIMITED');
  });

  it('um IP já bloqueado não consome o limite da conta (não trava a vítima sozinho)', async () => {
    // O atacante insiste 30 vezes de um único IP: só as 5 primeiras chegam ao limite da conta.
    await burst(30, () => login('vitima@example.com', '192.0.2.66'));

    // A vítima, de outro IP, ainda tem 5 tentativas na janela da conta (10 - 5).
    const victim = await burst(6, () => login('vitima@example.com', '203.0.113.200'));
    expect(victim).toEqual(okThenBlocked(5, 6));
  });
});

describe('chaves HMAC', () => {
  it('a chave da conta é HMAC-SHA256 do email: nem o email nem um SHA-256 simples aparecem', async () => {
    await login('ana@example.com');

    const keys = [...store.entries.keys()];
    const accountKey = keys.find((key) => key.includes(':loginAccount:account:'));
    expect(accountKey).toMatch(/^unit:rl:loginAccount:account:[0-9a-f]{64}$/);
    expect(keys.join()).not.toContain('ana@example.com');
    expect(keys.join()).not.toContain('203.0.113.10');
    const { createHash } = await import('node:crypto');
    const plainSha = createHash('sha256').update('account:ana@example.com').digest('hex');
    expect(accountKey).not.toContain(plainSha);
  });

  it('é determinística com o mesmo segredo e muda com outro segredo', () => {
    const other = createRateLimiter({
      store,
      policies,
      hmacSecret: `${SECRET}-outro`,
      keyPrefix: 'unit:rl',
    });

    const key = limiter.keyFor(policies.loginAccount, 'account', 'ana@example.com');
    expect(limiter.keyFor(policies.loginAccount, 'account', 'ana@example.com')).toBe(key);
    expect(other.keyFor(policies.loginAccount, 'account', 'ana@example.com')).not.toBe(key);
  });
});

describe('auditoria sem amplificação', () => {
  it('um único RATE_LIMIT_EXCEEDED por chave e janela, por mais 429 que haja', async () => {
    await burst(50, () => login('ana@example.com'));

    expect(events).toHaveLength(1);
    expect(events[0]).toEqual({
      type: 'RATE_LIMIT_EXCEEDED',
      userId: null,
      ip: '203.0.113.10',
      metadata: { policy: 'loginIp', scope: 'ip', limit: 5, windowSeconds: 900 },
    });

    store.now += 15 * 60_000; // nova janela: pode gerar um novo evento
    await burst(6, () => login('ana@example.com'));
    expect(events).toHaveLength(2);
  });

  it('escopo de usuário registra o userId; escopo de conta só entrega o email para hash', async () => {
    await burst(6, () =>
      app.inject({ method: 'POST', url: '/logout-all', headers: { 'x-test-user': USER_A } }),
    );
    for (let i = 0; i < 11; i++) await login('alvo@example.com', `198.51.100.${i}`);

    expect(events.find((e) => e.metadata?.policy === 'logoutAll')).toMatchObject({
      userId: USER_A,
    });
    // O AuditRecorder grava só o SHA-256 do email (ver audit.recorder.test.ts).
    expect(events.find((e) => e.metadata?.policy === 'loginAccount')).toMatchObject({
      email: 'alvo@example.com',
      userId: null,
    });
  });
});

describe('modo de falha de cada política', () => {
  it('fechado nas rotas sensíveis, aberto onde bloquear prejudicaria o usuário', () => {
    const modes = Object.fromEntries(
      Object.values(policies).map((policy) => [policy.name, policy.onStoreFailure]),
    );
    expect(modes).toEqual({
      loginIp: 'closed',
      loginAccount: 'closed',
      register: 'closed',
      refresh: 'closed',
      updateProfile: 'closed',
      forgotPasswordIp: 'closed',
      forgotPasswordAccount: 'closed',
      resetPasswordIp: 'closed',
      logout: 'open',
      logoutAll: 'open',
      adminUsers: 'open',
      adminUserById: 'open',
      adminAuditEvents: 'open',
    });
  });
});

describe('Redis indisponível', () => {
  const failingStore: RateLimitStore = {
    hit: () => Promise.reject(new Error('Connection is closed.')),
  };

  it.each(['/login', '/register', '/refresh'])(
    '%s falha FECHADO: 503 (nunca 401), com Retry-After',
    async (url) => {
      await app.close();
      app = await buildMiniApp({ store: failingStore });

      const response = await app.inject({
        method: 'POST',
        url,
        payload: { email: 'ana@example.com' },
      });

      expect(response.statusCode).toBe(503);
      expect(response.json<{ error: { code: string } }>().error.code).toBe('SERVICE_UNAVAILABLE');
      expect(response.headers['retry-after']).toBe('10');
      expect(response.body).not.toMatch(/Connection|Redis|closed/i);
    },
  );

  it('o limite por IP do login falha fechado sozinho (sem depender do limite por conta)', async () => {
    await app.close();
    app = await buildMiniApp({ store: failingStore });

    // Sem email no corpo, o limite por conta não se aplica: só o de IP decide.
    const response = await app.inject({ method: 'POST', url: '/login', payload: {} });

    expect(response.statusCode).toBe(503);
  });

  it('PATCH /users/me também falha fechado (protege a verificação da senha atual)', async () => {
    await app.close();
    app = await buildMiniApp({ store: failingStore });

    const response = await app.inject({
      method: 'PATCH',
      url: '/me',
      headers: { 'x-test-user': USER_A },
    });

    expect(response.statusCode).toBe(503);
  });

  it.each([
    ['POST', '/logout'],
    ['POST', '/logout-all'],
    ['GET', '/admin/users'],
    ['GET', '/admin/audit-events'],
  ] as const)('%s %s falha ABERTO: a requisição segue', async (method, url) => {
    await app.close();
    app = await buildMiniApp({ store: failingStore });

    const response = await app.inject({ method, url, headers: { 'x-test-user': USER_A } });

    expect(response.statusCode).toBe(200);
  });

  it('Redis lento além do timeout conta como indisponível', async () => {
    await app.close();
    const hanging: RateLimitStore = { hit: () => new Promise(() => undefined) };
    app = await buildMiniApp({ store: hanging, storeTimeoutMs: 50 });

    expect((await login('ana@example.com')).statusCode).toBe(503);
  });
});

describe('logs', () => {
  it('429 e falhas do Redis não registram chaves, HMACs, IPs nem emails', async () => {
    await burst(7, () => login('segredo.pessoal@example.com'));
    await app.close();
    app = await buildMiniApp({
      store: { hit: () => Promise.reject(new Error('Connection is closed.')) },
    });
    await login('segredo.pessoal@example.com');

    const log = logs.join('');
    expect(log).toContain('rate limit excedido');
    expect(log).toContain('rate limit indisponível');
    expect(log).not.toContain('segredo.pessoal');
    expect(log).not.toContain('unit:rl');
    expect(log).not.toMatch(/[0-9a-f]{64}/);
    // O IP aparece apenas como remoteAddress do log padrão de requisição, nunca nos eventos
    // de rate limit (que só levam política e escopo).
    const rateLimitLines = logs.filter((line) => line.includes('rate limit'));
    for (const line of rateLimitLines) expect(line).not.toContain('203.0.113.10');
  });

  it('o aviso de limite excedido sai uma vez por chave e janela (sem amplificar logs)', async () => {
    await burst(40, () => login('ana@example.com'));

    expect(logs.filter((line) => line.includes('rate limit excedido'))).toHaveLength(1);
  });
});

describe('IP falsificado', () => {
  it('TRUST_PROXY=false: X-Forwarded-For é ignorado, trocar o valor não contorna o limite', async () => {
    const statuses = [];
    for (let i = 0; i < 7; i++) {
      statuses.push(
        (await login(`x${i}@example.com`, '203.0.113.10', { 'x-forwarded-for': `10.9.9.${i}` }))
          .statusCode,
      );
    }

    expect(statuses).toEqual(okThenBlocked(5, 7));
  });

  it('TRUST_PROXY=1 (um proxy): só o endereço que o proxy anexou conta; o resto é do cliente', async () => {
    await app.close();
    app = await buildMiniApp({ trustProxy: trustProxyOption(1) });
    const viaProxy = (spoofed: string, realClient: string) =>
      login(`${spoofed}@example.com`, '10.0.0.1', {
        'x-forwarded-for': `${spoofed}, ${realClient}`,
      });

    const statuses = [];
    for (let i = 0; i < 7; i++)
      statuses.push((await viaProxy(`6.6.6.${i}`, '198.51.100.7')).statusCode);

    expect(statuses).toEqual(okThenBlocked(5, 7));
    expect((await viaProxy('6.6.6.6', '198.51.100.8')).statusCode).toBe(200);
  });

  it('TRUST_PROXY com CIDR: X-Forwarded-For só é aceito se a conexão vier do proxy confiável', async () => {
    await app.close();
    app = await buildMiniApp({ trustProxy: trustProxyOption(['10.0.0.0/8']) });

    // Conexão direta (fora do CIDR) tentando se passar por vários clientes: tudo conta para ela.
    const direct = [];
    for (let i = 0; i < 6; i++) {
      direct.push(
        (await login(`d${i}@example.com`, '203.0.113.50', { 'x-forwarded-for': `9.9.9.${i}` }))
          .statusCode,
      );
    }
    expect(direct).toEqual(okThenBlocked(5, 6));

    // Pelo proxy confiável, o cliente real é respeitado.
    const viaProxy = await login('p@example.com', '10.1.2.3', {
      'x-forwarded-for': '198.51.100.20',
    });
    expect(viaProxy.statusCode).toBe(200);
  });
});
