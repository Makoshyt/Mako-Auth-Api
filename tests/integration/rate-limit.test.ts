import { randomUUID } from 'node:crypto';
import type { FastifyInstance, InjectOptions } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createPrismaClient, type PrismaClient } from '../../src/infra/prisma.js';
import { createRedisClient, type Redis } from '../../src/infra/redis.js';
import { hashEmail } from '../../src/modules/audit/audit.recorder.js';
import type { ErrorBody } from '../../src/shared/error-handler.js';
import {
  buildTestApp,
  deleteTestKeys,
  type BuildTestAppOptions,
} from '../helpers/build-test-app.js';
import { TEST_DATABASE_URL, TEST_RATE_LIMIT_ROOT, TEST_REDIS_URL } from '../helpers/test-env.js';
import { purgeAuditEvents } from '../helpers/purge-audit-events.js';

/**
 * Rate limit com os DEFAULTS DE PRODUÇÃO, contra Redis e PostgreSQL reais.
 * IPs das faixas de documentação (RFC 5737), usados só neste arquivo, e emails num domínio
 * fictício próprio: a limpeza do banco e do Redis fica restrita a esses dados.
 */
const DOMAIN = '@ratelimit-test.example.com';
const email = (local: string) => `${local}${DOMAIN}`;
const PASSWORD = 'cavalo correto bateria grampo';
const NET = '198.51.100.';

let prisma: PrismaClient;
let redis: Redis;
const apps: FastifyInstance[] = [];

/** App com limites de produção; o namespace Redis é único por app (ou o informado). */
async function appWith(overrides: Record<string, string> = {}, options: BuildTestAppOptions = {}) {
  const app = await buildTestApp(overrides, { rateLimits: 'default', ...options });
  apps.push(app);
  return app;
}

const loginReq = (app: FastifyInstance, emailAddress: string, ip: string, password = PASSWORD) =>
  app.inject({
    method: 'POST',
    url: '/api/v1/auth/login',
    payload: { email: emailAddress, password },
    remoteAddress: ip,
  });

async function statuses(count: number, send: (i: number) => Promise<{ statusCode: number }>) {
  const result: number[] = [];
  for (let i = 0; i < count; i++) result.push((await send(i)).statusCode);
  return result;
}

async function registerUser(app: FastifyInstance, local: string, ip: string) {
  const response = await app.inject({
    method: 'POST',
    url: '/api/v1/auth/register',
    payload: { name: `Pessoa ${local}`, email: email(local), password: PASSWORD },
    remoteAddress: ip,
  });
  expect(response.statusCode).toBe(201);
  return response.json<{ id: string }>();
}

async function tokenOf(app: FastifyInstance, local: string, ip: string) {
  const response = await loginReq(app, email(local), ip);
  expect(response.statusCode).toBe(200);
  return response.json<{ accessToken: string; refreshToken: string }>();
}

async function cleanupDb() {
  await purgeAuditEvents(prisma, {
    where: { OR: [{ user: { email: { endsWith: DOMAIN } } }, { ip: { startsWith: NET } }] },
  });
  await prisma.user.deleteMany({ where: { email: { endsWith: DOMAIN } } });
}

beforeAll(async () => {
  prisma = createPrismaClient(TEST_DATABASE_URL);
  redis = createRedisClient(TEST_REDIS_URL);
});

beforeEach(cleanupDb);

afterEach(async () => {
  // Fechar o app apaga as chaves do namespace dele (ver buildTestApp).
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

afterAll(async () => {
  await cleanupDb();
  redis.disconnect();
  await prisma.$disconnect();
});

describe('login por IP (5 em 15 min)', () => {
  it('cinco tentativas permitidas (certas ou erradas) e a sexta bloqueada', async () => {
    const app = await appWith();
    await registerUser(app, 'ana', `${NET}1`);
    const ip = `${NET}2`;

    const result = await statuses(6, (i) =>
      loginReq(app, email('ana'), ip, i % 2 === 0 ? PASSWORD : 'senha errada porém longa'),
    );

    expect(result).toEqual([200, 401, 200, 401, 200, 429]);
  });

  it('o 429 vem antes de verificar a senha: nem a senha certa entra depois do limite', async () => {
    const app = await appWith();
    await registerUser(app, 'bia', `${NET}3`);
    await statuses(5, () => loginReq(app, email('bia'), `${NET}4`, 'senha errada porém longa'));

    const response = await loginReq(app, email('bia'), `${NET}4`);

    expect(response.statusCode).toBe(429);
    expect(response.json<ErrorBody>().error.code).toBe('RATE_LIMITED');
    expect(Number(response.headers['retry-after'])).toBeGreaterThan(890);
    expect(response.body).not.toContain('accessToken');
  });

  it('concorrência real: 20 logins simultâneos do mesmo IP, exatamente 5 passam do limite', async () => {
    const app = await appWith();

    const responses = await Promise.all(
      Array.from({ length: 20 }, (_, i) => loginReq(app, email(`ninguem${i}`), `${NET}5`)),
    );

    const blocked = responses.filter((r) => r.statusCode === 429).length;
    expect(blocked).toBe(15);
    expect(responses.filter((r) => r.statusCode === 401)).toHaveLength(5);
  });
});

describe('contadores compartilhados e TTL no Redis', () => {
  it('duas instâncias da API somam no mesmo contador', async () => {
    const prefix = `${TEST_RATE_LIMIT_ROOT}:${randomUUID()}`;
    const first = await appWith({ RATE_LIMIT_KEY_PREFIX: prefix });
    const second = await appWith({ RATE_LIMIT_KEY_PREFIX: prefix });
    const ip = `${NET}6`;

    const result = [
      ...(await statuses(3, (i) => loginReq(first, email(`x${i}`), ip))),
      ...(await statuses(2, (i) => loginReq(second, email(`y${i}`), ip))),
      (await loginReq(first, email('z'), ip)).statusCode,
      (await loginReq(second, email('w'), ip)).statusCode,
    ];

    expect(result).toEqual([401, 401, 401, 401, 401, 429, 429]);
  });

  it('as chaves têm TTL da janela, namespace próprio e HMAC (sem email nem IP)', async () => {
    const prefix = `${TEST_RATE_LIMIT_ROOT}:${randomUUID()}`;
    const app = await appWith({ RATE_LIMIT_KEY_PREFIX: prefix });
    await loginReq(app, email('chave'), `${NET}7`);

    const [, keys] = await redis.scan('0', 'MATCH', `${prefix}:*`, 'COUNT', 100);
    expect(keys.sort()).toEqual([
      expect.stringMatching(new RegExp(`^${prefix}:loginAccount:account:[0-9a-f]{64}$`)),
      expect.stringMatching(new RegExp(`^${prefix}:loginIp:ip:[0-9a-f]{64}$`)),
    ]);
    expect(keys.join()).not.toMatch(/ratelimit-test|198\.51\.100/);
    for (const key of keys) {
      const ttl = await redis.pttl(key);
      expect(ttl).toBeGreaterThan(0);
      expect(ttl).toBeLessThanOrEqual(key.includes('loginIp') ? 900_000 : 3_600_000);
    }
  });

  it('o contador expira com a janela e libera de novo', async () => {
    const app = await appWith({ RATE_LIMIT_LOGIN_IP: '2/1s' });
    const ip = `${NET}8`;

    expect(await statuses(3, (i) => loginReq(app, email(`e${i}`), ip))).toEqual([401, 401, 429]);
    await new Promise((resolve) => setTimeout(resolve, 1_100));

    expect((await loginReq(app, email('depois'), ip)).statusCode).toBe(401);
  });

  it('a limpeza de testes recusa prefixos fora do namespace de testes', async () => {
    await expect(deleteTestKeys(redis, 'authapi:rl')).rejects.toThrow(/fora do namespace/);
  });
});

describe('login por conta (10 em 1 h, HMAC do email)', () => {
  it('protege a conta contra tentativas distribuídas em muitos IPs, com email normalizado', async () => {
    const app = await appWith();
    // Variações de caixa e espaços: o Zod normaliza antes, então é a MESMA conta.
    const variants = [email('alvo'), `  ${email('ALVO')} `, email('Alvo').toUpperCase()];

    const result = await statuses(11, (i) =>
      loginReq(app, variants[i % variants.length] ?? '', `${NET}${100 + i}`),
    );

    expect(result).toEqual([...Array<number>(10).fill(401), 429]);
  });

  it('IP e conta independentes: estourar o IP não bloqueia a conta para outro IP', async () => {
    const app = await appWith();
    await registerUser(app, 'vitima', `${NET}9`);
    await statuses(25, () =>
      loginReq(app, email('vitima'), `${NET}10`, 'senha errada porém longa'),
    );

    // De outro IP, a vítima ainda entra: só 5 das 25 tentativas chegaram ao limite da conta.
    expect((await loginReq(app, email('vitima'), `${NET}11`)).statusCode).toBe(200);
  });
});

describe('cadastro e refresh', () => {
  it('cadastro: 5 por IP em 1 h; a sexta conta não é criada', async () => {
    const app = await appWith();
    const ip = `${NET}12`;

    const result = await statuses(6, (i) =>
      app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: { name: 'Em Massa', email: email(`massa${i}`), password: PASSWORD },
        remoteAddress: ip,
      }),
    );

    expect(result).toEqual([201, 201, 201, 201, 201, 429]);
    expect(await prisma.user.count({ where: { email: email('massa5') } })).toBe(0);
  });

  it('refresh: 20 por IP em 15 min (tokens inválidos também contam)', async () => {
    const app = await appWith();

    const result = await statuses(21, () =>
      app.inject({
        method: 'POST',
        url: '/api/v1/auth/refresh',
        payload: { refreshToken: 'A'.repeat(43) },
        remoteAddress: `${NET}13`,
      }),
    );

    expect(result).toEqual([...Array<number>(20).fill(401), 429]);
  });
});

describe('compatibilidade com JWT e RBAC', () => {
  async function adminAndUser(app: FastifyInstance) {
    const admin = await registerUser(app, 'chefe', `${NET}20`);
    await prisma.user.update({ where: { id: admin.id }, data: { role: 'ADMIN' } });
    await registerUser(app, 'comum', `${NET}21`);
    return {
      admin: await tokenOf(app, 'chefe', `${NET}22`),
      user: await tokenOf(app, 'comum', `${NET}23`),
    };
  }
  const get = (app: FastifyInstance, url: string, token?: string) =>
    app.inject({
      method: 'GET',
      url,
      ...(token && { headers: { authorization: `Bearer ${token}` } }),
    } as InjectOptions);

  it('ADMIN: 30 consultas de auditoria por minuto, a 31ª recebe 429', async () => {
    const app = await appWith();
    const { admin } = await adminAndUser(app);

    const result = await statuses(31, () =>
      get(app, '/api/v1/admin/audit-events', admin.accessToken),
    );

    expect(result).toEqual([...Array<number>(30).fill(200), 429]);
  });

  it('anônimo recebe sempre 401 (a autenticação vem antes e não consome limite)', async () => {
    const app = await appWith();

    const result = await statuses(35, () => get(app, '/api/v1/admin/audit-events'));

    expect(new Set(result)).toEqual(new Set([401]));
  });

  it('USER insistindo em rota admin: 403 até o limite, depois 429 (contém ACCESS_DENIED)', async () => {
    const app = await appWith();
    const { user } = await adminAndUser(app);

    const result = await statuses(32, () =>
      get(app, '/api/v1/admin/audit-events', user.accessToken),
    );

    expect(result).toEqual([...Array<number>(30).fill(403), 429, 429]);
    const denied = await prisma.auditEvent.count({
      where: { type: 'ACCESS_DENIED', user: { email: email('comum') } },
    });
    expect(denied).toBe(30);
  });

  it('limites por usuário são isolados: o ADMIN que estourou não afeta outro usuário', async () => {
    const app = await appWith();
    const { admin, user } = await adminAndUser(app);
    const logoutAll = (token: string) =>
      app.inject({
        method: 'POST',
        url: '/api/v1/auth/logout-all',
        headers: { authorization: `Bearer ${token}` },
      });
    // logout-all revoga a sessão: geramos novas sessões para continuar autenticado.
    const results: number[] = [];
    for (let i = 0; i < 6; i++) {
      const fresh = await tokenOf(app, 'chefe', `${NET}${30 + i}`);
      results.push((await logoutAll(fresh.accessToken)).statusCode);
    }

    expect(results).toEqual([204, 204, 204, 204, 204, 429]);
    expect((await logoutAll(user.accessToken)).statusCode).toBe(204);
    expect(admin.accessToken).toBeTruthy();
  });
});

describe('auditoria do rate limit', () => {
  it('um único RATE_LIMIT_EXCEEDED por chave e janela, sem email em texto', async () => {
    const app = await appWith();
    await statuses(40, (i) => loginReq(app, email(`a${i}`), `${NET}40`));
    for (let i = 0; i < 12; i++) await loginReq(app, email('conta.alvo'), `${NET}${150 + i}`);

    const events = await prisma.auditEvent.findMany({
      where: { type: 'RATE_LIMIT_EXCEEDED', ip: { startsWith: NET } },
      orderBy: { createdAt: 'asc' },
    });
    expect(events.map((e) => [e.ip, e.metadata])).toEqual([
      [`${NET}40`, { policy: 'loginIp', scope: 'ip', limit: 5, windowSeconds: 900 }],
      [`${NET}160`, { policy: 'loginAccount', scope: 'account', limit: 10, windowSeconds: 3600 }],
    ]);
    expect(events[1]?.emailHash).toBe(hashEmail(email('conta.alvo')));
    expect(JSON.stringify(events)).not.toContain(DOMAIN);
  });
});

describe('Redis indisponível', () => {
  const down = { REDIS_URL: 'redis://127.0.0.1:1' };

  it('login, cadastro e refresh: 503 SERVICE_UNAVAILABLE, nunca 401', async () => {
    const app = await appWith(down, { connectRedis: false });

    const responses = await Promise.all([
      loginReq(app, email('qualquer'), `${NET}50`),
      app.inject({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: { name: 'X', email: email('novo'), password: PASSWORD },
      }),
      app.inject({ method: 'POST', url: '/api/v1/auth/refresh', payload: { refreshToken: 'x' } }),
    ]);

    for (const response of responses) {
      expect(response.statusCode).toBe(503);
      expect(response.json<ErrorBody>().error.code).toBe('SERVICE_UNAVAILABLE');
      expect(response.body).not.toMatch(/redis|6379|127\.0\.0\.1:1|ECONNREFUSED|stream/i);
    }
    expect(await prisma.user.count({ where: { email: email('novo') } })).toBe(0);
  });

  it('logout continua funcionando (fail-open) e /health segue 200', async () => {
    const healthy = await appWith();
    await registerUser(healthy, 'sai', `${NET}51`);
    const { accessToken } = await tokenOf(healthy, 'sai', `${NET}52`);
    const app = await appWith(down, { connectRedis: false });

    const logout = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/logout',
      headers: { authorization: `Bearer ${accessToken}` },
    });

    expect(logout.statusCode).toBe(204);
    expect((await app.inject({ method: 'GET', url: '/health' })).statusCode).toBe(200);
  });
});

describe('logs', () => {
  it('429 e Redis fora do ar não registram emails, chaves nem HMACs', async () => {
    const lines: string[] = [];
    const logDestination = { write: (line: string) => void lines.push(line) };
    const app = await appWith({ LOG_LEVEL: 'trace' }, { logDestination });
    await statuses(7, () => loginReq(app, email('privado'), `${NET}60`));
    const broken = await appWith(
      { LOG_LEVEL: 'trace', REDIS_URL: 'redis://127.0.0.1:1' },
      { logDestination, connectRedis: false },
    );
    await loginReq(broken, email('privado'), `${NET}60`);

    const log = lines.join('');
    expect(log).toContain('rate limit excedido');
    expect(log).toContain('rate limit indisponível');
    expect(log).not.toContain('privado');
    expect(log).not.toContain(TEST_RATE_LIMIT_ROOT);
    expect(log).not.toMatch(/[0-9a-f]{64}/);
    expect(log).not.toContain(PASSWORD);
  });
});
