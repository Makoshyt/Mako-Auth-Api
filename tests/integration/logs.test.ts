import type { FastifyInstance, InjectOptions } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createPrismaClient, type PrismaClient } from '../../src/infra/prisma.js';
import { buildTestApp } from '../helpers/build-test-app.js';
import { TEST_DATABASE_URL } from '../helpers/test-env.js';
import { purgeAuditEvents } from '../helpers/purge-audit-events.js';

const DOMAIN = '@logs-test.example.com';
const PASSWORD = 'frase secreta que nunca pode ir para o log';
const WRONG_PASSWORD = 'outra frase errada que também não pode';

interface TokenPairBody {
  accessToken: string;
  refreshToken: string;
}

let app: FastifyInstance;
let prisma: PrismaClient;
const lines: string[] = [];

async function cleanup() {
  await purgeAuditEvents(prisma, { where: { user: { email: { endsWith: DOMAIN } } } });
  await prisma.user.deleteMany({ where: { email: { endsWith: DOMAIN } } });
}

beforeAll(async () => {
  prisma = createPrismaClient(TEST_DATABASE_URL);
  await cleanup();
  // Nível trace: o máximo de detalhe que o servidor consegue registrar.
  app = await buildTestApp(
    { LOG_LEVEL: 'trace' },
    { logDestination: { write: (line: string) => void lines.push(line) } },
  );
});

afterAll(async () => {
  await cleanup();
  await prisma.$disconnect();
  await app.close();
});

describe('logs', () => {
  it('o fluxo completo de autenticação não registra senhas, hashes nem tokens', async () => {
    const call = (options: InjectOptions) => app.inject(options);
    const userEmail = `log.user${DOMAIN}`;

    await call({
      method: 'POST',
      url: '/api/v1/auth/register',
      payload: { name: 'Log User', email: userEmail, password: PASSWORD },
    });
    await call({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: userEmail, password: WRONG_PASSWORD },
    });
    const first = (
      await call({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: userEmail, password: PASSWORD },
      })
    ).json<TokenPairBody>();
    const auth = { authorization: `Bearer ${first.accessToken}` };

    await call({ method: 'GET', url: '/api/v1/users/me', headers: auth });
    const second = (
      await call({
        method: 'POST',
        url: '/api/v1/auth/refresh',
        payload: { refreshToken: first.refreshToken },
      })
    ).json<TokenPairBody>();
    await call({
      method: 'POST',
      url: '/api/v1/auth/refresh',
      payload: { refreshToken: first.refreshToken }, // reuso: 409
    });
    const auth2 = { authorization: `Bearer ${second.accessToken}` };
    await call({
      method: 'PATCH',
      url: '/api/v1/users/me',
      headers: auth2,
      payload: { email: `log.novo${DOMAIN}`, currentPassword: WRONG_PASSWORD }, // 403
    });
    await call({
      method: 'PATCH',
      url: '/api/v1/users/me',
      headers: auth2,
      payload: { email: `log.novo${DOMAIN}`, currentPassword: PASSWORD },
    });
    await call({ method: 'POST', url: '/api/v1/auth/logout', headers: auth2 });

    const log = lines.join('');
    // Sanidade: os logs de requisição foram mesmo capturados.
    expect(log).toContain('incoming request');
    expect(log).toContain('/api/v1/auth/login');

    const secrets = [
      PASSWORD,
      WRONG_PASSWORD,
      first.accessToken,
      first.refreshToken,
      second.accessToken,
      second.refreshToken,
    ];
    for (const secret of secrets) expect(log).not.toContain(secret);
    expect(log).not.toMatch(/argon2|passwordHash|authorization/i);
  });

  it('o fluxo administrativo (200, 403, 404, 400) não registra credenciais nem dados pessoais', async () => {
    lines.length = 0;
    const call = (options: InjectOptions) => app.inject(options);
    const adminEmail = `log.admin${DOMAIN}`;
    const userEmail = `log.comum${DOMAIN}`;
    for (const email of [adminEmail, userEmail]) {
      await call({
        method: 'POST',
        url: '/api/v1/auth/register',
        payload: { name: 'Log Admin', email, password: PASSWORD },
      });
    }
    await prisma.user.update({ where: { email: adminEmail }, data: { role: 'ADMIN' } });
    const tokenOf = async (email: string) =>
      (
        await call({
          method: 'POST',
          url: '/api/v1/auth/login',
          payload: { email, password: PASSWORD },
        })
      ).json<TokenPairBody>();
    const admin = await tokenOf(adminEmail);
    const user = await tokenOf(userEmail);
    const as = (token: string) => ({ authorization: `Bearer ${token}` });

    await call({
      method: 'GET',
      url: '/api/v1/admin/users?pageSize=100',
      headers: as(admin.accessToken),
    });
    await call({
      method: 'GET',
      url: '/api/v1/admin/audit-events',
      headers: as(admin.accessToken),
    });
    await call({
      method: 'GET',
      url: '/api/v1/admin/users/0190a000-0000-7000-8000-0000000000ff',
      headers: as(admin.accessToken),
    }); // 404
    await call({
      method: 'GET',
      url: '/api/v1/admin/users?pageSize=999',
      headers: as(admin.accessToken),
    }); // 400
    await call({ method: 'GET', url: '/api/v1/admin/users', headers: as(user.accessToken) }); // 403
    // Filtro por email na query string: o email não pode aparecer no log da requisição.
    await call({
      method: 'GET',
      url: `/api/v1/admin/users?email=${encodeURIComponent(userEmail)}`,
      headers: as(admin.accessToken),
    });

    const log = lines.join('');
    expect(log).toContain('"url":"/api/v1/admin/users"');
    for (const secret of [
      PASSWORD,
      admin.accessToken,
      admin.refreshToken,
      user.accessToken,
      user.refreshToken,
    ]) {
      expect(log).not.toContain(secret);
    }
    expect(log).not.toMatch(/argon2|passwordHash|authorization/i);
    // As respostas (com emails dos usuários) não vão para o log; só método, URL e status.
    for (const email of [adminEmail, userEmail]) {
      expect(log).not.toContain(email);
      expect(log).not.toContain(encodeURIComponent(email)); // forma em que aparece na URL
    }
    expect(log).not.toContain('email=');
  });
});
