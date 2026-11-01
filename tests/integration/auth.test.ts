import { SignJWT } from 'jose';
import type { FastifyInstance, InjectOptions } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createPrismaClient, type PrismaClient } from '../../src/infra/prisma.js';
import { hashEmail } from '../../src/modules/audit/audit.recorder.js';
import { requireRole } from '../../src/modules/auth/auth.middleware.js';
import { createAccessTokenSigner } from '../../src/modules/auth/tokens.js';
import type { ErrorBody } from '../../src/shared/error-handler.js';
import { buildTestApp } from '../helpers/build-test-app.js';
import { TEST_DATABASE_URL, TEST_JWT_SECRET } from '../helpers/test-env.js';

/** Todos os dados usam este domínio fictício e são removidos antes e depois. */
const DOMAIN = '@auth-test.example.com';
const email = (local: string) => `${local}${DOMAIN}`;
const PASSWORD = 'cavalo correto bateria grampo';
const UNKNOWN_EMAIL = email('nao-existe');

interface TokenPairBody {
  accessToken: string;
  tokenType: string;
  expiresIn: number;
  refreshToken: string;
  refreshTokenExpiresAt: string;
}

let app: FastifyInstance;
let prisma: PrismaClient;

const call = (options: InjectOptions) => app.inject(options);
const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

async function registerUser(local: string, name = 'Pessoa Fictícia') {
  const response = await call({
    method: 'POST',
    url: '/api/v1/auth/register',
    payload: { name, email: email(local), password: PASSWORD },
  });
  expect(response.statusCode).toBe(201);
  return response.json<{ id: string; email: string }>();
}

const loginRequest = (emailAddress: string, password = PASSWORD) =>
  call({ method: 'POST', url: '/api/v1/auth/login', payload: { email: emailAddress, password } });

async function login(local: string): Promise<TokenPairBody> {
  const response = await loginRequest(email(local));
  expect(response.statusCode).toBe(200);
  return response.json<TokenPairBody>();
}

const refresh = (refreshToken: string) =>
  call({ method: 'POST', url: '/api/v1/auth/refresh', payload: { refreshToken } });

const me = (token: string) =>
  call({ method: 'GET', url: '/api/v1/users/me', headers: bearer(token) });

const sessionIdOf = (accessToken: string) =>
  (
    JSON.parse(Buffer.from(accessToken.split('.')[1] ?? '', 'base64url').toString()) as {
      sid: string;
    }
  ).sid;

async function cleanup() {
  await prisma.auditEvent.deleteMany({
    where: {
      OR: [{ user: { email: { endsWith: DOMAIN } } }, { emailHash: hashEmail(UNKNOWN_EMAIL) }],
    },
  });
  // Cascade: sessões e refresh tokens dos usuários de teste vão junto.
  await prisma.user.deleteMany({ where: { email: { endsWith: DOMAIN } } });
}

beforeAll(async () => {
  app = await buildTestApp();
  // Recurso exclusivo de ADMIN, só neste app de teste: não existe rota administrativa pública.
  app.get(
    '/api/v1/__test__/admin-only',
    { preHandler: [app.authenticate, requireRole('ADMIN')] },
    async () => ({ ok: true }),
  );
  prisma = createPrismaClient(TEST_DATABASE_URL);
});

beforeEach(cleanup);

afterAll(async () => {
  await cleanup();
  await prisma.$disconnect();
  await app.close();
});

describe('POST /api/v1/auth/login', () => {
  it('200 com par de tokens; cria a sessão no PostgreSQL e audita LOGIN_SUCCESS', async () => {
    const user = await registerUser('ana');

    const response = await loginRequest(`  ANA${DOMAIN.toUpperCase()} `);

    expect(response.statusCode).toBe(200);
    const body = response.json<TokenPairBody>();
    expect(body).toMatchObject({ tokenType: 'Bearer', expiresIn: 900 });
    expect(body.refreshToken).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const session = await prisma.session.findUniqueOrThrow({
      where: { id: sessionIdOf(body.accessToken) },
      include: { refreshTokens: true },
    });
    expect(session).toMatchObject({ userId: user.id, revokedAt: null, ip: '127.0.0.1' });
    // expires_at vem do relógio da aplicação e created_at do now() do PostgreSQL: tolerância de 5 s.
    const lifetimeMs = session.expiresAt.getTime() - session.createdAt.getTime();
    expect(Math.abs(lifetimeMs - 30 * 86_400_000)).toBeLessThan(5_000);
    // Só o hash do refresh token é persistido.
    expect(session.refreshTokens).toHaveLength(1);
    expect(session.refreshTokens[0]?.tokenHash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(session)).not.toContain(body.refreshToken);

    const audit = await prisma.auditEvent.findMany({ where: { userId: user.id } });
    expect(audit.map((event) => event.type)).toEqual(['LOGIN_SUCCESS']);
    expect(audit[0]?.emailHash).toBe(hashEmail(email('ana')));
  });

  it('senha incorreta e email inexistente: mesma resposta 401, sem sessão', async () => {
    const user = await registerUser('bia');

    const wrongPassword = await loginRequest(email('bia'), 'senha errada porém longa');
    const unknownEmail = await loginRequest(UNKNOWN_EMAIL);

    for (const response of [wrongPassword, unknownEmail]) {
      expect(response.statusCode).toBe(401);
      expect(response.json<ErrorBody>().error).toMatchObject({
        code: 'INVALID_CREDENTIALS',
        message: 'Email ou senha inválidos',
      });
    }
    expect(await prisma.session.count({ where: { userId: user.id } })).toBe(0);

    const failures = await prisma.auditEvent.findMany({
      where: {
        type: 'LOGIN_FAILURE',
        emailHash: { in: [hashEmail(email('bia')), hashEmail(UNKNOWN_EMAIL)] },
      },
      orderBy: { createdAt: 'asc' },
    });
    expect(failures.map((event) => event.metadata)).toEqual([
      { reason: 'INVALID_PASSWORD' },
      { reason: 'UNKNOWN_EMAIL' },
    ]);
  });

  it('400 para campos extras (ex.: role) e corpo inválido', async () => {
    await registerUser('carla');

    const withRole = await call({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: email('carla'), password: PASSWORD, role: 'ADMIN' },
    });
    const empty = await call({ method: 'POST', url: '/api/v1/auth/login', payload: {} });

    expect(withRole.statusCode).toBe(400);
    expect(empty.statusCode).toBe(400);
  });
});

describe('access token e middleware authenticate', () => {
  it('JWT válido: GET /users/me devolve o próprio perfil, sem dados sensíveis', async () => {
    const user = await registerUser('davi', 'Davi Ficticio');
    const { accessToken } = await login('davi');

    const response = await me(accessToken);

    expect(response.statusCode).toBe(200);
    const body = response.json<Record<string, unknown>>();
    expect(Object.keys(body).sort()).toEqual(
      ['createdAt', 'email', 'id', 'name', 'role', 'updatedAt'].sort(),
    );
    expect(body).toMatchObject({
      id: user.id,
      name: 'Davi Ficticio',
      email: email('davi'),
      role: 'USER',
    });
    expect(response.body).not.toMatch(/password|argon2|session/i);
  });

  it('401 UNAUTHORIZED sem token', async () => {
    const response = await call({ method: 'GET', url: '/api/v1/users/me' });

    expect(response.statusCode).toBe(401);
    expect(response.json<ErrorBody>().error.code).toBe('UNAUTHORIZED');
  });

  it.each([
    ['lixo', 'Bearer nao-e-um-jwt'],
    ['esquema Basic', 'Basic dXNlcjpwYXNz'],
  ])('401 com token inválido (%s)', async (_label, authorization) => {
    const response = await call({
      method: 'GET',
      url: '/api/v1/users/me',
      headers: { authorization },
    });

    expect(response.statusCode).toBe(401);
  });

  it('401 TOKEN_EXPIRED para JWT expirado de uma sessão ativa', async () => {
    const user = await registerUser('elis');
    const { accessToken } = await login('elis');
    const signer = createAccessTokenSigner(TEST_JWT_SECRET, 900);
    const expired = await signer.sign(
      { userId: user.id, sessionId: sessionIdOf(accessToken), role: 'USER' },
      new Date(Date.now() - 16 * 60 * 1000),
    );

    const response = await me(expired);

    expect(response.statusCode).toBe(401);
    expect(response.json<ErrorBody>().error.code).toBe('TOKEN_EXPIRED');
  });

  it('401 INVALID_TOKEN para JWT adulterado (role: ADMIN com a assinatura original)', async () => {
    await registerUser('fabio');
    const { accessToken } = await login('fabio');
    const [header, payload, signature] = accessToken.split('.');
    const claims = JSON.parse(Buffer.from(payload ?? '', 'base64url').toString()) as object;
    const forged = Buffer.from(JSON.stringify({ ...claims, role: 'ADMIN' })).toString('base64url');

    const response = await me(`${header ?? ''}.${forged}.${signature ?? ''}`);

    expect(response.statusCode).toBe(401);
    expect(response.json<ErrorBody>().error.code).toBe('INVALID_TOKEN');
  });

  it('401 para algoritmos inesperados: none e HS512 (mesmo com o segredo certo)', async () => {
    const user = await registerUser('gil');
    const { accessToken } = await login('gil');
    const iat = Math.floor(Date.now() / 1000);
    const payload = {
      sub: user.id,
      sid: sessionIdOf(accessToken),
      role: 'ADMIN',
      iat,
      exp: iat + 900,
      iss: 'authapi-pro',
      aud: 'authapi-pro:api',
    };
    const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const noneToken = `${b64({ alg: 'none', typ: 'JWT' })}.${b64(payload)}.`;
    const hs512 = await new SignJWT(payload)
      .setProtectedHeader({ alg: 'HS512', typ: 'JWT' })
      .sign(new TextEncoder().encode(TEST_JWT_SECRET));

    for (const token of [noneToken, hs512]) {
      const response = await me(token);
      expect(response.statusCode).toBe(401);
      expect(response.json<ErrorBody>().error.code).toBe('INVALID_TOKEN');
    }
  });

  it('401 INVALID_SESSION para sessão revogada (JWT ainda dentro do prazo)', async () => {
    await registerUser('hugo');
    const { accessToken } = await login('hugo');
    await prisma.session.update({
      where: { id: sessionIdOf(accessToken) },
      data: { revokedAt: new Date(), revokedReason: 'LOGOUT' },
    });

    const response = await me(accessToken);

    expect(response.statusCode).toBe(401);
    expect(response.json<ErrorBody>().error.code).toBe('INVALID_SESSION');
  });

  it('401 para sessão expirada, no access token e no refresh', async () => {
    await registerUser('iris');
    const { accessToken, refreshToken } = await login('iris');
    const dayMs = 86_400_000;
    // created_at também recua: o CHECK exige expires_at > created_at.
    await prisma.session.update({
      where: { id: sessionIdOf(accessToken) },
      data: {
        createdAt: new Date(Date.now() - 31 * dayMs),
        expiresAt: new Date(Date.now() - 1000),
      },
    });

    expect((await me(accessToken)).json<ErrorBody>().error.code).toBe('INVALID_SESSION');
    expect((await refresh(refreshToken)).statusCode).toBe(401);
  });

  it('ignora userId e role enviados em query, body ou headers arbitrários', async () => {
    await registerUser('joao');
    const other = await registerUser('kaio');
    const { accessToken } = await login('joao');

    const viaQuery = await call({
      method: 'GET',
      url: `/api/v1/users/me?userId=${other.id}&role=ADMIN`,
      headers: { ...bearer(accessToken), 'x-user-id': other.id, 'x-user-role': 'ADMIN' },
    });

    expect(viaQuery.statusCode).toBe(200);
    expect(viaQuery.json()).toMatchObject({ email: email('joao'), role: 'USER' });
  });
});

describe('requireRole', () => {
  it('403 FORBIDDEN para USER em recurso ADMIN; 401 sem token', async () => {
    await registerUser('lara');
    const { accessToken } = await login('lara');

    const asUser = await call({
      method: 'GET',
      url: '/api/v1/__test__/admin-only',
      headers: bearer(accessToken),
    });
    const anonymous = await call({ method: 'GET', url: '/api/v1/__test__/admin-only' });

    expect(asUser.statusCode).toBe(403);
    expect(asUser.json<ErrorBody>().error.code).toBe('FORBIDDEN');
    expect(anonymous.statusCode).toBe(401);
  });

  it('o papel vem do banco a cada requisição: promoção e rebaixamento valem na hora', async () => {
    const user = await registerUser('marta');
    const { accessToken } = await login('marta');
    const adminOnly = () =>
      call({ method: 'GET', url: '/api/v1/__test__/admin-only', headers: bearer(accessToken) });

    await prisma.user.update({ where: { id: user.id }, data: { role: 'ADMIN' } });
    expect((await adminOnly()).statusCode).toBe(200);

    await prisma.user.update({ where: { id: user.id }, data: { role: 'USER' } });
    expect((await adminOnly()).statusCode).toBe(403);
  });
});

describe('POST /api/v1/auth/refresh', () => {
  it('rotaciona: par novo, token antigo consumido no banco, sessão preservada', async () => {
    await registerUser('nina');
    const first = await login('nina');

    const response = await refresh(first.refreshToken);

    expect(response.statusCode).toBe(200);
    const second = response.json<TokenPairBody>();
    expect(second.refreshToken).not.toBe(first.refreshToken);
    expect(sessionIdOf(second.accessToken)).toBe(sessionIdOf(first.accessToken));
    expect((await me(second.accessToken)).statusCode).toBe(200);

    const tokens = await prisma.refreshToken.findMany({
      where: { sessionId: sessionIdOf(first.accessToken) },
      orderBy: { createdAt: 'asc' },
    });
    expect(tokens).toHaveLength(2);
    expect(tokens[0]?.usedAt).not.toBeNull();
    expect(tokens[1]?.usedAt).toBeNull();
  });

  it('401 INVALID_REFRESH_TOKEN para token desconhecido', async () => {
    const response = await refresh('A'.repeat(43));

    expect(response.statusCode).toBe(401);
    expect(response.json<ErrorBody>().error.code).toBe('INVALID_REFRESH_TOKEN');
  });

  it('concorrência real: 5 refreshes simultâneos do mesmo token = um 200 e quatro 409', async () => {
    await registerUser('otto');
    const { refreshToken, accessToken } = await login('otto');

    const responses = await Promise.all(Array.from({ length: 5 }, () => refresh(refreshToken)));

    const statuses = responses.map((response) => response.statusCode).sort();
    expect(statuses).toEqual([200, 409, 409, 409, 409]);
    for (const response of responses.filter((r) => r.statusCode === 409)) {
      expect(response.json<ErrorBody>().error.code).toBe('REFRESH_TOKEN_ALREADY_ROTATED');
      expect(response.body).not.toContain('refreshToken');
    }

    const sessionId = sessionIdOf(accessToken);
    const session = await prisma.session.findUniqueOrThrow({ where: { id: sessionId } });
    expect(session.revokedAt).toBeNull();
    // Exatamente um sucessor: nunca duas emissões a partir do mesmo token.
    expect(await prisma.refreshToken.count({ where: { sessionId } })).toBe(2);

    const winner = responses.find((r) => r.statusCode === 200)?.json<TokenPairBody>();
    expect((await refresh(winner?.refreshToken ?? '')).statusCode).toBe(200);
  });

  it('reuso dentro da janela de tolerância: 409 sem novos tokens e sem revogar', async () => {
    await registerUser('paulo');
    const first = await login('paulo');
    await refresh(first.refreshToken);

    const reuse = await refresh(first.refreshToken);

    expect(reuse.statusCode).toBe(409);
    const sessionId = sessionIdOf(first.accessToken);
    expect(await prisma.session.findUniqueOrThrow({ where: { id: sessionId } })).toMatchObject({
      revokedAt: null,
    });
    expect(await prisma.refreshToken.count({ where: { sessionId } })).toBe(2);
  });

  it('reuso fora da janela: 401, sessão inteira revogada e evento TOKEN_REUSE_DETECTED', async () => {
    const user = await registerUser('quezia');
    const first = await login('quezia');
    const second = (await refresh(first.refreshToken)).json<TokenPairBody>();
    const sessionId = sessionIdOf(first.accessToken);
    // Simula a passagem de 11 s desde a rotação.
    await prisma.refreshToken.updateMany({
      where: { sessionId, usedAt: { not: null } },
      data: { usedAt: new Date(Date.now() - 11_000) },
    });

    const reuse = await refresh(first.refreshToken);

    expect(reuse.statusCode).toBe(401);
    expect(reuse.json<ErrorBody>().error.code).toBe('REFRESH_TOKEN_REUSED');
    expect(await prisma.session.findUniqueOrThrow({ where: { id: sessionId } })).toMatchObject({
      revokedReason: 'TOKEN_REUSE',
    });
    // A família inteira cai, inclusive o par mais recente.
    expect((await refresh(second.refreshToken)).statusCode).toBe(401);
    expect((await me(second.accessToken)).statusCode).toBe(401);
    expect(
      await prisma.auditEvent.count({ where: { userId: user.id, type: 'TOKEN_REUSE_DETECTED' } }),
    ).toBe(1);
  });
});

describe('logout e logout-all', () => {
  it('logout: 204, access e refresh da sessão param na hora; repetição dá 401', async () => {
    await registerUser('rita');
    const { accessToken, refreshToken } = await login('rita');
    const logout = () =>
      call({ method: 'POST', url: '/api/v1/auth/logout', headers: bearer(accessToken) });

    const first = await logout();

    expect(first.statusCode).toBe(204);
    expect(first.body).toBe('');
    expect((await me(accessToken)).statusCode).toBe(401);
    expect((await refresh(refreshToken)).statusCode).toBe(401);
    expect(
      await prisma.session.findUniqueOrThrow({ where: { id: sessionIdOf(accessToken) } }),
    ).toMatchObject({ revokedReason: 'LOGOUT' });

    // O token pertence a uma sessão encerrada: a resposta é sempre a mesma.
    const again = await logout();
    expect(again.statusCode).toBe(401);
    expect(again.json<ErrorBody>().error.code).toBe('INVALID_SESSION');
  });

  it('logout não derruba outras sessões do mesmo usuário', async () => {
    await registerUser('sara');
    const phone = await login('sara');
    const laptop = await login('sara');

    await call({ method: 'POST', url: '/api/v1/auth/logout', headers: bearer(phone.accessToken) });

    expect((await me(laptop.accessToken)).statusCode).toBe(200);
  });

  it('logout-all: revoga todas as sessões do usuário (LOGOUT_ALL)', async () => {
    const user = await registerUser('tais');
    const phone = await login('tais');
    const laptop = await login('tais');

    const response = await call({
      method: 'POST',
      url: '/api/v1/auth/logout-all',
      headers: bearer(phone.accessToken),
    });

    expect(response.statusCode).toBe(204);
    for (const pair of [phone, laptop]) {
      expect((await me(pair.accessToken)).statusCode).toBe(401);
      expect((await refresh(pair.refreshToken)).statusCode).toBe(401);
    }
    const sessions = await prisma.session.findMany({ where: { userId: user.id } });
    expect(sessions.map((session) => session.revokedReason)).toEqual(['LOGOUT_ALL', 'LOGOUT_ALL']);
  });

  it('logout e logout-all sem token: 401', async () => {
    for (const url of ['/api/v1/auth/logout', '/api/v1/auth/logout-all']) {
      expect((await call({ method: 'POST', url })).statusCode).toBe(401);
    }
  });
});

describe('PATCH /api/v1/users/me', () => {
  const patch = (token: string, payload: Record<string, unknown>) =>
    call({ method: 'PATCH', url: '/api/v1/users/me', headers: bearer(token), payload });

  it('atualiza o nome do próprio usuário sem exigir senha', async () => {
    const user = await registerUser('ugo', 'Ugo Antigo');
    const { accessToken } = await login('ugo');

    const response = await patch(accessToken, { name: 'Ugo Novo' });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ id: user.id, name: 'Ugo Novo', email: email('ugo') });
    expect(response.body).not.toMatch(/password|argon2/i);
  });

  it('troca de email com a senha correta: grava, mantém a sessão atual, revoga as demais', async () => {
    await registerUser('vera');
    const current = await login('vera');
    const other = await login('vera');

    const response = await patch(current.accessToken, {
      email: `  VERA.NOVA${DOMAIN.toUpperCase()} `,
      currentPassword: PASSWORD,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ email: email('vera.nova') });
    expect((await me(current.accessToken)).statusCode).toBe(200);
    expect((await me(other.accessToken)).statusCode).toBe(401);
    expect((await refresh(other.refreshToken)).statusCode).toBe(401);
    expect(
      await prisma.session.findUniqueOrThrow({ where: { id: sessionIdOf(other.accessToken) } }),
    ).toMatchObject({ revokedReason: 'EMAIL_CHANGE' });
    // Login passa a funcionar só com o email novo.
    expect((await loginRequest(email('vera.nova'))).statusCode).toBe(200);
    expect((await loginRequest(email('vera'))).statusCode).toBe(401);
  });

  it('troca de email com senha incorreta: 403 e nada muda', async () => {
    await registerUser('wagner');
    const current = await login('wagner');
    const other = await login('wagner');

    const response = await patch(current.accessToken, {
      email: email('wagner.novo'),
      currentPassword: 'senha errada porém longa',
    });

    expect(response.statusCode).toBe(403);
    expect(response.json<ErrorBody>().error.code).toBe('INVALID_CURRENT_PASSWORD');
    expect((await me(current.accessToken)).json()).toMatchObject({ email: email('wagner') });
    expect((await me(other.accessToken)).statusCode).toBe(200);
  });

  it('troca de email sem a senha atual: 400', async () => {
    await registerUser('xena');
    const { accessToken } = await login('xena');

    const response = await patch(accessToken, { email: email('xena.nova') });

    expect(response.statusCode).toBe(400);
    expect(response.json<ErrorBody>().error.details).toEqual([
      expect.objectContaining({ field: 'body.currentPassword' }),
    ]);
  });

  it('409 ao trocar para o email de outro usuário', async () => {
    await registerUser('yara');
    await registerUser('zeca');
    const { accessToken } = await login('yara');

    const response = await patch(accessToken, { email: email('zeca'), currentPassword: PASSWORD });

    expect(response.statusCode).toBe(409);
  });

  it('tentativa de alterar role (ou passwordHash, id): 400 e o banco não muda', async () => {
    const user = await registerUser('alan');
    const { accessToken } = await login('alan');

    for (const extra of [{ role: 'ADMIN' }, { passwordHash: 'x' }, { id: crypto.randomUUID() }]) {
      const response = await patch(accessToken, { name: 'Alan Admin', ...extra });
      expect(response.statusCode).toBe(400);
    }
    const row = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(row).toMatchObject({ role: 'USER', name: 'Pessoa Fictícia' });
  });
});

describe('isolamento entre usuários', () => {
  it('cada token só enxerga e altera o próprio usuário; logout-all não afeta outros', async () => {
    const ana = await registerUser('iso.ana', 'Ana Iso');
    const beto = await registerUser('iso.beto', 'Beto Iso');
    const anaTokens = await login('iso.ana');
    const betoTokens = await login('iso.beto');

    expect((await me(anaTokens.accessToken)).json()).toMatchObject({ id: ana.id });
    expect((await me(betoTokens.accessToken)).json()).toMatchObject({ id: beto.id });

    await call({
      method: 'PATCH',
      url: '/api/v1/users/me',
      headers: bearer(anaTokens.accessToken),
      payload: { name: 'Ana Alterada' },
    });
    await call({
      method: 'POST',
      url: '/api/v1/auth/logout-all',
      headers: bearer(anaTokens.accessToken),
    });

    const betoNow = await me(betoTokens.accessToken);
    expect(betoNow.statusCode).toBe(200);
    expect(betoNow.json()).toMatchObject({ name: 'Beto Iso' });
    expect((await refresh(betoTokens.refreshToken)).statusCode).toBe(200);
  });
});

describe('OpenAPI', () => {
  it('documenta as rotas de auth e marca as protegidas com bearerAuth', async () => {
    const spec = (await call({ method: 'GET', url: '/docs/json' })).json<{
      paths: Record<string, Record<string, { security?: unknown }>>;
    }>();

    for (const path of ['/api/v1/auth/login', '/api/v1/auth/refresh']) {
      expect(spec.paths[path]?.post?.security).toBeUndefined();
    }
    for (const path of ['/api/v1/auth/logout', '/api/v1/auth/logout-all']) {
      expect(spec.paths[path]?.post?.security).toEqual([{ bearerAuth: [] }]);
    }
  });
});
