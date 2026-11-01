import type { FastifyInstance, InjectOptions } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createPrismaClient, type PrismaClient } from '../../src/infra/prisma.js';
import { createAccessTokenSigner } from '../../src/modules/auth/tokens.js';
import type { ErrorBody } from '../../src/shared/error-handler.js';
import { buildTestApp } from '../helpers/build-test-app.js';
import { TEST_DATABASE_URL, TEST_JWT_SECRET } from '../helpers/test-env.js';

/** Todos os dados usam este domínio fictício e são removidos antes e depois. */
const DOMAIN = '@admin-test.example.com';
const email = (local: string) => `${local}${DOMAIN}`;
const PASSWORD = 'cavalo correto bateria grampo';

interface PublicUserBody {
  id: string;
  name: string;
  email: string;
  role: string;
  createdAt: string;
  updatedAt: string;
}
interface ListBody<T> {
  data: T[];
  pagination: { page: number; pageSize: number; total: number; totalPages: number };
}
interface AuditEventBody {
  id: string;
  type: string;
  userId: string | null;
  ip: string | null;
  metadata: Record<string, unknown> | null;
  createdAt: string;
}

let app: FastifyInstance;
let prisma: PrismaClient;

const call = (options: InjectOptions) => app.inject(options);
const get = (url: string, token?: string) =>
  call({ method: 'GET', url, ...(token && { headers: { authorization: `Bearer ${token}` } }) });

async function registerUser(local: string, name = `Pessoa ${local}`) {
  const response = await call({
    method: 'POST',
    url: '/api/v1/auth/register',
    payload: { name, email: email(local), password: PASSWORD },
  });
  expect(response.statusCode).toBe(201);
  return response.json<PublicUserBody>();
}

async function login(local: string) {
  const response = await call({
    method: 'POST',
    url: '/api/v1/auth/login',
    payload: { email: email(local), password: PASSWORD },
  });
  expect(response.statusCode).toBe(200);
  return response.json<{ accessToken: string }>().accessToken;
}

const setRole = (id: string, role: 'USER' | 'ADMIN') =>
  prisma.user.update({ where: { id }, data: { role } });

/** Um ADMIN e um USER prontos, com tokens de sessões reais. */
async function actors() {
  const admin = await registerUser('chefe', 'Chefe Admin');
  await setRole(admin.id, 'ADMIN');
  const user = await registerUser('comum', 'Pessoa Comum');
  return {
    admin,
    user,
    adminToken: await login('chefe'),
    userToken: await login('comum'),
  };
}

const scoped = (query: string) =>
  `/api/v1/admin/users?email=${encodeURIComponent(DOMAIN)}${query ? `&${query}` : ''}`;

async function cleanup() {
  await prisma.auditEvent.deleteMany({ where: { user: { email: { endsWith: DOMAIN } } } });
  await prisma.user.deleteMany({ where: { email: { endsWith: DOMAIN } } });
}

beforeAll(async () => {
  app = await buildTestApp();
  prisma = createPrismaClient(TEST_DATABASE_URL);
});

beforeEach(cleanup);

afterAll(async () => {
  await cleanup();
  await prisma.$disconnect();
  await app.close();
});

const ADMIN_ROUTES = [
  '/api/v1/admin/users',
  '/api/v1/admin/users/0190a000-0000-7000-8000-000000000001',
  '/api/v1/admin/audit-events',
];

describe('RBAC das rotas administrativas', () => {
  it('ADMIN acessa a listagem de usuários', async () => {
    const { adminToken } = await actors();

    const response = await get(scoped(''), adminToken);

    expect(response.statusCode).toBe(200);
    const body = response.json<ListBody<PublicUserBody>>();
    expect(body.data.map((u) => u.email).sort()).toEqual([email('chefe'), email('comum')]);
  });

  it.each(ADMIN_ROUTES)('USER recebe 403 FORBIDDEN em %s', async (url) => {
    const { userToken } = await actors();

    const response = await get(url, userToken);

    expect(response.statusCode).toBe(403);
    expect(response.json<ErrorBody>().error.code).toBe('FORBIDDEN');
  });

  it.each(ADMIN_ROUTES)('sem token: 401 UNAUTHORIZED em %s', async (url) => {
    const response = await get(url);

    expect(response.statusCode).toBe(401);
    expect(response.json<ErrorBody>().error.code).toBe('UNAUTHORIZED');
  });

  it('JWT inválido: 401 INVALID_TOKEN', async () => {
    const response = await get('/api/v1/admin/users', 'abc.def.ghi');

    expect(response.statusCode).toBe(401);
    expect(response.json<ErrorBody>().error.code).toBe('INVALID_TOKEN');
  });

  it('a autenticação vem antes da validação: anônimo com query inválida recebe 401, USER 403', async () => {
    const { userToken } = await actors();
    const invalid = '/api/v1/admin/users?pageSize=9999&sort=passwordHash';

    expect((await get(invalid)).statusCode).toBe(401);
    expect((await get(invalid, userToken)).statusCode).toBe(403);
    expect((await get('/api/v1/admin/users/nao-e-uuid', userToken)).statusCode).toBe(403);
  });

  it('papel ADMIN forjado no JWT (assinatura válida) não dá privilégio: o banco diz USER', async () => {
    const { user, userToken } = await actors();
    const { sid } = JSON.parse(
      Buffer.from(userToken.split('.')[1] ?? '', 'base64url').toString(),
    ) as { sid: string };
    // Pior caso: alguém com o segredo emite um token da sessão real com role ADMIN.
    const forged = await createAccessTokenSigner(TEST_JWT_SECRET, 900).sign({
      userId: user.id,
      sessionId: sid,
      role: 'ADMIN',
    });

    const response = await get('/api/v1/admin/users', forged);

    expect(response.statusCode).toBe(403);
  });

  it('role ADMIN adulterado no payload sem reassinar: 401', async () => {
    const { userToken } = await actors();
    const [header, payload, signature] = userToken.split('.');
    const claims = JSON.parse(Buffer.from(payload ?? '', 'base64url').toString()) as object;
    const forged = Buffer.from(JSON.stringify({ ...claims, role: 'ADMIN' })).toString('base64url');

    const response = await get(
      '/api/v1/admin/users',
      `${header ?? ''}.${forged}.${signature ?? ''}`,
    );

    expect(response.statusCode).toBe(401);
  });

  it('role enviado pelo cliente (query/header) não é fonte de autorização', async () => {
    const { userToken } = await actors();

    const response = await call({
      method: 'GET',
      url: '/api/v1/admin/audit-events?role=ADMIN',
      headers: { authorization: `Bearer ${userToken}`, 'x-user-role': 'ADMIN', 'x-role': 'ADMIN' },
    });

    expect(response.statusCode).toBe(403);
  });

  it('promoção no banco vale na próxima requisição, com o MESMO token', async () => {
    const { user, userToken } = await actors();
    expect((await get('/api/v1/admin/users', userToken)).statusCode).toBe(403);

    await setRole(user.id, 'ADMIN');

    expect((await get('/api/v1/admin/users', userToken)).statusCode).toBe(200);
  });

  it('rebaixamento no banco corta o acesso imediatamente, com o token ainda válido', async () => {
    const { admin, adminToken } = await actors();
    expect((await get('/api/v1/admin/users', adminToken)).statusCode).toBe(200);

    await setRole(admin.id, 'USER');

    expect((await get('/api/v1/admin/users', adminToken)).statusCode).toBe(403);
    expect((await get('/api/v1/users/me', adminToken)).statusCode).toBe(200);
  });

  it('ADMIN com sessão encerrada perde o acesso (logout)', async () => {
    const { adminToken } = await actors();
    await call({
      method: 'POST',
      url: '/api/v1/auth/logout',
      headers: { authorization: `Bearer ${adminToken}` },
    });

    expect((await get('/api/v1/admin/users', adminToken)).statusCode).toBe(401);
  });
});

describe('GET /api/v1/admin/users', () => {
  async function withUsers() {
    const ctx = await actors();
    // Nomes fora de ordem alfabética e de criação, para testar a ordenação.
    for (const local of ['mario', 'beatriz', 'xavier', 'helena']) await registerUser(local);
    return ctx; // 6 usuários no domínio: chefe, comum + 4
  }

  it('paginação: páginas sem sobreposição, total e totalPages corretos', async () => {
    const { adminToken } = await withUsers();

    const pages = await Promise.all(
      [1, 2, 3, 4].map(async (page) =>
        (await get(scoped(`page=${page}&pageSize=2`), adminToken)).json<ListBody<PublicUserBody>>(),
      ),
    );

    expect(pages[0]?.pagination).toEqual({ page: 1, pageSize: 2, total: 6, totalPages: 3 });
    expect(pages.map((p) => p.data.length)).toEqual([2, 2, 2, 0]);
    const ids = pages.flatMap((p) => p.data.map((u) => u.id));
    expect(new Set(ids).size).toBe(6);
  });

  it('pageSize acima do máximo: 400; o máximo (100) é aceito', async () => {
    const { adminToken } = await actors();

    const tooBig = await get(scoped('pageSize=101'), adminToken);
    const max = await get(scoped('pageSize=100'), adminToken);

    expect(tooBig.statusCode).toBe(400);
    expect(tooBig.json<ErrorBody>().error.details).toEqual([
      expect.objectContaining({ field: 'querystring.pageSize' }),
    ]);
    expect(max.statusCode).toBe(200);
  });

  it('padrão: no máximo 20 itens por página', async () => {
    const { adminToken } = await actors();

    const body = (await get('/api/v1/admin/users', adminToken)).json<ListBody<PublicUserBody>>();

    expect(body.pagination.pageSize).toBe(20);
    expect(body.data.length).toBeLessThanOrEqual(20);
  });

  it('filtros por email (trecho, sem diferenciar maiúsculas) e por papel', async () => {
    const { adminToken } = await withUsers();

    const byEmail = (
      await get(`/api/v1/admin/users?email=${encodeURIComponent(`HELENA${DOMAIN}`)}`, adminToken)
    ).json<ListBody<PublicUserBody>>();
    const admins = (await get(scoped('role=ADMIN'), adminToken)).json<ListBody<PublicUserBody>>();
    const users = (await get(scoped('role=USER'), adminToken)).json<ListBody<PublicUserBody>>();

    expect(byEmail.data.map((u) => u.email)).toEqual([email('helena')]);
    expect(admins.data.map((u) => u.email)).toEqual([email('chefe')]);
    expect(users.pagination.total).toBe(5);
  });

  it('curingas do LIKE são texto literal: "_" e "%" não casam com qualquer caractere', async () => {
    const { adminToken } = await withUsers();

    const underscore = await get(
      `/api/v1/admin/users?email=${encodeURIComponent('m_rio')}`,
      adminToken,
    );
    const percent = await get(`/api/v1/admin/users?email=${encodeURIComponent('%')}`, adminToken);

    expect(underscore.json<ListBody<PublicUserBody>>().pagination.total).toBe(0);
    expect(percent.json<ListBody<PublicUserBody>>().pagination.total).toBe(0);
  });

  it.each([
    ['ordenação por campo não permitido', 'sort=passwordHash'],
    ['tentativa de injeção na ordenação', `sort=${encodeURIComponent('email; DROP TABLE users')}`],
    ['papel inexistente', 'role=ROOT'],
    ['parâmetro desconhecido', 'passwordHash=x'],
    ['página não numérica', 'page=abc'],
  ])('400 para filtro inválido: %s', async (_label, query) => {
    const { adminToken } = await actors();

    const response = await get(scoped(query), adminToken);

    expect(response.statusCode).toBe(400);
    expect(response.json<ErrorBody>().error.code).toBe('VALIDATION_ERROR');
  });

  it('ordenação segura por nome e por email, nos dois sentidos', async () => {
    const { adminToken } = await withUsers();
    const names = async (query: string) =>
      (await get(scoped(query), adminToken))
        .json<ListBody<PublicUserBody>>()
        .data.map((u) => u.name);
    const emails = async (query: string) =>
      (await get(scoped(query), adminToken))
        .json<ListBody<PublicUserBody>>()
        .data.map((u) => u.email);

    const asc = await names('sort=name&order=asc');
    // Mesmo prefixo e mesma caixa: a ordem relativa não depende da collation do banco.
    const extras = (list: string[]) => list.filter((name) => /^Pessoa [a-z]+$/.test(name));
    expect(extras(asc)).toEqual([
      'Pessoa beatriz',
      'Pessoa helena',
      'Pessoa mario',
      'Pessoa xavier',
    ]);
    expect(await names('sort=name&order=desc')).toEqual([...asc].reverse());
    const emailAsc = await emails('sort=email&order=asc');
    expect(emailAsc[0]).toBe(email('beatriz'));
    expect(emailAsc.at(-1)).toBe(email('xavier'));
  });

  it('padrão: mais recentes primeiro (createdAt desc)', async () => {
    const { adminToken } = await withUsers();

    const data = (await get(scoped(''), adminToken)).json<ListBody<PublicUserBody>>().data;

    expect(data[0]?.email).toBe(email('helena'));
    expect(data.at(-1)?.email).toBe(email('chefe'));
  });
});

describe('GET /api/v1/admin/users/:id', () => {
  it('devolve o usuário com campos públicos apenas', async () => {
    const { adminToken, user } = await actors();

    const response = await get(`/api/v1/admin/users/${user.id}`, adminToken);

    expect(response.statusCode).toBe(200);
    expect(Object.keys(response.json<object>()).sort()).toEqual(
      ['createdAt', 'email', 'id', 'name', 'role', 'updatedAt'].sort(),
    );
    expect(response.json()).toMatchObject({ id: user.id, email: email('comum'), role: 'USER' });
  });

  it('404 para usuário inexistente; 400 para id que não é UUID', async () => {
    const { adminToken } = await actors();

    const missing = await get(
      '/api/v1/admin/users/0190a000-0000-7000-8000-0000000000ff',
      adminToken,
    );
    const invalid = await get('/api/v1/admin/users/1%20OR%201=1', adminToken);

    expect(missing.statusCode).toBe(404);
    expect(missing.json<ErrorBody>().error.code).toBe('NOT_FOUND');
    expect(invalid.statusCode).toBe(400);
  });
});

describe('GET /api/v1/admin/audit-events', () => {
  it('lista eventos paginados, do mais recente ao mais antigo, sem dados sensíveis', async () => {
    const { adminToken, user } = await actors();

    const response = await get(`/api/v1/admin/audit-events?userId=${user.id}`, adminToken);

    expect(response.statusCode).toBe(200);
    const body = response.json<ListBody<AuditEventBody>>();
    expect(body.data.map((e) => e.type)).toEqual(['LOGIN_SUCCESS']);
    expect(Object.keys(body.data[0] ?? {}).sort()).toEqual(
      ['createdAt', 'id', 'ip', 'metadata', 'type', 'userId'].sort(),
    );
    expect(response.body).not.toMatch(/emailHash|email_hash|password|token/i);
  });

  it('filtros por tipo, usuário e período', async () => {
    const { adminToken, userToken, user, admin } = await actors();
    await get('/api/v1/admin/users', userToken); // gera ACCESS_DENIED do USER
    const list = async (query: string) =>
      (await get(`/api/v1/admin/audit-events?${query}`, adminToken)).json<
        ListBody<AuditEventBody>
      >();

    const denied = await list(`type=ACCESS_DENIED&userId=${user.id}`);
    const adminLogins = await list(`type=LOGIN_SUCCESS&userId=${admin.id}`);
    const now = Date.now();
    const inWindow = await list(
      `userId=${user.id}&from=${new Date(now - 60_000).toISOString()}&to=${new Date(now + 60_000).toISOString()}`,
    );
    const future = await list(`userId=${user.id}&from=${new Date(now + 60_000).toISOString()}`);

    expect(denied.data).toHaveLength(1);
    expect(adminLogins.data.map((e) => e.userId)).toEqual([admin.id]);
    expect(inWindow.data.map((e) => e.type).sort()).toEqual(['ACCESS_DENIED', 'LOGIN_SUCCESS']);
    expect(future.pagination.total).toBe(0);
  });

  it('ordenação estável e paginação: asc é o inverso exato de desc', async () => {
    const { adminToken, userToken, user } = await actors();
    for (let i = 0; i < 4; i++) await get('/api/v1/admin/audit-events', userToken);
    const ids = async (order: string) =>
      (
        await get(
          `/api/v1/admin/audit-events?userId=${user.id}&order=${order}&pageSize=100`,
          adminToken,
        )
      )
        .json<ListBody<AuditEventBody>>()
        .data.map((e) => e.id);

    const desc = await ids('desc');
    expect(desc).toHaveLength(5);
    expect(await ids('asc')).toEqual([...desc].reverse());
  });

  it.each([
    ['tipo inexistente', 'type=HACK'],
    ['userId inválido', 'userId=abc'],
    ['data inválida', 'from=ontem'],
    ['período invertido', 'from=2026-11-02T00:00:00Z&to=2026-11-01T00:00:00Z'],
    ['pageSize acima do máximo', 'pageSize=500'],
  ])('400 para %s', async (_label, query) => {
    const { adminToken } = await actors();

    expect((await get(`/api/v1/admin/audit-events?${query}`, adminToken)).statusCode).toBe(400);
  });
});

describe('auditoria de ACCESS_DENIED', () => {
  it('cada 403 gera um evento com usuário, IP e padrão da rota; sem token nem ids', async () => {
    const { user, userToken, adminToken } = await actors();
    const target = '0190a000-0000-7000-8000-0000000000ab';

    await get(`/api/v1/admin/users/${target}?email=segredo@example.com`, userToken);

    const events = await prisma.auditEvent.findMany({
      where: { userId: user.id, type: 'ACCESS_DENIED' },
    });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      ip: '127.0.0.1',
      emailHash: null,
      metadata: {
        method: 'GET',
        route: '/api/v1/admin/users/:id',
        requiredRoles: 'ADMIN',
        role: 'USER',
      },
    });
    const stored = JSON.stringify(events);
    expect(stored).not.toContain(target);
    expect(stored).not.toContain('segredo@example.com');
    expect(stored).not.toContain(userToken);

    // 401 (anônimo) e 200 (admin) não geram ACCESS_DENIED.
    await get('/api/v1/admin/users');
    await get('/api/v1/admin/users', adminToken);
    expect(
      await prisma.auditEvent.count({
        where: { type: 'ACCESS_DENIED', user: { email: { endsWith: DOMAIN } } },
      }),
    ).toBe(1);
  });

  it('logout-all registra LOGOUT_ALL (e não um LOGOUT duplicado)', async () => {
    const { user, userToken } = await actors();

    await call({
      method: 'POST',
      url: '/api/v1/auth/logout-all',
      headers: { authorization: `Bearer ${userToken}` },
    });

    const events = await prisma.auditEvent.findMany({
      where: { userId: user.id, type: { in: ['LOGOUT', 'LOGOUT_ALL'] } },
    });
    expect(events.map((e) => [e.type, e.metadata])).toEqual([
      ['LOGOUT_ALL', { revokedSessions: 1 }],
    ]);
  });
});

describe('ausência de credenciais e isolamento', () => {
  it('nenhuma resposta administrativa contém hash, senha ou tokens', async () => {
    const { adminToken, userToken, user } = await actors();

    const bodies = [
      (await get(scoped('pageSize=100'), adminToken)).body,
      (await get(`/api/v1/admin/users/${user.id}`, adminToken)).body,
      (await get('/api/v1/admin/audit-events?pageSize=100', adminToken)).body,
    ].join('\n');

    expect(bodies).not.toMatch(/passwordHash|password_hash|argon2|refresh|tokenHash/i);
    expect(bodies).not.toContain(PASSWORD);
    expect(bodies).not.toContain(adminToken);
    expect(bodies).not.toContain(userToken);
  });

  it('USER não lê dados de outro usuário nem pela área admin (IDOR)', async () => {
    const { userToken, admin, user } = await actors();

    for (const id of [admin.id, user.id]) {
      expect((await get(`/api/v1/admin/users/${id}`, userToken)).statusCode).toBe(403);
    }
    expect((await get(`/api/v1/admin/audit-events?userId=${admin.id}`, userToken)).statusCode).toBe(
      403,
    );
    // /users/me continua mostrando só o próprio usuário.
    expect((await get('/api/v1/users/me', userToken)).json()).toMatchObject({ id: user.id });
  });

  it('as rotas admin estão no OpenAPI marcadas com bearerAuth', async () => {
    const spec = (await get('/docs/json')).json<{
      paths: Record<string, Record<string, { security?: unknown }>>;
    }>();

    for (const path of [
      '/api/v1/admin/users',
      '/api/v1/admin/users/{id}',
      '/api/v1/admin/audit-events',
    ]) {
      expect(spec.paths[path]?.get?.security).toEqual([{ bearerAuth: [] }]);
    }
  });
});
