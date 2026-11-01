import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import type { FastifyInstance, InjectOptions } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { buildApp } from '../../src/app.js';
import type { AuditEventType } from '../../src/generated/prisma/enums.js';
import { createPrismaClient, type PrismaClient } from '../../src/infra/prisma.js';
import { createRedisClient } from '../../src/infra/redis.js';
import { hashEmail, type AuditEventInput } from '../../src/modules/audit/audit.recorder.js';
import {
  deleteAuditEvents,
  retentionConfigSchema,
  runAuditRetention,
} from '../../src/modules/audit/audit-retention.js';
import { MemoryMailer } from '../../src/modules/mail/memory-mailer.js';
import { createPasswordResetRepository } from '../../src/modules/password-reset/password-reset.repository.js';
import { createPasswordResetService } from '../../src/modules/password-reset/password-reset.service.js';
import { createUsersRepository } from '../../src/modules/users/users.repository.js';
import { createUsersService } from '../../src/modules/users/users.service.js';
import { createBackgroundTasks } from '../../src/shared/background-tasks.js';
import { hashPassword, verifyPassword } from '../../src/shared/password-hasher.js';
import { buildTestApp, deleteTestKeys } from '../helpers/build-test-app.js';
import { purgeAuditEvents } from '../helpers/purge-audit-events.js';
import { TEST_DATABASE_URL, testEnv } from '../helpers/test-env.js';

/** Dados fictícios: domínio próprio; eventos de retenção marcados com metadata.suite. */
const DOMAIN = '@audit-test.example.com';
const email = (local: string) => `${local}${DOMAIN}`;
const UNKNOWN = email('ninguem');
const PASSWORD = 'cavalo correto bateria grampo';
const SUITE = 'audit-retention-test';

let prisma: PrismaClient;
let mailer: MemoryMailer;
let app: FastifyInstance;

const call = (options: InjectOptions) => app.inject(options);
const as = (token: string) => ({ authorization: `Bearer ${token}` });

async function registerUser(local: string, role: 'USER' | 'ADMIN' = 'USER') {
  const response = await call({
    method: 'POST',
    url: '/api/v1/auth/register',
    payload: { name: `Pessoa ${local}`, email: email(local), password: PASSWORD },
  });
  expect(response.statusCode).toBe(201);
  const { id } = response.json<{ id: string }>();
  if (role === 'ADMIN') await prisma.user.update({ where: { id }, data: { role } });
  return id;
}

async function login(address: string, password = PASSWORD) {
  return call({ method: 'POST', url: '/api/v1/auth/login', payload: { email: address, password } });
}

async function tokensOf(local: string) {
  const response = await login(email(local));
  expect(response.statusCode).toBe(200);
  return response.json<{ accessToken: string; refreshToken: string }>();
}

/** Eventos de um usuário, em ordem: é a "matriz" observada no banco. */
async function eventsOf(userId: string) {
  return prisma.auditEvent.findMany({
    where: { userId },
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
  });
}
const typesOf = async (userId: string) => (await eventsOf(userId)).map((e) => e.type);

async function cleanupDb() {
  await purgeAuditEvents(prisma, {
    where: {
      OR: [
        { user: { email: { endsWith: DOMAIN } } },
        { emailHash: hashEmail(UNKNOWN) },
        { metadata: { path: ['suite'], equals: SUITE } },
      ],
    },
  });
  await prisma.user.deleteMany({ where: { email: { endsWith: DOMAIN } } });
}

beforeAll(() => {
  prisma = createPrismaClient(TEST_DATABASE_URL);
});

beforeEach(async () => {
  await cleanupDb();
  mailer = new MemoryMailer();
  app = await buildTestApp({}, { mailer });
});

afterEach(async () => {
  await app.close();
});

afterAll(async () => {
  await cleanupDb();
  await prisma.$disconnect();
});

describe('matriz de eventos (ponta a ponta)', () => {
  it('login e logout: um evento por ação, sem duplicar em repetições', async () => {
    const userId = await registerUser('ana');
    await login(email('ana'), 'senha errada porém longa');
    const first = await tokensOf('ana');
    const second = await tokensOf('ana');

    await call({ method: 'POST', url: '/api/v1/auth/logout', headers: as(first.accessToken) });
    await call({ method: 'POST', url: '/api/v1/auth/logout', headers: as(first.accessToken) }); // 401
    await call({ method: 'POST', url: '/api/v1/auth/logout-all', headers: as(second.accessToken) });

    expect(await typesOf(userId)).toEqual([
      'LOGIN_FAILURE',
      'LOGIN_SUCCESS',
      'LOGIN_SUCCESS',
      'LOGOUT',
      'LOGOUT_ALL',
    ]);
  });

  it('perfil: PROFILE_UPDATED após gravar; recusas viram PROFILE_UPDATE_DENIED; 400 não gera nada', async () => {
    const userId = await registerUser('bia');
    await registerUser('outra');
    const { accessToken } = await tokensOf('bia');
    const patch = (payload: object) =>
      call({ method: 'PATCH', url: '/api/v1/users/me', headers: as(accessToken), payload });

    expect((await patch({ name: 'Bia Nova' })).statusCode).toBe(200);
    expect((await patch({ email: email('bia.nova'), currentPassword: PASSWORD })).statusCode).toBe(
      200,
    );
    expect(
      (await patch({ email: email('x'), currentPassword: 'senha errada porém longa' })).statusCode,
    ).toBe(403);
    expect((await patch({ email: email('outra'), currentPassword: PASSWORD })).statusCode).toBe(
      409,
    );
    expect((await patch({ role: 'ADMIN' })).statusCode).toBe(400);
    expect((await patch({ email: email('y') })).statusCode).toBe(400);

    const events = (await eventsOf(userId)).filter((e) => e.type !== 'LOGIN_SUCCESS');
    expect(events.map((e) => [e.type, e.metadata])).toEqual([
      ['PROFILE_UPDATED', { fields: 'name', emailChanged: false, otherSessionsRevoked: false }],
      ['PROFILE_UPDATED', { fields: 'email', emailChanged: true, otherSessionsRevoked: true }],
      ['PROFILE_UPDATE_DENIED', { reason: 'INVALID_CURRENT_PASSWORD' }],
      ['PROFILE_UPDATE_DENIED', { reason: 'EMAIL_IN_USE' }],
    ]);
    expect(JSON.stringify(events)).not.toContain(DOMAIN);
    expect(JSON.stringify(events)).not.toContain('Bia Nova');
  });

  it('recuperação de senha: exatamente um pedido e um sucesso', async () => {
    const userId = await registerUser('caio');
    await call({
      method: 'POST',
      url: '/api/v1/auth/forgot-password',
      payload: { email: email('caio') },
    });
    await app.backgroundTasks.idle();
    const token = mailer.lastResetToken(email('caio')) ?? '';
    await call({
      method: 'POST',
      url: '/api/v1/auth/reset-password',
      payload: { token, newPassword: 'girassol teimoso na janela azul' },
    });

    expect(await typesOf(userId)).toEqual(['PASSWORD_RESET_REQUEST', 'PASSWORD_RESET_SUCCESS']);
  });

  it('acessos administrativos: listagem, consulta individual (com e sem resultado) e auditoria', async () => {
    const adminId = await registerUser('chefe', 'ADMIN');
    const targetId = await registerUser('alvo');
    const { accessToken } = await tokensOf('chefe');
    const get = (url: string) => call({ method: 'GET', url, headers: as(accessToken) });

    await get(`/api/v1/admin/users?role=USER&email=${encodeURIComponent('alvo@')}&pageSize=5`);
    await get(`/api/v1/admin/users/${targetId}`);
    await get('/api/v1/admin/users/0190a000-0000-7000-8000-0000000000ff'); // 404
    await get(
      `/api/v1/admin/audit-events?type=LOGIN_SUCCESS&userId=${targetId}&from=2026-01-01T00:00:00Z`,
    );
    await get('/api/v1/admin/users?pageSize=999'); // 400: não chega ao handler, não gera evento

    const events = (await eventsOf(adminId)).filter((e) => e.type.startsWith('ADMIN_'));
    expect(events.map((e) => [e.type, e.metadata])).toEqual([
      [
        'ADMIN_USERS_LISTED',
        {
          page: 1,
          pageSize: 5,
          sort: 'createdAt',
          order: 'desc',
          role: 'USER',
          emailFilter: true,
          resultCount: 1,
        },
      ],
      ['ADMIN_USER_VIEWED', { targetUserId: targetId, found: true }],
      ['ADMIN_USER_VIEWED', { targetUserId: '0190a000-0000-7000-8000-0000000000ff', found: false }],
      [
        'ADMIN_AUDIT_QUERIED',
        {
          page: 1,
          pageSize: 20,
          order: 'desc',
          filterType: 'LOGIN_SUCCESS',
          targetUserId: targetId,
          from: '2026-01-01T00:00:00.000Z',
          resultCount: 0,
        },
      ],
    ]);
    expect(JSON.stringify(events)).not.toContain('alvo@');
  });

  it('USER em rota admin: só ACCESS_DENIED; anônimo não gera evento', async () => {
    const userId = await registerUser('comum');
    const { accessToken } = await tokensOf('comum');
    const before = await prisma.auditEvent.count();

    await call({ method: 'GET', url: '/api/v1/admin/audit-events', headers: as(accessToken) });
    await call({ method: 'GET', url: '/api/v1/admin/audit-events' });

    expect(await typesOf(userId)).toEqual(['LOGIN_SUCCESS', 'ACCESS_DENIED']);
    expect(await prisma.auditEvent.count()).toBe(before + 1);
  });
});

describe('consulta administrativa da auditoria', () => {
  it('sem recursão: a consulta não vê o próprio registro; N consultas geram N eventos', async () => {
    const adminId = await registerUser('auditor', 'ADMIN');
    const { accessToken } = await tokensOf('auditor');
    const query = () =>
      call({
        method: 'GET',
        url: `/api/v1/admin/audit-events?type=ADMIN_AUDIT_QUERIED&userId=${adminId}`,
        headers: as(accessToken),
      });

    const totals = [];
    for (let i = 0; i < 3; i++)
      totals.push((await query()).json<{ pagination: { total: number } }>().pagination.total);

    expect(totals).toEqual([0, 1, 2]);
    expect(
      await prisma.auditEvent.count({ where: { userId: adminId, type: 'ADMIN_AUDIT_QUERIED' } }),
    ).toBe(3);
  });

  it('filtra pelos novos tipos, pagina com limite e não devolve dados sensíveis', async () => {
    await registerUser('admin2', 'ADMIN');
    const userId = await registerUser('perfil');
    const user = await tokensOf('perfil');
    await call({
      method: 'PATCH',
      url: '/api/v1/users/me',
      headers: as(user.accessToken),
      payload: { name: 'A' },
    });
    await call({
      method: 'PATCH',
      url: '/api/v1/users/me',
      headers: as(user.accessToken),
      payload: { name: 'B' },
    });
    const admin = await tokensOf('admin2');

    const response = await call({
      method: 'GET',
      url: `/api/v1/admin/audit-events?type=PROFILE_UPDATED&userId=${userId}&pageSize=1&order=asc`,
      headers: as(admin.accessToken),
    });
    const tooBig = await call({
      method: 'GET',
      url: '/api/v1/admin/audit-events?pageSize=101',
      headers: as(admin.accessToken),
    });

    expect(response.statusCode).toBe(200);
    const body = response.json<{ data: { type: string }[]; pagination: object }>();
    expect(body.data.map((e) => e.type)).toEqual(['PROFILE_UPDATED']);
    expect(body.pagination).toEqual({ page: 1, pageSize: 1, total: 2, totalPages: 2 });
    expect(response.body).not.toMatch(/emailHash|email_hash|password|token|@/i);
    expect(tooBig.statusCode).toBe(400);
  });
});

describe('privacidade', () => {
  it('nenhum evento de um fluxo completo contém senha, token, hash de senha ou email', async () => {
    const userId = await registerUser('privada');
    await registerUser('chefe3', 'ADMIN');
    await login(email('privada'), 'senha errada porém longa');
    const user = await tokensOf('privada');
    await call({
      method: 'POST',
      url: '/api/v1/auth/refresh',
      payload: { refreshToken: user.refreshToken },
    });
    await call({
      method: 'PATCH',
      url: '/api/v1/users/me',
      headers: as(user.accessToken),
      payload: { email: email('privada.nova'), currentPassword: PASSWORD },
    });
    await call({
      method: 'POST',
      url: '/api/v1/auth/forgot-password',
      payload: { email: email('privada.nova') },
    });
    await call({
      method: 'POST',
      url: '/api/v1/auth/forgot-password',
      payload: { email: UNKNOWN },
    });
    await app.backgroundTasks.idle();
    const resetToken = mailer.lastResetToken(email('privada.nova')) ?? '';
    await call({
      method: 'POST',
      url: '/api/v1/auth/reset-password',
      payload: { token: resetToken, newPassword: 'girassol teimoso na janela azul' },
    });
    const admin = await tokensOf('chefe3');
    await call({
      method: 'GET',
      url: `/api/v1/admin/users/${userId}`,
      headers: as(admin.accessToken),
    });

    const events = await prisma.auditEvent.findMany({
      where: { OR: [{ user: { email: { endsWith: DOMAIN } } }, { emailHash: hashEmail(UNKNOWN) }] },
    });
    expect(events.length).toBeGreaterThanOrEqual(8);
    const stored = JSON.stringify(events);
    for (const secret of [
      PASSWORD,
      'girassol teimoso',
      user.accessToken,
      user.refreshToken,
      resetToken,
      admin.accessToken,
      DOMAIN,
      'argon2',
    ]) {
      expect(stored).not.toContain(secret);
    }
  });
});

describe('integridade transacional', () => {
  /** Prisma com falha injetada em session.updateMany, que roda DENTRO da transação. */
  const faultyPrisma = () =>
    prisma.$extends({
      query: {
        session: {
          updateMany() {
            throw new Error('falha simulada na transação');
          },
        },
      },
    }) as unknown as PrismaClient;

  function capture() {
    const events: AuditEventInput[] = [];
    return {
      events,
      audit: { record: (e: AuditEventInput) => (events.push(e), Promise.resolve()) },
    };
  }

  it('troca de email que falha no meio: email intacto e nenhum PROFILE_UPDATED', async () => {
    const userId = await registerUser('trans');
    const { events, audit } = capture();
    const service = createUsersService({
      usersRepository: createUsersRepository(faultyPrisma()),
      hashPassword,
      verifyPassword,
      audit,
    });

    await expect(
      service.updateProfile(userId, { email: email('trans.nova'), currentPassword: PASSWORD }),
    ).rejects.toThrow(/falha simulada/);

    expect((await prisma.user.findUniqueOrThrow({ where: { id: userId } })).email).toBe(
      email('trans'),
    );
    expect(events.map((e) => e.type)).not.toContain('PROFILE_UPDATED');
  });

  it('reset de senha que falha no meio: nenhum PASSWORD_RESET_SUCCESS', async () => {
    const userId = await registerUser('trans2');
    await call({
      method: 'POST',
      url: '/api/v1/auth/forgot-password',
      payload: { email: email('trans2') },
    });
    await app.backgroundTasks.idle();
    const { events, audit } = capture();
    const service = createPasswordResetService({
      repository: createPasswordResetRepository(faultyPrisma()),
      hashPassword,
      mailer,
      audit,
      tasks: createBackgroundTasks(() => undefined),
      tokenTtlMinutes: 15,
    });

    await expect(
      service.resetPassword(
        mailer.lastResetToken(email('trans2')) ?? '',
        'girassol teimoso na janela',
        {
          ip: null,
          userAgent: null,
        },
      ),
    ).rejects.toThrow(/falha simulada/);

    expect(events).toEqual([]);
    expect(await typesOf(userId)).toEqual(['PASSWORD_RESET_REQUEST']);
  });
});

describe('falha ao gravar a auditoria', () => {
  it('as ações seguem funcionando, sem expor o erro ao cliente; o detalhe vai só para o log', async () => {
    const lines: string[] = [];
    const env = testEnv({ LOG_LEVEL: 'error' });
    const broken = prisma.$extends({
      query: {
        auditEvent: {
          create() {
            throw new Error('audit indisponível: detalhe interno 10.0.0.9');
          },
        },
      },
    }) as unknown as PrismaClient;
    const redis = createRedisClient(env.REDIS_URL);
    const faultyApp = await buildApp({
      env,
      prisma: broken,
      redis,
      logDestination: { write: (line: string) => void lines.push(line) },
    });
    try {
      await registerUser('resiliente', 'ADMIN');
      const loginResponse = await faultyApp.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: email('resiliente'), password: PASSWORD },
      });
      const { accessToken } = loginResponse.json<{ accessToken: string }>();
      const list = await faultyApp.inject({
        method: 'GET',
        url: '/api/v1/admin/users',
        headers: as(accessToken),
      });
      const patch = await faultyApp.inject({
        method: 'PATCH',
        url: '/api/v1/users/me',
        headers: as(accessToken),
        payload: { name: 'Ainda Funciona' },
      });

      expect([loginResponse.statusCode, list.statusCode, patch.statusCode]).toEqual([
        200, 200, 200,
      ]);
      for (const body of [loginResponse.body, list.body, patch.body])
        expect(body).not.toContain('10.0.0.9');
      expect(lines.join('')).toContain('falha ao gravar evento de auditoria');
    } finally {
      await faultyApp.close();
      await deleteTestKeys(redis, env.RATE_LIMIT_KEY_PREFIX);
      redis.disconnect();
    }
  });
});

describe('append-only no banco (trigger)', () => {
  async function fictitious(type: AuditEventType = 'LOGIN_FAILURE', daysAgo = 0) {
    return prisma.auditEvent.create({
      data: {
        type,
        metadata: { suite: SUITE },
        createdAt: new Date(Date.now() - daysAgo * 86_400_000),
      },
    });
  }

  it('UPDATE é recusado, inclusive pelo Prisma', async () => {
    const event = await fictitious();

    await expect(
      prisma.auditEvent.update({ where: { id: event.id }, data: { ip: '1.2.3.4' } }),
    ).rejects.toThrow(/append-only/);
    expect((await prisma.auditEvent.findUniqueOrThrow({ where: { id: event.id } })).ip).toBeNull();
  });

  it('DELETE direto é recusado; só a rotina de retenção (deleteAuditEvents) apaga', async () => {
    const event = await fictitious();

    await expect(prisma.auditEvent.delete({ where: { id: event.id } })).rejects.toThrow(/retenção/);
    await expect(prisma.auditEvent.deleteMany({ where: { id: event.id } })).rejects.toThrow(
      /retenção/,
    );
    expect(await deleteAuditEvents(prisma, { id: event.id })).toBe(1);
  });

  it('a flag de exclusão vale só dentro da própria transação', async () => {
    const event = await fictitious();
    await deleteAuditEvents(prisma, { id: '0190a000-0000-7000-8000-0000000000ff' });

    await expect(prisma.auditEvent.deleteMany({ where: { id: event.id } })).rejects.toThrow(
      /retenção/,
    );
  });

  it('excluir um usuário preserva os eventos dele, só sem o vínculo (ON DELETE SET NULL)', async () => {
    const userId = await registerUser('excluida');
    await tokensOf('excluida');
    const [event] = await eventsOf(userId);

    await prisma.user.delete({ where: { id: userId } });

    const after = await prisma.auditEvent.findUniqueOrThrow({ where: { id: event?.id ?? '' } });
    expect(after.userId).toBeNull();
    expect(after.type).toBe('LOGIN_SUCCESS');
    await deleteAuditEvents(prisma, { id: after.id });
  });
});

describe('retenção configurável (dados fictícios)', () => {
  const insert = (type: AuditEventType, daysAgo: number) =>
    prisma.auditEvent.create({
      data: {
        type,
        metadata: { suite: SUITE, daysAgo },
        createdAt: new Date(Date.now() - daysAgo * 86_400_000),
      },
    });
  const remaining = async () =>
    (
      await prisma.auditEvent.findMany({
        where: { metadata: { path: ['suite'], equals: SUITE } },
        orderBy: { createdAt: 'asc' },
      })
    ).map((e) => `${e.type}:${String((e.metadata as { daysAgo: number }).daysAgo)}`);

  async function seed() {
    await insert('LOGIN_SUCCESS', 200); // comum, vencido (> 180)
    await insert('LOGIN_FAILURE', 190); // comum, vencido
    await insert('LOGIN_SUCCESS', 100); // comum, dentro do prazo
    await insert('TOKEN_REUSE_DETECTED', 200); // estendido, dentro do prazo (< 365)
    await insert('ADMIN_USER_VIEWED', 400); // estendido, vencido
  }

  it('simulação conta sem apagar; execução apaga só os vencidos, mais antigos primeiro', async () => {
    await seed();
    const config = retentionConfigSchema.parse({});

    const dry = await runAuditRetention(prisma, config);
    expect(dry).toMatchObject({ dryRun: true, eligible: 3, deleted: 0, batches: 0 });
    expect(await remaining()).toHaveLength(5);

    const run = await runAuditRetention(prisma, config, { dryRun: false });
    expect(run).toMatchObject({ dryRun: false, eligible: 3, deleted: 3, complete: true });
    expect(await remaining()).toEqual(['TOKEN_REUSE_DETECTED:200', 'LOGIN_SUCCESS:100']);
  });

  it('respeita o tamanho do lote e o teto de lotes por execução', async () => {
    await seed();
    const config = retentionConfigSchema.parse({
      AUDIT_RETENTION_BATCH_SIZE: '1',
      AUDIT_RETENTION_MAX_BATCHES: '2',
    });

    const first = await runAuditRetention(prisma, config, { dryRun: false });
    expect(first).toMatchObject({ deleted: 2, batches: 2, complete: false });
    // O mais antigo (400 dias) foi primeiro.
    expect(await remaining()).not.toContain('ADMIN_USER_VIEWED:400');

    const second = await runAuditRetention(prisma, config, { dryRun: false });
    expect(second).toMatchObject({ deleted: 1, complete: true });
  });

  it('prazos configuráveis: com 365/730 dias, nada do seed vence', async () => {
    await seed();
    const config = retentionConfigSchema.parse({
      AUDIT_RETENTION_DAYS: '365',
      AUDIT_RETENTION_EXTENDED_DAYS: '730',
    });

    expect((await runAuditRetention(prisma, config, { dryRun: false })).deleted).toBe(0);
  });

  it('CLI: simulação por padrão; execução exige habilitação e confirmação do banco', async () => {
    await seed();
    const tsxCli = createRequire(import.meta.url).resolve('tsx/cli');
    const run = (args: string[], extraEnv: Record<string, string> = {}) =>
      spawnSync(process.execPath, [tsxCli, 'scripts/audit-retention.ts', ...args], {
        env: {
          ...process.env,
          NODE_ENV: 'test',
          DATABASE_URL: TEST_DATABASE_URL,
          AUDIT_RETENTION_ENABLED: 'false',
          ...extraEnv,
        },
        encoding: 'utf8',
        timeout: 60_000,
      });

    const dry = run([]);
    expect(dry.status).toBe(0);
    expect(dry.stdout).toContain('simulação');
    expect(dry.stdout).toContain('Vencidos: 3 · apagados: 0');

    const notEnabled = run(['--execute', '--confirm', 'authapi_test']);
    expect(notEnabled.status).toBe(1);
    expect(notEnabled.stderr).toContain('AUDIT_RETENTION_ENABLED=true');

    const wrongConfirm = run(['--execute', '--confirm', 'authapi'], {
      AUDIT_RETENTION_ENABLED: 'true',
    });
    expect(wrongConfirm.status).toBe(1);
    expect(await remaining()).toHaveLength(5);

    const execute = run(['--execute', '--confirm', 'authapi_test'], {
      AUDIT_RETENTION_ENABLED: 'true',
    });
    expect(execute.status).toBe(0);
    expect(execute.stdout).toContain('apagados: 3');
    expect(await remaining()).toEqual(['TOKEN_REUSE_DETECTED:200', 'LOGIN_SUCCESS:100']);
  });
});
