import type { FastifyInstance, InjectOptions, LightMyRequestResponse } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createPrismaClient, type PrismaClient } from '../../src/infra/prisma.js';
import { hashEmail } from '../../src/modules/audit/audit.recorder.js';
import { hashOpaqueToken } from '../../src/modules/auth/tokens.js';
import { MemoryMailer } from '../../src/modules/mail/memory-mailer.js';
import { createPasswordResetRepository } from '../../src/modules/password-reset/password-reset.repository.js';
import { createPasswordResetService } from '../../src/modules/password-reset/password-reset.service.js';
import { createBackgroundTasks } from '../../src/shared/background-tasks.js';
import type { ErrorBody } from '../../src/shared/error-handler.js';
import { hashPassword, verifyPassword } from '../../src/shared/password-hasher.js';
import { buildTestApp, type BuildTestAppOptions } from '../helpers/build-test-app.js';
import { TEST_DATABASE_URL } from '../helpers/test-env.js';
import { purgeAuditEvents } from '../helpers/purge-audit-events.js';

/** Dados fictícios: domínio próprio e IPs da faixa de documentação 192.0.2.0/24 (RFC 5737). */
const DOMAIN = '@reset-test.example.com';
const email = (local: string) => `${local}${DOMAIN}`;
const UNKNOWN = email('nao-existe');
const OLD_PASSWORD = 'cavalo correto bateria grampo';
const NEW_PASSWORD = 'girassol teimoso na janela azul';
const NET = '192.0.2.';

let prisma: PrismaClient;
let mailer: MemoryMailer;
let app: FastifyInstance;
const extraApps: FastifyInstance[] = [];

async function appWith(overrides: Record<string, string> = {}, options: BuildTestAppOptions = {}) {
  const instance = await buildTestApp(overrides, { mailer, ...options });
  extraApps.push(instance);
  return instance;
}

const post = (
  target: FastifyInstance,
  url: string,
  payload: object,
  extra: Partial<InjectOptions> = {},
) => target.inject({ method: 'POST', url: `/api/v1/auth/${url}`, payload, ...extra });
const forgot = (address: string, target = app, ip?: string) =>
  post(target, 'forgot-password', { email: address }, ip ? { remoteAddress: ip } : {});
const reset = (token: string, newPassword = NEW_PASSWORD, target = app, ip?: string) =>
  post(target, 'reset-password', { token, newPassword }, ip ? { remoteAddress: ip } : {});
const login = (address: string, password: string) =>
  post(app, 'login', { email: address, password });

async function registerUser(local: string) {
  const response = await post(app, 'register', {
    name: `Pessoa ${local}`,
    email: email(local),
    password: OLD_PASSWORD,
  });
  expect(response.statusCode).toBe(201);
  return response.json<{ id: string }>();
}

/** Pede a recuperação e devolve o token, como o usuário o leria no email. */
async function requestToken(local: string, target = app): Promise<string> {
  expect((await forgot(email(local), target)).statusCode).toBe(202);
  await target.backgroundTasks.idle();
  const token = mailer.lastResetToken(email(local));
  if (!token) throw new Error('nenhum email de recuperação enviado');
  return token;
}

async function cleanupDb() {
  await purgeAuditEvents(prisma, {
    where: {
      OR: [
        { user: { email: { endsWith: DOMAIN } } },
        { emailHash: hashEmail(UNKNOWN) },
        { ip: { startsWith: NET } },
      ],
    },
  });
  await prisma.user.deleteMany({ where: { email: { endsWith: DOMAIN } } });
}

beforeAll(async () => {
  prisma = createPrismaClient(TEST_DATABASE_URL);
});

beforeEach(async () => {
  await cleanupDb();
  mailer = new MemoryMailer();
  app = await buildTestApp({}, { mailer });
});

afterEach(async () => {
  await Promise.all([app, ...extraApps.splice(0)].map((instance) => instance.close()));
});

afterAll(async () => {
  await cleanupDb();
  await prisma.$disconnect();
});

describe('POST /auth/forgot-password', () => {
  it('email existente: 202, token enviado por email e só o SHA-256 no banco', async () => {
    const user = await registerUser('ana');

    const response = await forgot(email('ana'));
    await app.backgroundTasks.idle();

    expect(response.statusCode).toBe(202);
    const token = mailer.lastResetToken(email('ana')) ?? '';
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(response.body).not.toContain(token);
    const rows = await prisma.passwordResetToken.findMany({ where: { userId: user.id } });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.tokenHash).toBe(hashOpaqueToken(token));
    expect(JSON.stringify(rows)).not.toContain(token);
    const ttl = (rows[0]?.expiresAt.getTime() ?? 0) - (rows[0]?.createdAt.getTime() ?? 0);
    expect(Math.abs(ttl - 15 * 60_000)).toBeLessThan(5_000);
  });

  it('email inexistente: mesmo 202, nada gravado nem enviado', async () => {
    const response = await forgot(UNKNOWN);
    await app.backgroundTasks.idle();

    expect(response.statusCode).toBe(202);
    expect(mailer.sent).toHaveLength(0);
    expect(await prisma.passwordResetToken.count({ where: { user: { email: UNKNOWN } } })).toBe(0);
  });

  it('respostas indistinguíveis: mesmo status, corpo e cabeçalhos', async () => {
    await registerUser('bia');

    const existing = await forgot(email('bia'));
    const missing = await forgot(UNKNOWN);
    const view = (r: LightMyRequestResponse) => ({
      status: r.statusCode,
      body: r.body,
      headers: Object.keys(r.headers)
        .filter((h) => h !== 'date')
        .sort(),
      contentType: r.headers['content-type'],
      length: r.headers['content-length'],
    });

    expect(view(existing)).toEqual(view(missing));
    expect(existing.json()).toEqual({
      message: 'Se o email estiver cadastrado, você receberá as instruções para redefinir a senha.',
    });
  });

  it('a resposta não espera o trabalho que depende da conta (busca, INSERT, envio)', async () => {
    await registerUser('caio');
    let release: () => void = () => undefined;
    mailer.gate = new Promise<void>((resolve) => {
      release = resolve;
    });

    // O envio está travado: se a rota esperasse por ele, esta chamada nunca terminaria.
    const response = await forgot(email('caio'));

    expect(response.statusCode).toBe(202);
    expect(mailer.sent).toHaveLength(0);
    release();
    await app.backgroundTasks.idle();
    expect(mailer.to(email('caio'))).toHaveLength(1);
  });

  it('400 para email inválido e para campos extras, igual para qualquer conta', async () => {
    expect((await forgot('nao-e-email')).statusCode).toBe(400);
    expect((await post(app, 'forgot-password', { email: UNKNOWN, userId: 'x' })).statusCode).toBe(
      400,
    );
  });
});

describe('POST /auth/reset-password', () => {
  it('sucesso: troca a senha, login com a nova funciona e a antiga é rejeitada', async () => {
    await registerUser('davi');
    const token = await requestToken('davi');

    const response = await reset(token);

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      message: 'Senha redefinida. Entre novamente com a nova senha.',
    });
    // Só a mensagem: nenhum dado do usuário, token ou hash.
    expect(Object.keys(response.json<object>())).toEqual(['message']);
    expect((await login(email('davi'), NEW_PASSWORD)).statusCode).toBe(200);
    expect((await login(email('davi'), OLD_PASSWORD)).statusCode).toBe(401);
  });

  it('revoga TODAS as sessões existentes (motivo PASSWORD_RESET)', async () => {
    const user = await registerUser('elis');
    const sessions = [];
    for (let i = 0; i < 3; i++) {
      sessions.push(
        (await login(email('elis'), OLD_PASSWORD)).json<{
          accessToken: string;
          refreshToken: string;
        }>(),
      );
    }
    const token = await requestToken('elis');

    await reset(token);

    const rows = await prisma.session.findMany({ where: { userId: user.id } });
    expect(rows.map((s) => s.revokedReason)).toEqual([
      'PASSWORD_RESET',
      'PASSWORD_RESET',
      'PASSWORD_RESET',
    ]);
    for (const pair of sessions) {
      const me = await app.inject({
        method: 'GET',
        url: '/api/v1/users/me',
        headers: { authorization: `Bearer ${pair.accessToken}` },
      });
      expect(me.statusCode).toBe(401);
      expect((await post(app, 'refresh', { refreshToken: pair.refreshToken })).statusCode).toBe(
        401,
      );
    }
  });

  it('token já utilizado: 400 genérico', async () => {
    await registerUser('fabio');
    const token = await requestToken('fabio');
    await reset(token);

    const again = await reset(token, 'outra frase longa diferente');

    expect(again.statusCode).toBe(400);
    expect(again.json<ErrorBody>().error).toMatchObject({
      code: 'INVALID_RESET_TOKEN',
      message: 'Link de recuperação inválido ou expirado',
    });
  });

  it('token expirado: 400 genérico e a senha não muda', async () => {
    const user = await registerUser('gil');
    const token = await requestToken('gil');
    await prisma.passwordResetToken.updateMany({
      where: { userId: user.id },
      data: { expiresAt: new Date(Date.now() - 1_000) },
    });

    const response = await reset(token);

    expect(response.json<ErrorBody>().error.code).toBe('INVALID_RESET_TOKEN');
    expect((await login(email('gil'), OLD_PASSWORD)).statusCode).toBe(200);
  });

  it.each([
    ['inexistente', 'A'.repeat(43)],
    ['lixo', 'nao-e-um-token'],
  ])('token %s: 400 genérico', async (_label, token) => {
    const response = await reset(token);

    expect(response.statusCode).toBe(400);
    expect(response.json<ErrorBody>().error.code).toBe('INVALID_RESET_TOKEN');
  });

  it('JWT e refresh token não servem como token de recuperação', async () => {
    await registerUser('hugo');
    const { accessToken, refreshToken } = (await login(email('hugo'), OLD_PASSWORD)).json<{
      accessToken: string;
      refreshToken: string;
    }>();

    for (const token of [accessToken, refreshToken]) {
      expect((await reset(token)).json<ErrorBody>().error.code).toBe('INVALID_RESET_TOKEN');
    }
  });

  it('nova senha fraca: 400 WEAK_PASSWORD e o link continua valendo', async () => {
    await registerUser('iris');
    const token = await requestToken('iris');

    const weak = await reset(token, 'Password2024!');
    const short = await reset(token, 'curta');

    expect(weak.json<ErrorBody>().error).toMatchObject({
      code: 'WEAK_PASSWORD',
      details: { reason: 'COMMON_PASSWORD' },
    });
    expect(short.statusCode).toBe(400);
    expect((await reset(token)).statusCode).toBe(200);
  });

  it('concorrência real: dois resets simultâneos com o mesmo token, só um vence', async () => {
    const user = await registerUser('joao');
    const token = await requestToken('joao');
    const passwords = ['primeira frase vencedora longa', 'segunda frase concorrente longa'];

    const responses = await Promise.all(passwords.map((password) => reset(token, password)));

    expect(responses.map((r) => r.statusCode).sort()).toEqual([200, 400]);
    const winner = passwords[responses.findIndex((r) => r.statusCode === 200)] ?? '';
    const loser = passwords.find((p) => p !== winner) ?? '';
    const row = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    await expect(verifyPassword(row.passwordHash, winner)).resolves.toBe(true);
    await expect(verifyPassword(row.passwordHash, loser)).resolves.toBe(false);
    expect(
      await prisma.auditEvent.count({ where: { userId: user.id, type: 'PASSWORD_RESET_SUCCESS' } }),
    ).toBe(1);
  });

  it('consumo único: 5 resets simultâneos, exatamente 1 sucesso', async () => {
    await registerUser('kaio');
    const token = await requestToken('kaio');

    const responses = await Promise.all(
      Array.from({ length: 5 }, (_, i) => reset(token, `frase concorrente numero ${i} longa`)),
    );

    expect(responses.filter((r) => r.statusCode === 200)).toHaveLength(1);
    expect(responses.filter((r) => r.statusCode === 400)).toHaveLength(4);
  });

  it('invalida os outros tokens ativos da conta', async () => {
    const user = await registerUser('lara');
    const first = await requestToken('lara');
    const second = await requestToken('lara');

    expect((await reset(second)).statusCode).toBe(200);

    expect((await reset(first, 'outra frase longa diferente')).json<ErrorBody>().error.code).toBe(
      'INVALID_RESET_TOKEN',
    );
    const active = await prisma.passwordResetToken.count({
      where: { userId: user.id, usedAt: null },
    });
    expect(active).toBe(0);
  });

  it('o token de uma conta não altera outra; email e userId no corpo são rejeitados', async () => {
    const victim = await registerUser('marta');
    await registerUser('nina');
    const ninaToken = await requestToken('nina');

    const withEmail = await post(app, 'reset-password', {
      token: ninaToken,
      newPassword: NEW_PASSWORD,
      email: email('marta'),
    });
    const withUserId = await post(app, 'reset-password', {
      token: ninaToken,
      newPassword: NEW_PASSWORD,
      userId: victim.id,
    });
    expect(withEmail.statusCode).toBe(400);
    expect(withUserId.statusCode).toBe(400);

    expect((await reset(ninaToken)).statusCode).toBe(200);
    expect((await login(email('marta'), OLD_PASSWORD)).statusCode).toBe(200);
    expect((await login(email('nina'), NEW_PASSWORD)).statusCode).toBe(200);
  });

  it('não altera o papel do usuário', async () => {
    const user = await registerUser('otto');
    await prisma.user.update({ where: { id: user.id }, data: { role: 'ADMIN' } });
    await reset(await requestToken('otto'));

    expect((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).role).toBe('ADMIN');
  });
});

describe('falha transacional', () => {
  it('erro na última etapa (revogar sessões) desfaz tudo: senha, token e sessões intactos', async () => {
    const user = await registerUser('paulo');
    await login(email('paulo'), OLD_PASSWORD);
    const token = await requestToken('paulo');
    const before = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });

    // Cliente com falha injetada em session.updateMany, que roda DEPOIS de consumir o token,
    // gravar a senha e invalidar os outros tokens, dentro da mesma transação.
    const faulty = prisma.$extends({
      query: {
        session: {
          updateMany() {
            throw new Error('falha simulada no meio da transação');
          },
        },
      },
    }) as unknown as PrismaClient;
    const service = createPasswordResetService({
      repository: createPasswordResetRepository(faulty),
      hashPassword,
      mailer,
      audit: { record: () => Promise.resolve() },
      tasks: createBackgroundTasks(() => undefined),
      tokenTtlMinutes: 15,
    });

    await expect(
      service.resetPassword(token, NEW_PASSWORD, { ip: null, userAgent: null }),
    ).rejects.toThrow(/falha simulada/);

    const after = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(after.passwordHash).toBe(before.passwordHash);
    expect(after.passwordChangedAt).toEqual(before.passwordChangedAt);
    const stored = await prisma.passwordResetToken.findUniqueOrThrow({
      where: { tokenHash: hashOpaqueToken(token) },
    });
    expect(stored.usedAt).toBeNull();
    expect(await prisma.session.count({ where: { userId: user.id, revokedAt: null } })).toBe(1);
    // E o link continua utilizável pelo caminho normal.
    expect((await reset(token)).statusCode).toBe(200);
  });
});

describe('auditoria', () => {
  it('registra pedido (com desfecho interno) e sucesso, sem token, senha ou email em texto', async () => {
    const user = await registerUser('quezia');
    const token = await requestToken('quezia');
    await forgot(UNKNOWN);
    await app.backgroundTasks.idle();
    await reset(token);

    const events = await prisma.auditEvent.findMany({
      where: {
        type: { in: ['PASSWORD_RESET_REQUEST', 'PASSWORD_RESET_SUCCESS'] },
        OR: [{ userId: user.id }, { emailHash: hashEmail(UNKNOWN) }],
      },
      orderBy: { createdAt: 'asc' },
    });
    expect(events.map((e) => [e.type, e.metadata])).toEqual([
      ['PASSWORD_RESET_REQUEST', { outcome: 'TOKEN_ISSUED' }],
      ['PASSWORD_RESET_REQUEST', { outcome: 'UNKNOWN_EMAIL' }],
      ['PASSWORD_RESET_SUCCESS', { revokedSessions: 0 }],
    ]);
    expect(events[1]?.emailHash).toBe(hashEmail(UNKNOWN));
    const stored = JSON.stringify(events);
    expect(stored).not.toContain(token);
    expect(stored).not.toContain(NEW_PASSWORD);
    expect(stored).not.toContain(DOMAIN);
  });
});

describe('rate limiting (defaults de produção)', () => {
  const strict = (overrides: Record<string, string> = {}) =>
    appWith(overrides, { rateLimits: 'default' });

  it('forgot-password: 5 por IP por hora; o 6º recebe 429', async () => {
    const limited = await strict();
    const statuses = [];
    for (let i = 0; i < 6; i++)
      statuses.push((await forgot(email(`ip${i}`), limited, `${NET}1`)).statusCode);
    await limited.backgroundTasks.idle();

    expect(statuses).toEqual([202, 202, 202, 202, 202, 429]);
  });

  it('forgot-password: 3 por conta por hora, mesmo de IPs diferentes; igual para conta inexistente', async () => {
    const limited = await strict();
    await registerUser('alvo');
    const sequence = async (address: string, base: number) => {
      const result = [];
      for (let i = 0; i < 4; i++)
        result.push((await forgot(address, limited, `${NET}${base + i}`)).statusCode);
      return result;
    };

    const existing = await sequence(email('alvo'), 10);
    const missing = await sequence(UNKNOWN, 20);
    await limited.backgroundTasks.idle();

    // O 429 aparece igual para as duas: o limite por conta não revela se ela existe.
    expect(existing).toEqual([202, 202, 202, 429]);
    expect(missing).toEqual([202, 202, 202, 429]);
    expect(mailer.to(email('alvo'))).toHaveLength(3);
  });

  it('reset-password: 10 tentativas por IP em 15 min', async () => {
    const limited = await strict();
    const statuses = [];
    for (let i = 0; i < 11; i++)
      statuses.push((await reset(`tentativa-${i}`, NEW_PASSWORD, limited, `${NET}30`)).statusCode);

    expect(statuses).toEqual([...Array<number>(10).fill(400), 429]);
  });

  it('Redis indisponível: forgot e reset respondem 503 (fail-closed), nada é enviado', async () => {
    await registerUser('redis');
    const broken = await appWith({ REDIS_URL: 'redis://127.0.0.1:1' }, { connectRedis: false });

    const responses = [
      await forgot(email('redis'), broken),
      await reset('qualquer', NEW_PASSWORD, broken),
    ];
    await broken.backgroundTasks.idle();

    for (const response of responses) {
      expect(response.statusCode).toBe(503);
      expect(response.json<ErrorBody>().error.code).toBe('SERVICE_UNAVAILABLE');
    }
    expect(mailer.sent).toHaveLength(0);
  });
});

describe('logs', () => {
  it('o fluxo inteiro não registra token, senhas, hash nem email', async () => {
    const lines: string[] = [];
    const logged = await appWith(
      { LOG_LEVEL: 'trace' },
      { logDestination: { write: (line: string) => void lines.push(line) } },
    );
    await registerUser('rita');
    const token = await requestToken('rita', logged);
    await forgot(UNKNOWN, logged);
    await logged.backgroundTasks.idle();
    await reset('token-invalido', NEW_PASSWORD, logged);
    await reset(token, 'Password2024!', logged);
    await reset(token, NEW_PASSWORD, logged);

    const log = lines.join('');
    expect(log).toContain('/api/v1/auth/reset-password');
    for (const secret of [
      token,
      hashOpaqueToken(token),
      NEW_PASSWORD,
      'Password2024!',
      email('rita'),
      UNKNOWN,
    ]) {
      expect(log).not.toContain(secret);
    }
    expect(log).not.toContain(encodeURIComponent(email('rita')));
    expect(log).not.toMatch(/argon2/i);
  });
});
