import type { FastifyInstance } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createPrismaClient, type PrismaClient } from '../../src/infra/prisma.js';
import { buildDetectionRules } from '../../src/modules/alerts/alert-rules.js';
import { CHECKPOINT_NAME, runDetection } from '../../src/modules/alerts/detection-engine.js';
import type { ErrorBody } from '../../src/shared/error-handler.js';
import { hashPassword } from '../../src/shared/password-hasher.js';
import { buildTestApp } from '../helpers/build-test-app.js';
import { purgeAuditEvents } from '../helpers/purge-audit-events.js';
import { TEST_DATABASE_URL, testEnv } from '../helpers/test-env.js';

/**
 * Resiliência: dependências fora do ar, reinício do servidor e do motor de alertas.
 * Dados fictícios: domínio próprio, IPs de 198.19.0.0/16 (RFC 2544), eventos com metadata.suite.
 */
const DOMAIN = '@resilience-test.example.com';
const SUITE = 'resilience-test';
const NET = '198.19.';
const PASSWORD = 'cavalo correto bateria grampo';
/** Banco inexistente com senha marcada: nunca pode aparecer em resposta nem em log. */
const DEAD_DATABASE = 'postgresql://ficticio:SenhaFicticiaQueNaoPodeVazar@127.0.0.1:1/inexistente';
const MIN = 60_000;

let prisma: PrismaClient;
const apps: FastifyInstance[] = [];

const ago = (ms: number) => new Date(Date.now() - ms);

async function track(app: Promise<FastifyInstance>) {
  const instance = await app;
  apps.push(instance);
  return instance;
}

async function cleanup() {
  await prisma.securityAlert.deleteMany({
    where: { NOT: { fingerprint: { startsWith: 'db-test:' } } },
  });
  await prisma.detectionCheckpoint.deleteMany({ where: { name: CHECKPOINT_NAME } });
  await prisma.detectionFlaggedEvent.deleteMany();
  await purgeAuditEvents(prisma, {
    where: {
      OR: [
        { metadata: { path: ['suite'], equals: SUITE } },
        { ip: { startsWith: NET } },
        { user: { email: { endsWith: DOMAIN } } },
      ],
    },
  });
  await prisma.user.deleteMany({ where: { email: { endsWith: DOMAIN } } });
}

/** Espera uma condição assíncrona (o motor roda em segundo plano), com prazo. */
async function waitFor<T>(probe: () => Promise<T | null | undefined>, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await probe();
    if (value) return value;
    if (Date.now() > deadline) throw new Error('condição não atingida no prazo');
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

beforeAll(() => {
  prisma = createPrismaClient(TEST_DATABASE_URL);
});

beforeEach(cleanup);

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

afterAll(async () => {
  await cleanup();
  await prisma.$disconnect();
});

describe('PostgreSQL indisponível', () => {
  it('login com o banco fora do ar: 500 genérico; nem resposta nem log revelam a conexão', async () => {
    const lines: string[] = [];
    const app = await track(
      buildTestApp(
        { DATABASE_URL: DEAD_DATABASE, LOG_LEVEL: 'trace' },
        { logDestination: { write: (line: string) => void lines.push(line) } },
      ),
    );

    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: `alguem${DOMAIN}`, password: PASSWORD },
    });

    expect(response.statusCode).toBe(500);
    expect(response.json<ErrorBody>().error).toMatchObject({
      code: 'INTERNAL_ERROR',
      message: 'Erro interno do servidor',
    });
    expect(response.body).not.toMatch(/SenhaFicticia|postgresql:|ECONNREFUSED|127\.0\.0\.1:1/);
    const logs = lines.join('\n');
    expect(logs).toContain('erro não tratado');
    expect(logs).not.toContain('SenhaFicticiaQueNaoPodeVazar');
    expect(logs).not.toContain(PASSWORD);
  });

  it('motor de alertas com o banco fora do ar: a rodada falha sem derrubar nada e é logada sem segredos', async () => {
    const lines: string[] = [];
    const app = await track(
      buildTestApp(
        { DATABASE_URL: DEAD_DATABASE, ALERTS_ENGINE_ENABLED: 'true', LOG_LEVEL: 'info' },
        { logDestination: { write: (line: string) => void lines.push(line) } },
      ),
    );

    await app.ready();
    await waitFor(async () =>
      lines.some((line) => line.includes('motor de alertas: rodada falhou')),
    );

    // A API continua respondendo (liveness) e o readiness reflete o banco fora do ar.
    expect((await app.inject({ method: 'GET', url: '/health' })).statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/ready' })).statusCode).toBe(503);
    expect(lines.join('\n')).not.toContain('SenhaFicticiaQueNaoPodeVazar');
  });

  it('runDetection direto contra um banco inacessível rejeita (o checkpoint real não muda)', async () => {
    const dead = createPrismaClient(DEAD_DATABASE);
    try {
      await expect(
        runDetection(dead, {
          rules: buildDetectionRules(testEnv()),
          lagMs: 0,
          initialLookbackMs: 3_600_000,
          dedupWindowMs: 86_400_000,
        }),
      ).rejects.toThrow();
    } finally {
      await dead.$disconnect();
    }
    expect(await prisma.detectionCheckpoint.count({ where: { name: CHECKPOINT_NAME } })).toBe(0);
  });
});

describe('reinício', () => {
  it('reinício do servidor: sessão e refresh token continuam valendo na nova instância', async () => {
    await prisma.user.create({
      data: {
        email: `reinicio${DOMAIN}`,
        name: 'Pessoa Reinício',
        passwordHash: await hashPassword(PASSWORD),
      },
    });
    const first = await buildTestApp();
    const login = await first.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: `reinicio${DOMAIN}`, password: PASSWORD },
    });
    const tokens = login.json<{ accessToken: string; refreshToken: string }>();
    await first.close();

    const second = await track(buildTestApp());
    const me = await second.inject({
      method: 'GET',
      url: '/api/v1/users/me',
      headers: { authorization: `Bearer ${tokens.accessToken}` },
    });
    const refreshed = await second.inject({
      method: 'POST',
      url: '/api/v1/auth/refresh',
      payload: { refreshToken: tokens.refreshToken },
    });

    expect(me.statusCode).toBe(200);
    expect(refreshed.statusCode).toBe(200);
  });

  it('motor dentro da API: roda ao subir, para ao fechar e, após reiniciar, continua do checkpoint', async () => {
    const ip = `${NET}1.1`;
    const at = ago(30 * MIN);
    await prisma.detectionCheckpoint.create({
      data: { name: CHECKPOINT_NAME, processedUntil: at },
    });
    for (let i = 0; i < 3; i++)
      await prisma.auditEvent.create({
        data: {
          type: 'RATE_LIMIT_EXCEEDED',
          ip,
          createdAt: ago((20 - i) * MIN),
          metadata: { suite: SUITE },
        },
      });
    const findAlert = () =>
      prisma.securityAlert.findFirst({
        where: { rule: 'RATE_LIMIT_ABUSE', details: { path: ['subject', 'ip'], equals: ip } },
      });

    // 1ª instância: o agendador começa no onReady (rodada imediata) e o close espera a rodada.
    const first = await buildTestApp({
      ALERTS_ENGINE_ENABLED: 'true',
      ALERTS_ENGINE_LAG_SECONDS: '0',
    });
    await first.ready();
    const created = await waitFor(findAlert);
    expect(created.eventCount).toBe(1);
    await first.close();
    const afterFirst = await prisma.detectionCheckpoint.findUniqueOrThrow({
      where: { name: CHECKPOINT_NAME },
    });
    expect(afterFirst.processedUntil.getTime()).toBeGreaterThan(at.getTime());

    // Com a API parada chegam mais bloqueios; a 2ª instância continua do checkpoint persistido.
    for (let i = 0; i < 2; i++)
      await prisma.auditEvent.create({
        data: { type: 'RATE_LIMIT_EXCEEDED', ip, metadata: { suite: SUITE } },
      });
    const second = await track(
      buildTestApp({ ALERTS_ENGINE_ENABLED: 'true', ALERTS_ENGINE_LAG_SECONDS: '0' }),
    );
    await second.ready();

    const updated = await waitFor(async () => {
      const alert = await findAlert();
      return alert && alert.eventCount === 3 ? alert : null;
    });
    expect(updated.id).toBe(created.id);
  }, 30_000);
});
