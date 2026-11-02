import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createPrismaClient, type PrismaClient } from '../../src/infra/prisma.js';
import {
  alertRetentionConfigSchema,
  runAlertRetention,
} from '../../src/modules/alerts/alert-retention.js';
import { TEST_DATABASE_URL } from '../helpers/test-env.js';

/** Somente alertas FICTÍCIOS, identificados pelo prefixo do fingerprint, no banco authapi_test. */
const PREFIX = 'retention-test:';
const DAY = 86_400_000;
const NOW = new Date('2026-11-02T12:00:00.000Z');
const daysAgo = (days: number) => new Date(NOW.getTime() - days * DAY);

let prisma: PrismaClient;

async function alert(name: string, status: 'OPEN' | 'RESOLVED', ageDays: number) {
  const at = daysAgo(ageDays);
  return prisma.securityAlert.create({
    data: {
      rule: 'RATE_LIMIT_ABUSE',
      severity: 'LOW',
      status,
      fingerprint: `${PREFIX}${name}`,
      summary: 'alerta fictício de retenção',
      details: { peak: 3 },
      firstSeenAt: at,
      lastSeenAt: at,
      createdAt: at,
      resolvedAt: status === 'RESOLVED' ? at : null,
    },
    select: { id: true },
  });
}

const remaining = async () =>
  (
    await prisma.securityAlert.findMany({
      where: { fingerprint: { startsWith: PREFIX } },
      select: { fingerprint: true },
      orderBy: { fingerprint: 'asc' },
    })
  ).map((row) => row.fingerprint.slice(PREFIX.length));

const config = (overrides: Record<string, string> = {}) =>
  alertRetentionConfigSchema.parse({ ALERTS_RETENTION_DAYS: '365', ...overrides });

beforeAll(() => {
  prisma = createPrismaClient(TEST_DATABASE_URL);
});

beforeEach(async () => {
  await prisma.securityAlert.deleteMany({ where: { fingerprint: { startsWith: PREFIX } } });
  await alert('resolvido-antigo-1', 'RESOLVED', 400);
  await alert('resolvido-antigo-2', 'RESOLVED', 500);
  await alert('resolvido-antigo-3', 'RESOLVED', 600);
  await alert('resolvido-recente', 'RESOLVED', 10);
  await alert('aberto-antigo', 'OPEN', 900);
});

afterAll(async () => {
  await prisma.securityAlert.deleteMany({ where: { fingerprint: { startsWith: PREFIX } } });
  await prisma.$disconnect();
});

describe('retenção de alertas (dados fictícios)', () => {
  it('configuração: desligada por padrão; prazo mínimo de 30 dias', () => {
    expect(alertRetentionConfigSchema.parse({})).toEqual({
      ALERTS_RETENTION_ENABLED: false,
      ALERTS_RETENTION_DAYS: 365,
      ALERTS_RETENTION_BATCH_SIZE: 500,
      ALERTS_RETENTION_MAX_BATCHES: 100,
    });
    expect(alertRetentionConfigSchema.safeParse({ ALERTS_RETENTION_DAYS: '7' }).success).toBe(
      false,
    );
  });

  it('simulação (padrão): conta, mas não apaga nada', async () => {
    const result = await runAlertRetention(prisma, config(), { now: NOW });

    expect(result).toMatchObject({
      dryRun: true,
      eligible: 3,
      openOlderThanCutoff: 1,
      deleted: 0,
      batches: 0,
    });
    expect(await remaining()).toHaveLength(5);
  });

  it('execução: apaga só RESOLVED vencidos, em lotes; OPEN antigo e RESOLVED recente ficam', async () => {
    const result = await runAlertRetention(prisma, config({ ALERTS_RETENTION_BATCH_SIZE: '2' }), {
      now: NOW,
      dryRun: false,
    });

    expect(result).toMatchObject({ eligible: 3, deleted: 3, batches: 2, complete: true });
    expect(await remaining()).toEqual(['aberto-antigo', 'resolvido-recente']);
  });

  it('limite de lotes: para no teto e informa que ainda há vencidos', async () => {
    const result = await runAlertRetention(
      prisma,
      config({ ALERTS_RETENTION_BATCH_SIZE: '1', ALERTS_RETENTION_MAX_BATCHES: '2' }),
      { now: NOW, dryRun: false },
    );

    expect(result).toMatchObject({ deleted: 2, batches: 2, complete: false });
    expect(await remaining()).toHaveLength(3);
  });

  it('alerta OPEN nunca é elegível: o CHECK do banco impede OPEN com resolvedAt', async () => {
    // Um alerta OPEN nunca entra no lote, mesmo que tenha resolvedAt antigo por erro de dados:
    // o CHECK do banco impede esse estado, e o WHERE do DELETE repete status e data.
    const where = { status: 'RESOLVED' as const, resolvedAt: { lt: daysAgo(365) } };
    expect(
      await prisma.securityAlert.count({
        where: { ...where, fingerprint: { startsWith: PREFIX } },
      }),
    ).toBe(3);
    await expect(
      prisma.securityAlert.updateMany({
        where: { fingerprint: `${PREFIX}aberto-antigo` },
        data: { resolvedAt: daysAgo(900) },
      }),
    ).rejects.toThrow();
  });
});
