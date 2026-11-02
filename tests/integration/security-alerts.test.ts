import { createHash } from 'node:crypto';
import type { FastifyInstance, InjectOptions } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { AuditEventType } from '../../src/generated/prisma/enums.js';
import { createPrismaClient, type PrismaClient } from '../../src/infra/prisma.js';
import type { AlertEvidence, AlertExplainer } from '../../src/modules/alerts/alert-explainer.js';
import { buildDetectionRules, type DetectionRule } from '../../src/modules/alerts/alert-rules.js';
import { upsertAlert } from '../../src/modules/alerts/detection.repository.js';
import {
  CHECKPOINT_NAME,
  runDetection,
  type EngineConfig,
} from '../../src/modules/alerts/detection-engine.js';
import type { ErrorBody } from '../../src/shared/error-handler.js';
import { hashPassword } from '../../src/shared/password-hasher.js';
import { buildTestApp, type BuildTestAppOptions } from '../helpers/build-test-app.js';
import { purgeAuditEvents } from '../helpers/purge-audit-events.js';
import { TEST_DATABASE_URL, testEnv } from '../helpers/test-env.js';

/**
 * Dados fictícios: domínio próprio, IPs da faixa de benchmark 198.18.0.0/15 (RFC 2544) e
 * eventos marcados com metadata.suite. O motor só roda quando o teste chama runDetection
 * (ALERTS_ENGINE_ENABLED=false nos testes).
 */
const DOMAIN = '@alerts-test.example.com';
const SUITE = 'alerts-test';
const NET = '198.18.';
const PASSWORD = 'cavalo correto bateria grampo';
const MIN = 60_000;
const YEAR = 365 * 86_400_000;

let prisma: PrismaClient;
let app: FastifyInstance;
const extraApps: FastifyInstance[] = [];
const rules = buildDetectionRules(testEnv());

/** Deduplicação anual nos testes: evita que um teste perto da meia-noite UTC vire dois alertas. */
const engine = (overrides: Partial<EngineConfig> = {}): EngineConfig => ({
  rules,
  lagMs: 0,
  initialLookbackMs: 24 * 3_600_000,
  dedupWindowMs: YEAR,
  ...overrides,
});

const sha = (value: string) => createHash('sha256').update(value).digest('hex');
const ago = (ms: number) => new Date(Date.now() - ms);

async function dbNow() {
  const [row] = await prisma.$queryRaw<{ now: Date }[]>`SELECT now() AS now`;
  return row?.now ?? new Date();
}

/** Começa a avaliação logo antes dos eventos do teste (isola de eventos de outros testes). */
async function startCheckpointAt(at: Date) {
  await prisma.detectionCheckpoint.upsert({
    where: { name: CHECKPOINT_NAME },
    create: { name: CHECKPOINT_NAME, processedUntil: at },
    update: { processedUntil: at },
  });
}

/** `at` retroativo só ANTES da rodada; depois dela, use `null` (now() do banco, como na aplicação). */
async function event(
  type: AuditEventType,
  at: Date | null,
  data: { ip?: string; emailHash?: string; userId?: string } = {},
) {
  return prisma.auditEvent.create({
    data: { type, ...(at && { createdAt: at }), metadata: { suite: SUITE }, ...data },
  });
}

async function user(local: string) {
  return prisma.user.create({
    data: {
      email: `${local}${DOMAIN}`,
      name: `Pessoa ${local}`,
      passwordHash: await hashPassword(PASSWORD),
    },
    select: { id: true },
  });
}

const alertsFor = (rule: string) =>
  prisma.securityAlert.findMany({ where: { rule: rule as never }, orderBy: { createdAt: 'asc' } });

async function cleanup() {
  // Banco de testes: os alertas existentes vêm só desta suíte (o motor não roda nas outras),
  // exceto os do database.test, identificados pelo prefixo próprio.
  await prisma.securityAlert.deleteMany({
    where: { NOT: { fingerprint: { startsWith: 'db-test:' } } },
  });
  await prisma.detectionCheckpoint.deleteMany({ where: { name: CHECKPOINT_NAME } });
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

beforeAll(() => {
  prisma = createPrismaClient(TEST_DATABASE_URL);
});

beforeEach(async () => {
  await cleanup();
  app = await buildTestApp();
});

afterEach(async () => {
  await Promise.all([app, ...extraApps.splice(0)].map((instance) => instance.close()));
});

afterAll(async () => {
  await cleanup();
  await prisma.$disconnect();
});

describe('regras de detecção', () => {
  it('BRUTE_FORCE_ACCOUNT: 8 falhas para a mesma conta em 1 h (7 não disparam)', async () => {
    const victim = await user('vitima');
    await startCheckpointAt(ago(70 * MIN));
    const target = sha(`vitima${DOMAIN}`);
    for (let i = 0; i < 7; i++)
      await event('LOGIN_FAILURE', ago((50 - i) * MIN), {
        emailHash: target,
        userId: victim.id,
        ip: `${NET}0.${i}`,
      });
    await runDetection(prisma, engine());
    expect(await alertsFor('BRUTE_FORCE_ACCOUNT')).toEqual([]);

    // A 8ª falha chega depois da rodada, com o horário real: as 7 anteriores ainda estão na janela.
    await event('LOGIN_FAILURE', null, {
      emailHash: target,
      userId: victim.id,
      ip: `${NET}0.9`,
    });
    await runDetection(prisma, engine());

    const [alert] = await alertsFor('BRUTE_FORCE_ACCOUNT');
    expect(alert).toMatchObject({
      severity: 'MEDIUM',
      status: 'OPEN',
      userId: victim.id,
      eventCount: 1,
    });
    expect(alert?.details).toMatchObject({
      threshold: 8,
      windowSeconds: 3600,
      peak: 8,
      eventType: 'LOGIN_FAILURE',
      subject: { kind: 'account', userId: victim.id },
    });
  });

  it('BRUTE_FORCE_ACCOUNT: 8 falhas espalhadas em mais de 1 h não disparam (janela deslizante)', async () => {
    await startCheckpointAt(ago(4 * 60 * MIN));
    const target = sha(`espalhada${DOMAIN}`);
    // Uma a cada 20 min: no máximo 4 em qualquer janela de 1 h.
    for (let i = 0; i < 8; i++)
      await event('LOGIN_FAILURE', ago((170 - i * 20) * MIN), { emailHash: target });

    await runDetection(prisma, engine());

    expect(await alertsFor('BRUTE_FORCE_ACCOUNT')).toEqual([]);
  });

  it('BRUTE_FORCE_ACCOUNT: conta inexistente gera alerta sem userId e sem hash de email', async () => {
    await startCheckpointAt(ago(30 * MIN));
    const target = sha(`ninguem${DOMAIN}`);
    for (let i = 0; i < 8; i++)
      await event('LOGIN_FAILURE', ago((20 - i) * MIN), { emailHash: target });

    await runDetection(prisma, engine());

    const [alert] = await alertsFor('BRUTE_FORCE_ACCOUNT');
    expect(alert).toMatchObject({ userId: null });
    expect(alert?.details).toMatchObject({ subject: { kind: 'account', userId: null } });
    expect(JSON.stringify(alert)).not.toContain(target);
  });

  it('CREDENTIAL_STUFFING: um IP falhando em 5 contas diferentes em 1 h → HIGH', async () => {
    await startCheckpointAt(ago(30 * MIN));
    const ip = `${NET}1.1`;
    for (let i = 0; i < 5; i++)
      await event('LOGIN_FAILURE', ago((20 - i) * MIN), { ip, emailHash: sha(`c${i}`) });
    // Mesmo volume, mas sempre a mesma conta: não é stuffing.
    for (let i = 0; i < 5; i++)
      await event('LOGIN_FAILURE', ago((20 - i) * MIN), {
        ip: `${NET}1.2`,
        emailHash: sha('mesma'),
      });

    await runDetection(prisma, engine());

    const alerts = await alertsFor('CREDENTIAL_STUFFING');
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({ severity: 'HIGH', userId: null });
    expect(alerts[0]?.details).toMatchObject({ peak: 5, subject: { kind: 'ip', ip } });
  });

  it('TOKEN_REUSE: um único reuso já gera alerta HIGH ligado ao usuário', async () => {
    const owner = await user('dono');
    await startCheckpointAt(ago(10 * MIN));
    await event('TOKEN_REUSE_DETECTED', ago(5 * MIN), { userId: owner.id, ip: `${NET}2.1` });

    await runDetection(prisma, engine());

    expect(await alertsFor('TOKEN_REUSE')).toEqual([
      expect.objectContaining({ severity: 'HIGH', userId: owner.id, eventCount: 1 }),
    ]);
  });

  it('RATE_LIMIT_ABUSE: 3 bloqueios do mesmo IP → LOW; 6 → MEDIUM (sobe, nunca desce)', async () => {
    await startCheckpointAt(ago(50 * MIN));
    const ip = `${NET}3.1`;
    for (let i = 0; i < 3; i++) await event('RATE_LIMIT_EXCEEDED', ago((40 - i) * MIN), { ip });
    await runDetection(prisma, engine());
    expect((await alertsFor('RATE_LIMIT_ABUSE'))[0]).toMatchObject({
      severity: 'LOW',
      eventCount: 1,
    });

    // Novos bloqueios chegam depois da rodada, com o horário real (janela de 1 h inclui os 3 anteriores).
    for (let i = 0; i < 3; i++) await event('RATE_LIMIT_EXCEEDED', null, { ip });
    await runDetection(prisma, engine());

    const alerts = await alertsFor('RATE_LIMIT_ABUSE');
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({ severity: 'MEDIUM', eventCount: 4 });
    expect(alerts[0]?.details).toMatchObject({ peak: 6 });
  });

  it('ADMIN_ACCESS_PROBING: 5 acessos negados do mesmo usuário em 1 h', async () => {
    const probe = await user('curioso');
    await startCheckpointAt(ago(30 * MIN));
    for (let i = 0; i < 5; i++)
      await event('ACCESS_DENIED', ago((20 - i) * MIN), { userId: probe.id });

    await runDetection(prisma, engine());

    expect(await alertsFor('ADMIN_ACCESS_PROBING')).toEqual([
      expect.objectContaining({ severity: 'MEDIUM', userId: probe.id }),
    ]);
  });

  it('PASSWORD_RESET_ABUSE: 5 pedidos de recuperação do mesmo IP em 1 h', async () => {
    await startCheckpointAt(ago(30 * MIN));
    for (let i = 0; i < 5; i++)
      await event('PASSWORD_RESET_REQUEST', ago((20 - i) * MIN), {
        ip: `${NET}4.1`,
        emailHash: sha(`r${i}`),
      });

    await runDetection(prisma, engine());

    expect(await alertsFor('PASSWORD_RESET_ABUSE')).toEqual([
      expect.objectContaining({ severity: 'LOW' }),
    ]);
  });

  it('não gera alerta a partir de eventos administrativos nem grava eventos de auditoria', async () => {
    const admin = await user('admin-ruidoso');
    await startCheckpointAt(ago(30 * MIN));
    for (let i = 0; i < 20; i++)
      await event('ADMIN_SECURITY_ALERTS_QUERIED', ago((20 - i / 2) * MIN), { userId: admin.id });
    const before = await prisma.auditEvent.count();

    await runDetection(prisma, engine());

    expect(
      await prisma.securityAlert.count({
        where: { NOT: { fingerprint: { startsWith: 'db-test:' } } },
      }),
    ).toBe(0);
    expect(await prisma.auditEvent.count()).toBe(before);
  });
});

describe('processamento, deduplicação e recuperação', () => {
  it('rodar de novo sem eventos novos não altera nada (sem dupla contagem)', async () => {
    await startCheckpointAt(ago(30 * MIN));
    for (let i = 0; i < 3; i++)
      await event('RATE_LIMIT_EXCEEDED', ago((20 - i) * MIN), { ip: `${NET}5.1` });
    await runDetection(prisma, engine());
    const first = await alertsFor('RATE_LIMIT_ABUSE');

    await runDetection(prisma, engine());
    await runDetection(prisma, engine());

    expect(await alertsFor('RATE_LIMIT_ABUSE')).toEqual(first);
  });

  it('o checkpoint é persistido: um "reinício" continua de onde parou e pega o que chegou nesse meio', async () => {
    await startCheckpointAt(ago(60 * MIN));
    const ip = `${NET}5.2`;
    for (let i = 0; i < 3; i++) await event('RATE_LIMIT_EXCEEDED', ago((50 - i) * MIN), { ip });
    const firstRun = await runDetection(prisma, engine());
    const saved = await prisma.detectionCheckpoint.findUniqueOrThrow({
      where: { name: CHECKPOINT_NAME },
    });
    expect(saved.processedUntil).toEqual(firstRun.processedUntil);

    // Eventos que chegam com o "processo parado" (depois do checkpoint): a próxima rodada, sem
    // nenhum estado em memória, os pega a partir do checkpoint persistido.
    const after = firstRun.processedUntil?.getTime() ?? 0;
    for (let i = 0; i < 2; i++) await event('RATE_LIMIT_EXCEEDED', new Date(after + 5 + i), { ip });
    await new Promise((resolve) => setTimeout(resolve, 20));
    const secondRun = await runDetection(prisma, engine());

    expect(secondRun.acquired).toBe(true);
    const [alert] = await alertsFor('RATE_LIMIT_ABUSE');
    expect(alert?.eventCount).toBe(3); // 1 (3º evento) + 2 novos acima do limite
    expect(secondRun.processedUntil?.getTime()).toBeGreaterThan(
      firstRun.processedUntil?.getTime() ?? 0,
    );
  });

  it('retoma após parada longa em vários intervalos (maxRange), com o mesmo resultado', async () => {
    await startCheckpointAt(ago(5 * 60 * MIN));
    for (let i = 0; i < 8; i++)
      await event('LOGIN_FAILURE', ago((250 - i) * MIN), { emailHash: sha('longa') });

    const result = await runDetection(prisma, engine({ maxRangeMs: 60 * MIN }));

    expect(result.iterations).toBeGreaterThanOrEqual(5);
    expect(await alertsFor('BRUTE_FORCE_ACCOUNT')).toEqual([
      expect.objectContaining({ eventCount: 1 }),
    ]);
  });

  it('respeita maxIterations e informa que ficou para trás', async () => {
    await startCheckpointAt(ago(5 * 60 * MIN));

    const result = await runDetection(prisma, engine({ maxRangeMs: 60 * MIN, maxIterations: 2 }));

    expect(result).toMatchObject({ iterations: 2, behind: true });
  });

  it('falha no meio da rodada: nada é confirmado; a próxima rodada reprocessa sem perder nem duplicar', async () => {
    const start = ago(30 * MIN);
    await startCheckpointAt(start);
    for (let i = 0; i < 3; i++)
      await event('RATE_LIMIT_EXCEEDED', ago((20 - i) * MIN), { ip: `${NET}5.3` });
    const broken: DetectionRule = {
      ...rules[0],
      eventType: 'TIPO_INEXISTENTE' as AuditEventType,
    } as DetectionRule;
    const rateRule = rules.find((r) => r.rule === 'RATE_LIMIT_ABUSE') as DetectionRule;

    // A regra válida roda primeiro e grava; a quebrada falha depois, na mesma transação.
    await expect(runDetection(prisma, engine({ rules: [rateRule, broken] }))).rejects.toThrow();

    expect(await alertsFor('RATE_LIMIT_ABUSE')).toEqual([]);
    const checkpoint = await prisma.detectionCheckpoint.findUniqueOrThrow({
      where: { name: CHECKPOINT_NAME },
    });
    expect(checkpoint.processedUntil).toEqual(start);

    await runDetection(prisma, engine());
    expect(await alertsFor('RATE_LIMIT_ABUSE')).toEqual([
      expect.objectContaining({ eventCount: 1 }),
    ]);
  });

  it('LIMITAÇÃO documentada: evento gravado com horário anterior ao checkpoint não é reavaliado', async () => {
    await startCheckpointAt(ago(10 * MIN));
    await runDetection(prisma, engine());
    // Simula um INSERT que só confirmou depois que o checkpoint já passou do horário dele
    // (mais atrasado que ALERTS_ENGINE_LAG_SECONDS). Na aplicação, os INSERTs de auditoria são
    // instantâneos e o lag (5 s) cobre essa folga; ver docs/architecture.md.
    for (let i = 0; i < 3; i++)
      await event('RATE_LIMIT_EXCEEDED', ago(5 * MIN), { ip: `${NET}5.9` });

    await runDetection(prisma, engine());

    expect(await alertsFor('RATE_LIMIT_ABUSE')).toEqual([]);
  });

  it('eventos mais novos que o lag esperam a próxima rodada', async () => {
    await startCheckpointAt(ago(10 * MIN));
    for (let i = 0; i < 3; i++)
      await event('RATE_LIMIT_EXCEEDED', ago(2_000 + i), { ip: `${NET}5.4` });

    await runDetection(prisma, engine({ lagMs: 60_000 }));
    expect(await alertsFor('RATE_LIMIT_ABUSE')).toEqual([]);

    await runDetection(prisma, engine({ lagMs: 0 }));
    expect(await alertsFor('RATE_LIMIT_ABUSE')).toHaveLength(1);
  });

  it('deduplicação deslizante: incidente que atravessa a virada do período continua no mesmo alerta', async () => {
    const window = 10 * MIN;
    let now = (await dbNow()).getTime();
    // Precisa de alguns segundos dentro do período atual para os eventos "novos".
    if (now - Math.floor(now / window) * window < 5_000) {
      await new Promise((resolve) => setTimeout(resolve, 5_000));
      now = (await dbNow()).getTime();
    }
    const bucketStart = Math.floor(now / window) * window;
    const from = bucketStart - 2 * window;
    await startCheckpointAt(new Date(from));
    const ip = `${NET}5.5`;
    // 3 eventos no fim do período anterior e 3 logo após a virada: o mesmo incidente.
    for (let i = 0; i < 3; i++)
      await event('RATE_LIMIT_EXCEEDED', new Date(bucketStart - 60_000 + i), { ip });
    for (let i = 0; i < 3; i++)
      await event('RATE_LIMIT_EXCEEDED', new Date(bucketStart + 1000 + i), { ip });

    // 1ª iteração vai até o fim do período anterior; a 2ª cobre o atual.
    const result = await runDetection(
      prisma,
      engine({ dedupWindowMs: window, maxRangeMs: bucketStart - 1 - from }),
    );

    expect(result.iterations).toBeGreaterThanOrEqual(2);
    expect(result).toMatchObject({ created: 1, updated: 1 });
    const alerts = await alertsFor('RATE_LIMIT_ABUSE');
    expect(alerts).toHaveLength(1);
    // Fingerprint do período em que o incidente começou; 1 evento no 1º trecho + 3 no 2º.
    expect(alerts[0]?.fingerprint.endsWith(`:${Math.floor((bucketStart - 1) / window)}`)).toBe(
      true,
    );
    expect(alerts[0]).toMatchObject({ eventCount: 4, severity: 'MEDIUM' });
  });

  it('deduplicação deslizante: depois de um intervalo maior que a janela, a atividade vira alerta novo', async () => {
    const window = 10 * MIN;
    const from = ago(45 * MIN);
    await startCheckpointAt(from);
    const ip = `${NET}5.6`;
    const at = (offsetMs: number) => new Date(from.getTime() + offsetMs);
    // Lote 1 em from+5 min; lote 2 em from+20 min: 15 min sem atividade (> 10 min de janela).
    for (let i = 0; i < 3; i++) await event('RATE_LIMIT_EXCEEDED', at(5 * MIN + i), { ip });
    for (let i = 0; i < 3; i++) await event('RATE_LIMIT_EXCEEDED', at(20 * MIN + i), { ip });

    await runDetection(prisma, engine({ dedupWindowMs: window, maxRangeMs: 10 * MIN }));

    const alerts = await alertsFor('RATE_LIMIT_ABUSE');
    expect(alerts).toHaveLength(2);
    expect(new Set(alerts.map((a) => a.fingerprint)).size).toBe(2);
    // Lote 2 ainda está na janela de 1 h da regra junto com o lote 1: os 3 eventos contam.
    expect(alerts.map((a) => a.eventCount)).toEqual([1, 3]);
    expect(alerts.every((a) => a.status === 'OPEN')).toBe(true);
  });

  it('alerta RESOLVED não recebe continuação: a atividade nova abre outro alerta', async () => {
    const from = ago(30 * MIN);
    await startCheckpointAt(from);
    const ip = `${NET}5.7`;
    for (let i = 0; i < 3; i++)
      await event('RATE_LIMIT_EXCEEDED', new Date(from.getTime() + MIN + i), { ip });
    await runDetection(prisma, engine({ lagMs: 0 }));
    const [first] = await alertsFor('RATE_LIMIT_ABUSE');
    // Resolução manual (não há endpoint para isso: é ação humana fora da API).
    await prisma.securityAlert.update({
      where: { id: first?.id ?? '' },
      data: { status: 'RESOLVED', resolvedAt: new Date() },
    });

    await event('RATE_LIMIT_EXCEEDED', null, { ip });
    await runDetection(prisma, engine({ lagMs: 0 }));

    const alerts = await alertsFor('RATE_LIMIT_ABUSE');
    expect(alerts.map((a) => [a.status, a.eventCount])).toEqual([
      ['RESOLVED', 1],
      ['OPEN', 1],
    ]);
  });
});

describe('concorrência', () => {
  it('duas rodadas simultâneas: uma por vez (advisory lock), sem alertas duplicados', async () => {
    await startCheckpointAt(ago(30 * MIN));
    for (let i = 0; i < 8; i++)
      await event('LOGIN_FAILURE', ago((20 - i) * MIN), { emailHash: sha('concorrente') });

    const results = await Promise.all([
      runDetection(prisma, engine()),
      runDetection(prisma, engine()),
    ]);

    expect(results.some((r) => r.acquired)).toBe(true);
    expect(await alertsFor('BRUTE_FORCE_ACCOUNT')).toEqual([
      expect.objectContaining({ eventCount: 1 }),
    ]);
  });

  it('5 gravações simultâneas do mesmo incidente: um único alerta aberto, contagens somadas', async () => {
    const base = {
      rule: 'RATE_LIMIT_ABUSE' as const,
      severity: 'LOW' as const,
      fingerprint: `RATE_LIMIT_ABUSE:${'a'.repeat(32)}:1`,
      summary: 'teste de concorrência',
      details: { peak: 3 },
      userId: null,
      eventCount: 1,
      firstSeen: ago(10 * MIN),
      lastSeen: ago(5 * MIN),
    };

    const outcomes = await Promise.all(
      Array.from({ length: 5 }, (_, i) =>
        prisma.$transaction((tx) => upsertAlert(tx, { ...base, details: { peak: 3 + i } })),
      ),
    );

    expect(outcomes.filter((o) => o === 'created')).toHaveLength(1);
    const alerts = await alertsFor('RATE_LIMIT_ABUSE');
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({ eventCount: 5, status: 'OPEN' });
    expect(alerts[0]?.details).toMatchObject({ peak: 7 });
  });
});

describe('ponta a ponta: tentativas reais → alerta → consulta', () => {
  it('8 logins errados pela API geram BRUTE_FORCE_ACCOUNT visível ao ADMIN', async () => {
    const victim = await user('alvo-real');
    const admin = await user('chefe');
    await prisma.user.update({ where: { id: admin.id }, data: { role: 'ADMIN' } });
    await startCheckpointAt(await dbNow());
    for (let i = 0; i < 8; i++) {
      await app.inject({
        method: 'POST',
        url: '/api/v1/auth/login',
        payload: { email: `alvo-real${DOMAIN}`, password: 'senha errada porém longa' },
        remoteAddress: `${NET}6.${i}`,
      });
    }

    await runDetection(prisma, engine());

    const login = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: `chefe${DOMAIN}`, password: PASSWORD },
    });
    const { accessToken } = login.json<{ accessToken: string }>();
    const list = await app.inject({
      method: 'GET',
      url: '/api/v1/admin/security-alerts?rule=BRUTE_FORCE_ACCOUNT',
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(list.statusCode).toBe(200);
    const body = list.json<{ data: { rule: string; userId: string | null }[] }>();
    expect(body.data).toEqual([
      expect.objectContaining({ rule: 'BRUTE_FORCE_ACCOUNT', userId: victim.id }),
    ]);
  });
});

describe('endpoints administrativos', () => {
  async function adminToken(local = 'adm') {
    const admin = await user(local);
    await prisma.user.update({ where: { id: admin.id }, data: { role: 'ADMIN' } });
    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: `${local}${DOMAIN}`, password: PASSWORD },
    });
    return { id: admin.id, token: response.json<{ accessToken: string }>().accessToken };
  }

  async function seedAlerts() {
    await startCheckpointAt(ago(30 * MIN));
    for (let i = 0; i < 3; i++)
      await event('RATE_LIMIT_EXCEEDED', ago((20 - i) * MIN), { ip: `${NET}7.1` });
    for (let i = 0; i < 5; i++)
      await event('LOGIN_FAILURE', ago((20 - i) * MIN), {
        ip: `${NET}7.2`,
        emailHash: sha(`s${i}`),
      });
    for (let i = 0; i < 5; i++)
      await event('PASSWORD_RESET_REQUEST', ago((20 - i) * MIN), { ip: `${NET}7.3` });
    await runDetection(prisma, engine());
  }

  const get = (url: string, token?: string, target = app) =>
    target.inject({
      method: 'GET',
      url,
      ...(token && { headers: { authorization: `Bearer ${token}` } }),
    } as InjectOptions);

  it('RBAC: anônimo 401, USER 403, ADMIN 200', async () => {
    const regular = await user('comum');
    const userLogin = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: `comum${DOMAIN}`, password: PASSWORD },
    });
    const { token } = await adminToken();

    expect((await get('/api/v1/admin/security-alerts')).statusCode).toBe(401);
    expect(
      (
        await get(
          '/api/v1/admin/security-alerts',
          userLogin.json<{ accessToken: string }>().accessToken,
        )
      ).statusCode,
    ).toBe(403);
    expect((await get('/api/v1/admin/security-alerts', token)).statusCode).toBe(200);
    expect(regular.id).toBeTruthy();
  });

  it('paginação e filtros por regra, severidade e estado', async () => {
    await seedAlerts();
    const { token } = await adminToken();
    const list = async (query: string) =>
      (await get(`/api/v1/admin/security-alerts?${query}`, token)).json<{
        data: { rule: string; severity: string }[];
        pagination: { total: number; totalPages: number };
      }>();

    expect((await list('')).pagination.total).toBe(3);
    expect((await list('pageSize=1')).pagination).toMatchObject({ total: 3, totalPages: 3 });
    expect((await list('rule=CREDENTIAL_STUFFING')).data.map((a) => a.severity)).toEqual(['HIGH']);
    expect((await list('severity=LOW')).data.map((a) => a.rule).sort()).toEqual([
      'PASSWORD_RESET_ABUSE',
      'RATE_LIMIT_ABUSE',
    ]);
    expect((await list('status=RESOLVED')).pagination.total).toBe(0);
    const asc = (await list('order=asc')).data.map((a) => a.rule);
    expect((await list('order=desc')).data.map((a) => a.rule)).toEqual([...asc].reverse());
  });

  it.each([
    ['regra inexistente', 'rule=HACK'],
    ['severidade inválida', 'severity=CRITICAL'],
    ['pageSize acima do máximo', 'pageSize=101'],
    ['parâmetro desconhecido', 'fingerprint=x'],
  ])('400 para %s', async (_label, query) => {
    const { token } = await adminToken();

    expect((await get(`/api/v1/admin/security-alerts?${query}`, token)).statusCode).toBe(400);
  });

  it('consulta individual: 200 sem fingerprint; 404 inexistente; 400 id inválido', async () => {
    await seedAlerts();
    const { token } = await adminToken();
    const [alert] = await alertsFor('CREDENTIAL_STUFFING');

    const found = await get(`/api/v1/admin/security-alerts/${alert?.id ?? ''}`, token);
    const missing = await get(
      '/api/v1/admin/security-alerts/0190a000-0000-7000-8000-0000000000ff',
      token,
    );
    const invalid = await get('/api/v1/admin/security-alerts/nao-e-uuid', token);

    expect(found.statusCode).toBe(200);
    expect(found.json()).toMatchObject({
      id: alert?.id,
      rule: 'CREDENTIAL_STUFFING',
      severity: 'HIGH',
    });
    expect(found.body).not.toContain('fingerprint');
    expect(missing.statusCode).toBe(404);
    expect(missing.json<ErrorBody>().error.code).toBe('NOT_FOUND');
    expect(invalid.statusCode).toBe(400);
  });

  it('respostas sem dados sensíveis (nem email, hash de email, senha ou token)', async () => {
    await seedAlerts();
    const { token } = await adminToken();

    const body = (await get('/api/v1/admin/security-alerts?pageSize=100', token)).body;

    // O nome do tipo PASSWORD_RESET_REQUEST pode aparecer em details.eventType; chaves de senha, nunca.
    expect(body).not.toMatch(/fingerprint|emailHash|email_hash|passwordHash|"password"|@|argon2/i);
    for (let i = 0; i < 5; i++) expect(body).not.toContain(sha(`s${i}`));
    expect(body).not.toContain(token);
  });

  it('cada consulta é auditada (ADMIN_SECURITY_ALERTS_QUERIED) e não vira alerta', async () => {
    await seedAlerts();
    const { id, token } = await adminToken();
    for (let i = 0; i < 6; i++) await get('/api/v1/admin/security-alerts', token);

    await runDetection(prisma, engine());

    expect(
      await prisma.auditEvent.count({
        where: { userId: id, type: 'ADMIN_SECURITY_ALERTS_QUERIED' },
      }),
    ).toBe(6);
    expect(await prisma.securityAlert.count({ where: { userId: id } })).toBe(0);
  });

  it('rate limit (defaults): explicação 10/min por ADMIN; a 11ª recebe 429', async () => {
    await seedAlerts();
    const strict = await buildTestApp({}, { rateLimits: 'default' } satisfies BuildTestAppOptions);
    extraApps.push(strict);
    const { token } = await adminToken();
    const [alert] = await alertsFor('RATE_LIMIT_ABUSE');
    const statuses = [];
    for (let i = 0; i < 11; i++) {
      const response = await strict.inject({
        method: 'POST',
        url: `/api/v1/admin/security-alerts/${alert?.id ?? ''}/explanation`,
        headers: { authorization: `Bearer ${token}` },
      });
      statuses.push(response.statusCode);
    }

    expect(statuses).toEqual([...Array<number>(10).fill(200), 429]);
  });
});

describe('IA local (explicação)', () => {
  async function adminToken(target: FastifyInstance) {
    const admin = await user('ia-admin');
    await prisma.user.update({ where: { id: admin.id }, data: { role: 'ADMIN' } });
    const response = await target.inject({
      method: 'POST',
      url: '/api/v1/auth/login',
      payload: { email: `ia-admin${DOMAIN}`, password: PASSWORD },
    });
    return response.json<{ accessToken: string }>().accessToken;
  }

  async function oneAlert() {
    await startCheckpointAt(ago(30 * MIN));
    for (let i = 0; i < 5; i++)
      await event('LOGIN_FAILURE', ago((20 - i) * MIN), {
        ip: `${NET}8.1`,
        emailHash: sha(`ia${i}`),
      });
    await runDetection(prisma, engine());
    const [alert] = await alertsFor('CREDENTIAL_STUFFING');
    if (!alert) throw new Error('alerta não criado');
    return alert;
  }

  const explain = (target: FastifyInstance, id: string, token: string) =>
    target.inject({
      method: 'POST',
      url: `/api/v1/admin/security-alerts/${id}/explanation`,
      headers: { authorization: `Bearer ${token}` },
    });

  it('desabilitada por padrão: responde "disabled" e o alerta continua acessível', async () => {
    const alert = await oneAlert();
    const token = await adminToken(app);

    const response = await explain(app, alert.id, token);

    expect(response.json()).toEqual({ status: 'disabled', advisory: true });
  });

  it('a IA recebe só evidências minimizadas e não altera o alerta', async () => {
    const received: AlertEvidence[] = [];
    const fake: AlertExplainer = {
      explain: (evidence) => {
        received.push(evidence);
        return Promise.resolve({
          status: 'ok',
          model: 'fake',
          explanation: {
            summary: 'Explicação',
            likelyCauses: ['Causa'],
            suggestedChecks: ['Verificação'],
          },
        });
      },
    };
    const withAi = await buildTestApp({}, { alertExplainer: fake });
    extraApps.push(withAi);
    const alert = await oneAlert();
    const token = await adminToken(withAi);

    const response = await explain(withAi, alert.id, token);

    expect(response.json()).toMatchObject({ status: 'ok', advisory: true, model: 'fake' });
    const sent = JSON.stringify(received);
    expect(sent).not.toContain(`${NET}8.1`);
    expect(sent).not.toContain(alert.id);
    expect(sent).not.toMatch(/@|[0-9a-f]{64}/);
    const after = await prisma.securityAlert.findUniqueOrThrow({ where: { id: alert.id } });
    expect(after).toEqual(alert);
  });

  it('IA indisponível: 200 com status "unavailable" (sem erro para o ADMIN)', async () => {
    const down: AlertExplainer = {
      explain: () => Promise.resolve({ status: 'unavailable', reason: 'UNREACHABLE' }),
    };
    const withAi = await buildTestApp({}, { alertExplainer: down });
    extraApps.push(withAi);
    const alert = await oneAlert();
    const token = await adminToken(withAi);

    const response = await explain(withAi, alert.id, token);

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      status: 'unavailable',
      reason: 'UNREACHABLE',
      advisory: true,
    });
  });
});
