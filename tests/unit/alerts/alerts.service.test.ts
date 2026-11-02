import { describe, expect, it, vi } from 'vitest';
import type { AuditEventInput } from '../../../src/modules/audit/audit.recorder.js';
import type { AlertEvidence } from '../../../src/modules/alerts/alert-explainer.js';
import type { AlertView } from '../../../src/modules/alerts/alerts.repository.js';
import { createAlertsService, toEvidence } from '../../../src/modules/alerts/alerts.service.js';
import {
  createEngineScheduler,
  type RunResult,
} from '../../../src/modules/alerts/detection-engine.js';

const alert: AlertView = {
  id: '0190a000-0000-7000-8000-0000000000a1',
  rule: 'CREDENTIAL_STUFFING',
  severity: 'HIGH',
  status: 'OPEN',
  summary: 'Falhas de login em 5 ou mais contas diferentes a partir do mesmo IP em 1 h',
  details: {
    threshold: 5,
    windowSeconds: 3600,
    peak: 7,
    eventType: 'LOGIN_FAILURE',
    subject: { kind: 'ip', ip: '203.0.113.77' },
    sampleEventIds: ['0190a000-0000-7000-8000-0000000000e1'],
  },
  userId: '0190a000-0000-7000-8000-0000000000b2',
  eventCount: 7,
  firstSeenAt: new Date('2026-11-02T10:00:00.000Z'),
  lastSeenAt: new Date('2026-11-02T10:12:00.000Z'),
  resolvedAt: null,
  createdAt: new Date('2026-11-02T10:13:00.000Z'),
  updatedAt: new Date('2026-11-02T10:13:00.000Z'),
};
const actor = { userId: '0190a000-0000-7000-8000-0000000000ad', ip: '198.51.100.1' };

describe('minimização para a IA', () => {
  it('só natureza e intensidade: sem IP, ids de usuário, ids de eventos ou datas absolutas', () => {
    const evidence = toEvidence(alert);

    expect(evidence).toEqual({
      rule: 'CREDENTIAL_STUFFING',
      severity: 'HIGH',
      status: 'OPEN',
      summary: alert.summary,
      threshold: 5,
      windowSeconds: 3600,
      peak: 7,
      eventCount: 7,
      durationSeconds: 720,
      subjectKind: 'ip',
    });
    const serialized = JSON.stringify(evidence);
    for (const secret of ['203.0.113.77', alert.userId ?? '', '0000000000e1', '2026-11-02']) {
      expect(serialized).not.toContain(secret);
    }
  });
});

describe('AlertsService', () => {
  function build(
    explain = vi.fn((_e: AlertEvidence) => Promise.resolve({ status: 'disabled' as const })),
  ) {
    const events: AuditEventInput[] = [];
    const service = createAlertsService({
      repository: {
        list: () => Promise.resolve({ items: [alert], total: 1 }),
        findById: (id) => Promise.resolve(id === alert.id ? alert : null),
      },
      explainer: { explain },
      audit: { record: (event) => (events.push(event), Promise.resolve()) },
    });
    return { service, events, explain };
  }

  it('cada consulta gera um ADMIN_SECURITY_ALERTS_QUERIED, depois da leitura', async () => {
    const { service, events } = build();

    await service.list(
      { page: 1, pageSize: 20, order: 'desc', rule: 'CREDENTIAL_STUFFING' },
      actor,
    );
    await service.get(alert.id, actor);
    await service.get('0190a000-0000-7000-8000-0000000000ff', actor).catch(() => undefined);
    await service.explain(alert.id, actor);

    expect(events.map((e) => [e.type, e.metadata])).toEqual([
      [
        'ADMIN_SECURITY_ALERTS_QUERIED',
        { action: 'LIST', page: 1, pageSize: 20, rule: 'CREDENTIAL_STUFFING', resultCount: 1 },
      ],
      ['ADMIN_SECURITY_ALERTS_QUERIED', { action: 'VIEW', alertId: alert.id, found: true }],
      [
        'ADMIN_SECURITY_ALERTS_QUERIED',
        { action: 'VIEW', alertId: '0190a000-0000-7000-8000-0000000000ff', found: false },
      ],
      [
        'ADMIN_SECURITY_ALERTS_QUERIED',
        { action: 'EXPLAIN', alertId: alert.id, aiStatus: 'disabled' },
      ],
    ]);
  });

  it('explicação: envia ao explicador só a evidência minimizada', async () => {
    const { service, explain } = build();

    await service.explain(alert.id, actor);

    expect(explain).toHaveBeenCalledWith(toEvidence(alert));
  });

  it('404 para alerta inexistente, sem chamar a IA', async () => {
    const { service, explain } = build();

    await expect(
      service.explain('0190a000-0000-7000-8000-0000000000ff', actor),
    ).rejects.toMatchObject({
      statusCode: 404,
    });
    expect(explain).not.toHaveBeenCalled();
  });
});

describe('agendador do motor', () => {
  const result: RunResult = {
    acquired: true,
    iterations: 1,
    created: 0,
    updated: 0,
    processedUntil: null,
    behind: false,
  };

  it('nunca sobrepõe rodadas e stop espera a rodada atual', async () => {
    let release = (): void => undefined;
    const run = vi.fn(
      () =>
        new Promise<RunResult>((resolve) => {
          release = () => {
            resolve(result);
          };
        }),
    );
    const scheduler = createEngineScheduler(
      run,
      60_000,
      () => undefined,
      () => undefined,
    );

    const first = scheduler.runOnce();
    const second = scheduler.runOnce();
    expect(run).toHaveBeenCalledTimes(1);
    expect(second).toBe(first);

    const stopped = scheduler.stop();
    release();
    await stopped;
    await expect(first).resolves.toEqual(result);
  });

  it('erro na rodada vai para onError e não derruba o processo', async () => {
    const onError = vi.fn();
    const scheduler = createEngineScheduler(
      () => Promise.reject(new Error('banco indisponível')),
      60_000,
      () => undefined,
      onError,
    );

    await expect(scheduler.runOnce()).resolves.toBeNull();
    expect(onError).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'banco indisponível' }),
    );
  });
});
