import { describe, expect, it } from 'vitest';
import {
  EXTENDED_RETENTION_TYPES,
  expiredWhere,
  retentionConfigSchema,
} from '../../../src/modules/audit/audit-retention.js';

describe('configuração de retenção', () => {
  it('padrões seguros: desligada, 180/365 dias, lotes de 1000, até 100 lotes', () => {
    expect(retentionConfigSchema.parse({})).toEqual({
      AUDIT_RETENTION_ENABLED: false,
      AUDIT_RETENTION_DAYS: 180,
      AUDIT_RETENTION_EXTENDED_DAYS: 365,
      AUDIT_RETENTION_BATCH_SIZE: 1000,
      AUDIT_RETENTION_MAX_BATCHES: 100,
    });
  });

  it.each([
    ['retenção curta demais', { AUDIT_RETENTION_DAYS: '7' }],
    ['lote gigante', { AUDIT_RETENTION_BATCH_SIZE: '50000' }],
    ['lote zero', { AUDIT_RETENTION_BATCH_SIZE: '0' }],
    [
      'estendida menor que a padrão',
      { AUDIT_RETENTION_DAYS: '400', AUDIT_RETENTION_EXTENDED_DAYS: '365' },
    ],
    ['habilitação ambígua', { AUDIT_RETENTION_ENABLED: 'talvez' }],
  ])('recusa %s', (_label, env) => {
    expect(retentionConfigSchema.safeParse(env).success).toBe(false);
  });
});

describe('critério de vencimento', () => {
  it('tipos comuns vencem no corte padrão; sinais de ataque e responsabilização, no estendido', () => {
    const config = retentionConfigSchema.parse({});
    const now = new Date('2026-11-01T00:00:00.000Z');

    expect(expiredWhere(config, now)).toEqual({
      OR: [
        {
          type: { notIn: [...EXTENDED_RETENTION_TYPES] },
          createdAt: { lt: new Date('2026-05-05T00:00:00.000Z') },
        },
        {
          type: { in: [...EXTENDED_RETENTION_TYPES] },
          createdAt: { lt: new Date('2025-11-01T00:00:00.000Z') },
        },
      ],
    });
    expect(EXTENDED_RETENTION_TYPES).toEqual(
      expect.arrayContaining(['TOKEN_REUSE_DETECTED', 'ACCESS_DENIED', 'ADMIN_AUDIT_QUERIED']),
    );
    expect(EXTENDED_RETENTION_TYPES).not.toContain('LOGIN_SUCCESS');
  });
});
