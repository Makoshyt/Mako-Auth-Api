import { describe, expect, it } from 'vitest';
import {
  buildDetectionRules,
  fingerprintFor,
  subjectKeyFor,
  severityFor,
  summaryFor,
} from '../../../src/modules/alerts/alert-rules.js';
import { testEnv } from '../../helpers/test-env.js';

const rules = buildDetectionRules(testEnv());
const byRule = (name: string) => {
  const rule = rules.find((r) => r.rule === name);
  if (!rule) throw new Error(`regra ${name} ausente`);
  return rule;
};

describe('regras de detecção', () => {
  it('seis regras, cada uma lendo um único tipo de evento que a aplicação registra', () => {
    expect(
      rules.map((r) => [r.rule, r.eventType, r.groupBy, r.metric, r.threshold, r.windowMs]),
    ).toEqual([
      ['BRUTE_FORCE_ACCOUNT', 'LOGIN_FAILURE', 'email_hash', 'count', 8, 3_600_000],
      ['CREDENTIAL_STUFFING', 'LOGIN_FAILURE', 'ip', 'distinct_email', 5, 3_600_000],
      ['TOKEN_REUSE', 'TOKEN_REUSE_DETECTED', 'user_id', 'count', 1, 86_400_000],
      ['RATE_LIMIT_ABUSE', 'RATE_LIMIT_EXCEEDED', 'ip', 'count', 3, 3_600_000],
      ['ADMIN_ACCESS_PROBING', 'ACCESS_DENIED', 'user_id', 'count', 5, 3_600_000],
      ['PASSWORD_RESET_ABUSE', 'PASSWORD_RESET_REQUEST', 'ip', 'count', 5, 3_600_000],
    ]);
  });

  it('nenhuma regra lê eventos administrativos (o motor nunca alerta sobre consultas a alertas)', () => {
    for (const rule of rules) expect(rule.eventType.startsWith('ADMIN_')).toBe(false);
  });

  it('limites e janelas vêm da configuração', () => {
    const custom = buildDetectionRules(testEnv({ ALERT_BRUTE_FORCE_ACCOUNT: '20/30m' }));

    expect(custom[0]).toMatchObject({ threshold: 20, windowMs: 1_800_000 });
    expect(summaryFor(custom[0] ?? byRule('BRUTE_FORCE_ACCOUNT'))).toBe(
      '20 ou mais falhas de login para a mesma conta em 30 min',
    );
  });
});

describe('severidade', () => {
  it.each([
    ['BRUTE_FORCE_ACCOUNT', 8, 'MEDIUM'],
    ['BRUTE_FORCE_ACCOUNT', 15, 'MEDIUM'],
    ['BRUTE_FORCE_ACCOUNT', 16, 'HIGH'],
    ['CREDENTIAL_STUFFING', 5, 'HIGH'],
    ['TOKEN_REUSE', 1, 'HIGH'],
    ['RATE_LIMIT_ABUSE', 3, 'LOW'],
    ['RATE_LIMIT_ABUSE', 6, 'MEDIUM'],
    ['ADMIN_ACCESS_PROBING', 5, 'MEDIUM'],
    ['ADMIN_ACCESS_PROBING', 10, 'HIGH'],
    ['PASSWORD_RESET_ABUSE', 5, 'LOW'],
    ['PASSWORD_RESET_ABUSE', 10, 'MEDIUM'],
  ])('%s com pico %i → %s (sobe ao atingir o dobro do limite)', (name, peak, severity) => {
    expect(severityFor(byRule(name), peak)).toBe(severity);
  });
});

describe('fingerprint (deduplicação)', () => {
  const day = 86_400_000;
  const at = new Date('2026-11-02T10:00:00.000Z');

  it('não contém o alvo em texto (nem IP, nem hash de email) e cabe na coluna', () => {
    const fp = fingerprintFor('CREDENTIAL_STUFFING', '203.0.113.77', at, day);

    expect(fp).not.toContain('203.0.113.77');
    expect(fp).toMatch(/^CREDENTIAL_STUFFING:[0-9a-f]{32}:\d+$/);
    expect(fp.length).toBeLessThanOrEqual(128);
  });

  it('mesmo alvo e regra no mesmo período: mesmo fingerprint', () => {
    expect(fingerprintFor('RATE_LIMIT_ABUSE', 'x', at, day)).toBe(
      fingerprintFor('RATE_LIMIT_ABUSE', 'x', new Date('2026-11-02T23:59:59.000Z'), day),
    );
  });

  it('outro período, outro alvo ou outra regra: fingerprint diferente', () => {
    const base = fingerprintFor('RATE_LIMIT_ABUSE', 'x', at, day);

    expect(fingerprintFor('RATE_LIMIT_ABUSE', 'x', new Date(at.getTime() + day), day)).not.toBe(
      base,
    );
    expect(fingerprintFor('RATE_LIMIT_ABUSE', 'y', at, day)).not.toBe(base);
    expect(fingerprintFor('PASSWORD_RESET_ABUSE', 'x', at, day)).not.toBe(base);
  });
  it('a chave do alvo é o prefixo comum aos fingerprints de todos os períodos (continuação)', () => {
    const key = subjectKeyFor('RATE_LIMIT_ABUSE', '203.0.113.77');

    expect(key).toMatch(/^RATE_LIMIT_ABUSE:[0-9a-f]{32}$/);
    expect(key).not.toContain('203.0.113.77');
    for (const when of [at, new Date(at.getTime() + day), new Date(at.getTime() + 30 * day)]) {
      expect(
        fingerprintFor('RATE_LIMIT_ABUSE', '203.0.113.77', when, day).startsWith(`${key}:`),
      ).toBe(true);
    }
    expect(subjectKeyFor('PASSWORD_RESET_ABUSE', '203.0.113.77')).not.toBe(key);
  });
});
