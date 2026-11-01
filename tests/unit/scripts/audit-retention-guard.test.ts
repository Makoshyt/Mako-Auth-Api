import { describe, expect, it } from 'vitest';
import {
  checkRetentionRun,
  type RetentionRunInput,
} from '../../../scripts/audit-retention-guard.js';

const DEV_DB = 'postgresql://authapi:senha-ficticia@127.0.0.1:5433/authapi';
const TEST_DB = 'postgresql://authapi:senha-ficticia@127.0.0.1:5433/authapi_test';
const PROD_DB = 'postgresql://app:senha-ficticia@db.interno.example.com:5432/authapi';

const base: RetentionRunInput = {
  nodeEnv: 'development',
  databaseUrl: DEV_DB,
  enabled: false,
  execute: false,
  confirm: undefined,
};
const errorsOf = (input: Partial<RetentionRunInput>) => {
  const result = checkRetentionRun({ ...base, ...input });
  return result.ok ? [] : result.errors;
};

describe('checkRetentionRun (npm run audit:retention)', () => {
  it.each([DEV_DB, TEST_DB, PROD_DB])(
    'simulação é sempre permitida (somente leitura): %s',
    (databaseUrl) => {
      expect(checkRetentionRun({ ...base, databaseUrl })).toMatchObject({
        ok: true,
        mode: 'dry-run',
      });
    },
  );

  it('banco de DESENVOLVIMENTO: exclusão recusada mesmo com tudo habilitado e confirmado', () => {
    expect(errorsOf({ execute: true, enabled: true, confirm: 'authapi' })).toEqual([
      expect.stringMatching(/só roda em bancos \*_test/),
    ]);
  });

  it('banco de testes: exclusão permitida com habilitação e confirmação', () => {
    expect(
      checkRetentionRun({
        ...base,
        databaseUrl: TEST_DB,
        execute: true,
        enabled: true,
        confirm: 'authapi_test',
      }),
    ).toEqual({ ok: true, mode: 'execute', database: { host: '127.0.0.1', name: 'authapi_test' } });
  });

  it('produção: exclusão permitida só com AUDIT_RETENTION_ENABLED e confirmação do nome do banco', () => {
    const prod = { nodeEnv: 'production', databaseUrl: PROD_DB, execute: true };

    expect(errorsOf({ ...prod, enabled: true, confirm: 'authapi' })).toEqual([]);
    expect(errorsOf({ ...prod, enabled: false, confirm: 'authapi' })).toEqual([
      expect.stringMatching(/AUDIT_RETENTION_ENABLED=true/),
    ]);
    expect(errorsOf({ ...prod, enabled: true })).toEqual([
      expect.stringMatching(/--confirm authapi/),
    ]);
    expect(errorsOf({ ...prod, enabled: true, confirm: 'outro_banco' })).toEqual([
      expect.stringMatching(/Confirmação/),
    ]);
  });

  it('DATABASE_URL inválida: recusa', () => {
    expect(errorsOf({ databaseUrl: 'mysql://x/y' })).toEqual(['DATABASE_URL ausente ou inválida.']);
    expect(errorsOf({ databaseUrl: undefined })).toHaveLength(1);
  });

  it('não vaza a senha da DATABASE_URL nas mensagens', () => {
    const errors = errorsOf({ execute: true, enabled: true, confirm: 'x' });

    expect(errors.join(' ')).not.toContain('senha-ficticia');
  });
});
