import { describe, expect, it } from 'vitest';
import { checkPromotion } from '../../../scripts/admin-provisioning.js';

const valid = {
  nodeEnv: 'development',
  databaseUrl: 'postgresql://authapi:senha-ficticia@127.0.0.1:5433/authapi',
  email: 'ada.admin@example.com',
  confirm: 'ada.admin@example.com',
};

const errorsOf = (input: Partial<typeof valid>) => {
  const result = checkPromotion({ ...valid, ...input });
  return result.ok ? [] : result.errors;
};

describe('checkPromotion (npm run admin:promote)', () => {
  it('aceita usuário fictício, banco local e confirmação idêntica', () => {
    expect(checkPromotion(valid)).toEqual({
      ok: true,
      email: 'ada.admin@example.com',
      database: { host: '127.0.0.1', name: 'authapi' },
    });
  });

  it('NODE_ENV=production: bloqueado, mesmo com todo o resto válido', () => {
    expect(errorsOf({ nodeEnv: 'production' })).toEqual([
      expect.stringMatching(/NODE_ENV=production/),
    ]);
  });

  it.each(['staging', 'prod', 'qa'])('NODE_ENV=%s: bloqueado (só development ou test)', (env) => {
    expect(errorsOf({ nodeEnv: env })).toEqual([expect.stringMatching(/Bloqueado: NODE_ENV/)]);
  });

  it.each([
    'postgresql://u:p@db.empresa.com:5432/authapi',
    'postgresql://u:p@10.0.0.5:5432/authapi',
  ])('banco não local: bloqueado (%s)', (databaseUrl) => {
    expect(errorsOf({ databaseUrl })).toEqual([expect.stringMatching(/não é local/)]);
  });

  it('não vaza a senha da DATABASE_URL nas mensagens', () => {
    const errors = errorsOf({ databaseUrl: 'postgresql://u:SenhaSecreta99@db.remoto.com/x' });

    expect(errors.join(' ')).not.toContain('SenhaSecreta99');
  });

  it.each(['maria@gmail.com', 'admin@empresa.com.br', 'x@example.com.br', 'x@notexample.com'])(
    'email fora dos domínios fictícios: bloqueado (%s)',
    (email) => {
      expect(errorsOf({ email, confirm: email })).toEqual([
        expect.stringMatching(/domínios fictícios/),
      ]);
    },
  );

  it.each(['dev@sub.example.org', 'qa@empresa.test', 'a@b.example', 'z@x.invalid'])(
    'aceita domínio reservado: %s',
    (email) => {
      expect(errorsOf({ email, confirm: email })).toEqual([]);
    },
  );

  it.each([
    ['ausente', undefined],
    ['diferente', 'bruno.user@example.com'],
    ['"yes"', 'yes'],
  ])('exige confirmação explícita: %s', (_label, confirm) => {
    expect(errorsOf({ confirm })).toEqual([expect.stringMatching(/Confirmação/)]);
  });

  it('sem email nem banco: lista todos os problemas', () => {
    expect(errorsOf({ email: undefined, confirm: undefined, databaseUrl: undefined })).toHaveLength(
      2,
    );
  });
});
