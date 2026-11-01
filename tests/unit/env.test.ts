import { describe, expect, it } from 'vitest';
import { EnvValidationError, loadEnv } from '../../src/config/env.js';

/** Variáveis obrigatórias (sem padrão), com valores fictícios. */
const required = {
  DATABASE_URL: 'postgresql://user:pass@localhost:5433/db',
  REDIS_URL: 'redis://localhost:6379',
  JWT_ACCESS_SECRET: 'segredo-ficticio-de-teste-com-32-caracteres-ou-mais',
};

function captureError(fn: () => unknown): EnvValidationError {
  try {
    fn();
  } catch (error) {
    if (error instanceof EnvValidationError) return error;
    throw error;
  }
  throw new Error('era esperado EnvValidationError, mas nenhuma exceção foi lançada');
}

describe('loadEnv', () => {
  it('aplica valores padrão seguros para as variáveis opcionais', () => {
    const env = loadEnv(required);

    expect(env).toEqual({
      NODE_ENV: 'development',
      HOST: '127.0.0.1',
      PORT: 3000,
      LOG_LEVEL: 'info',
      CORS_ORIGINS: [],
      SWAGGER_ENABLED: true,
      TRUST_PROXY: false,
      JWT_ACCESS_TTL_SECONDS: 900,
      REFRESH_TOKEN_TTL_DAYS: 7,
      SESSION_ABSOLUTE_TTL_DAYS: 30,
      REFRESH_REUSE_GRACE_SECONDS: 10,
      ...required,
    });
  });

  it('exige DATABASE_URL, REDIS_URL e JWT_ACCESS_SECRET', () => {
    const error = captureError(() => loadEnv({}));
    const fields = error.issues.map((issue) => issue.split(':')[0]);
    expect(fields).toEqual(['DATABASE_URL', 'REDIS_URL', 'JWT_ACCESS_SECRET']);
  });

  it('rejeita JWT_ACCESS_SECRET curto sem expor o valor', () => {
    const weak = 'curto-demais-123';

    const error = captureError(() => loadEnv({ ...required, JWT_ACCESS_SECRET: weak }));
    expect(error.issues).toEqual([expect.stringMatching(/^JWT_ACCESS_SECRET: /)]);
    expect(error.message).not.toContain(weak);
  });

  it('rejeita refresh token com validade maior que a da sessão', () => {
    const error = captureError(() =>
      loadEnv({ ...required, REFRESH_TOKEN_TTL_DAYS: '40', SESSION_ABSOLUTE_TTL_DAYS: '30' }),
    );
    expect(error.issues).toEqual([expect.stringMatching(/^REFRESH_TOKEN_TTL_DAYS: /)]);
  });

  it('rejeita URLs com protocolo errado', () => {
    const error = captureError(() =>
      loadEnv({
        ...required,
        DATABASE_URL: 'mysql://localhost/db',
        REDIS_URL: 'http://localhost:6379',
      }),
    );
    const fields = error.issues.map((issue) => issue.split(':')[0]);
    expect(fields).toEqual(['DATABASE_URL', 'REDIS_URL']);
  });

  it('converte tipos: porta numérica, booleanos e lista de origens', () => {
    const env = loadEnv({
      ...required,
      PORT: '8080',
      SWAGGER_ENABLED: 'false',
      TRUST_PROXY: 'true',
      CORS_ORIGINS: ' http://a.example.com , http://b.example.com ,',
    });

    expect(env.PORT).toBe(8080);
    expect(env.SWAGGER_ENABLED).toBe(false);
    expect(env.TRUST_PROXY).toBe(true);
    expect(env.CORS_ORIGINS).toEqual(['http://a.example.com', 'http://b.example.com']);
  });

  it('rejeita valores inválidos listando todas as variáveis com problema', () => {
    const error = captureError(() => loadEnv({ ...required, PORT: '99999', LOG_LEVEL: 'verbose' }));
    const fields = error.issues.map((issue) => issue.split(':')[0]);
    expect(fields).toEqual(['PORT', 'LOG_LEVEL']);
  });

  it('não inclui o valor recebido na mensagem de erro (evita vazar segredos)', () => {
    const secretLikeValue = 'super-secret-value-123';

    const error = captureError(() => loadEnv({ ...required, PORT: secretLikeValue }));
    expect(error.message).toContain('PORT');
    expect(error.message).not.toContain(secretLikeValue);
  });

  it('não vaza a senha de uma DATABASE_URL inválida', () => {
    const error = captureError(() =>
      loadEnv({ ...required, DATABASE_URL: 'ftp://user:SenhaFicticia99@host/db' }),
    );
    expect(error.message).not.toContain('SenhaFicticia99');
  });

  it('proíbe CORS curinga em produção, mas permite em desenvolvimento', () => {
    expect(() => loadEnv({ ...required, NODE_ENV: 'production', CORS_ORIGINS: '*' })).toThrow(
      /CORS_ORIGINS/,
    );
    expect(
      loadEnv({ ...required, NODE_ENV: 'development', CORS_ORIGINS: '*' }).CORS_ORIGINS,
    ).toEqual(['*']);
  });
});
