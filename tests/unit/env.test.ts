import { describe, expect, it } from 'vitest';
import { EnvValidationError, loadEnv } from '../../src/config/env.js';

/** Variáveis obrigatórias (sem padrão), com valores fictícios. */
const required = {
  DATABASE_URL: 'postgresql://user:pass@localhost:5433/db',
  REDIS_URL: 'redis://localhost:6379',
  JWT_ACCESS_SECRET: 'segredo-ficticio-de-teste-com-32-caracteres-ou-mais',
  RATE_LIMIT_HMAC_SECRET: 'outro-segredo-ficticio-para-o-hmac-de-rate-limit',
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
      RATE_LIMIT_KEY_PREFIX: 'authapi:rl',
      // Defaults da Etapa 6 (janelas em ms).
      RATE_LIMIT_LOGIN_IP: { max: 5, windowMs: 15 * 60_000 },
      RATE_LIMIT_LOGIN_ACCOUNT: { max: 10, windowMs: 60 * 60_000 },
      RATE_LIMIT_REGISTER_IP: { max: 5, windowMs: 60 * 60_000 },
      RATE_LIMIT_REFRESH_IP: { max: 20, windowMs: 15 * 60_000 },
      RATE_LIMIT_LOGOUT_USER: { max: 20, windowMs: 15 * 60_000 },
      RATE_LIMIT_LOGOUT_ALL_USER: { max: 5, windowMs: 15 * 60_000 },
      RATE_LIMIT_UPDATE_PROFILE_USER: { max: 10, windowMs: 15 * 60_000 },
      RATE_LIMIT_ADMIN_USERS: { max: 60, windowMs: 60_000 },
      RATE_LIMIT_ADMIN_USER_BY_ID: { max: 60, windowMs: 60_000 },
      RATE_LIMIT_ADMIN_AUDIT_EVENTS: { max: 30, windowMs: 60_000 },
      // Defaults da Etapa 7.
      RATE_LIMIT_FORGOT_PASSWORD_IP: { max: 5, windowMs: 60 * 60_000 },
      RATE_LIMIT_FORGOT_PASSWORD_ACCOUNT: { max: 3, windowMs: 60 * 60_000 },
      RATE_LIMIT_RESET_PASSWORD_IP: { max: 10, windowMs: 15 * 60_000 },
      PASSWORD_RESET_TOKEN_TTL_MINUTES: 15,
      PASSWORD_RESET_URL: 'http://localhost:5173/reset-password',
      MAIL_PROVIDER: 'log',
      MAIL_FROM: 'AuthAPI Pro <no-reply@authapi.localhost>',
      DEV_MAILBOX_DIR: '.dev-mailbox',
      ...required,
    });
  });

  it('exige DATABASE_URL, REDIS_URL, JWT_ACCESS_SECRET e RATE_LIMIT_HMAC_SECRET', () => {
    const error = captureError(() => loadEnv({}));
    const fields = error.issues.map((issue) => issue.split(':')[0]);
    expect(fields).toEqual([
      'DATABASE_URL',
      'REDIS_URL',
      'JWT_ACCESS_SECRET',
      'RATE_LIMIT_HMAC_SECRET',
    ]);
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
      TRUST_PROXY: '1',
      CORS_ORIGINS: ' http://a.example.com , http://b.example.com ,',
    });

    expect(env.PORT).toBe(8080);
    expect(env.SWAGGER_ENABLED).toBe(false);
    expect(env.TRUST_PROXY).toBe(1);
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

  describe('TRUST_PROXY', () => {
    it.each([
      ['false', false],
      ['', false],
      ['1', 1],
      ['2', 2],
      ['10.0.0.1', ['10.0.0.1']],
      ['10.0.0.0/8, 172.16.0.0/12 ,::1/128', ['10.0.0.0/8', '172.16.0.0/12', '::1/128']],
    ])('aceita "%s"', (value, expected) => {
      expect(loadEnv({ ...required, TRUST_PROXY: value }).TRUST_PROXY).toEqual(expected);
    });

    it.each([
      'true',
      'TRUE',
      '0',
      '11',
      '10.0.0.0/33',
      '999.1.1.1',
      'proxy.local',
      '10.0.0.1,lixo',
    ])('recusa "%s" (true confiaria em X-Forwarded-For forjado pelo cliente)', (value) => {
      const error = captureError(() => loadEnv({ ...required, TRUST_PROXY: value }));
      expect(error.issues).toEqual([expect.stringMatching(/^TRUST_PROXY: /)]);
    });
  });

  describe('rate limiting', () => {
    it('converte "<máximo>/<janela>" para máximo e janela em ms', () => {
      const env = loadEnv({
        ...required,
        RATE_LIMIT_LOGIN_IP: '3/30s',
        RATE_LIMIT_REGISTER_IP: '2/2h',
        RATE_LIMIT_ADMIN_USERS: '100/1m',
      });

      expect(env.RATE_LIMIT_LOGIN_IP).toEqual({ max: 3, windowMs: 30_000 });
      expect(env.RATE_LIMIT_REGISTER_IP).toEqual({ max: 2, windowMs: 7_200_000 });
      expect(env.RATE_LIMIT_ADMIN_USERS).toEqual({ max: 100, windowMs: 60_000 });
    });

    it.each([
      '5',
      '5/',
      '/15m',
      '0/15m',
      '5/0s',
      '5/15d',
      '5/25h',
      'cinco/15m',
      '-1/15m',
      '200000/1m',
    ])('recusa política inválida: "%s"', (value) => {
      const error = captureError(() => loadEnv({ ...required, RATE_LIMIT_LOGIN_IP: value }));
      expect(error.issues).toEqual([expect.stringMatching(/^RATE_LIMIT_LOGIN_IP: /)]);
    });

    it('recusa RATE_LIMIT_HMAC_SECRET curto, sem expor o valor', () => {
      const weak = 'hmac-curto';

      const error = captureError(() => loadEnv({ ...required, RATE_LIMIT_HMAC_SECRET: weak }));
      expect(error.issues).toEqual([expect.stringMatching(/^RATE_LIMIT_HMAC_SECRET: /)]);
      expect(error.message).not.toContain(weak);
    });

    it('recusa RATE_LIMIT_HMAC_SECRET igual ao JWT_ACCESS_SECRET', () => {
      const error = captureError(() =>
        loadEnv({ ...required, RATE_LIMIT_HMAC_SECRET: required.JWT_ACCESS_SECRET }),
      );
      expect(error.issues).toEqual([expect.stringMatching(/^RATE_LIMIT_HMAC_SECRET: .*diferente/)]);
    });

    it.each(['com espaço', 'a'.repeat(65), ':comeca-com-dois-pontos', 'rl*'])(
      'recusa RATE_LIMIT_KEY_PREFIX inválido: "%s"',
      (value) => {
        expect(() => loadEnv({ ...required, RATE_LIMIT_KEY_PREFIX: value })).toThrow(
          /RATE_LIMIT_KEY_PREFIX/,
        );
      },
    );
  });

  describe('recuperação de senha e email', () => {
    it('em produção, recusa dev-mailbox (grava tokens em disco)', () => {
      const error = captureError(() =>
        loadEnv({
          ...required,
          NODE_ENV: 'production',
          MAIL_PROVIDER: 'dev-mailbox',
          PASSWORD_RESET_URL: 'https://app.example.com/reset',
        }),
      );
      expect(error.issues).toEqual([expect.stringMatching(/^MAIL_PROVIDER: /)]);
    });

    it('em produção, exige https no link de recuperação', () => {
      const error = captureError(() =>
        loadEnv({
          ...required,
          NODE_ENV: 'production',
          PASSWORD_RESET_URL: 'http://app.example.com/r',
        }),
      );
      expect(error.issues).toEqual([expect.stringMatching(/^PASSWORD_RESET_URL: .*https/)]);
    });

    it('em desenvolvimento, aceita dev-mailbox e http local', () => {
      const env = loadEnv({ ...required, MAIL_PROVIDER: 'dev-mailbox' });
      expect(env.MAIL_PROVIDER).toBe('dev-mailbox');
    });

    it.each(['4', '61', 'abc'])('recusa PASSWORD_RESET_TOKEN_TTL_MINUTES=%s (5 a 60)', (value) => {
      expect(() => loadEnv({ ...required, PASSWORD_RESET_TOKEN_TTL_MINUTES: value })).toThrow(
        /PASSWORD_RESET_TOKEN_TTL_MINUTES/,
      );
    });

    it.each(['smtp', 'ses', 'memory'])('recusa MAIL_PROVIDER desconhecido: %s', (value) => {
      expect(() => loadEnv({ ...required, MAIL_PROVIDER: value })).toThrow(/MAIL_PROVIDER/);
    });
  });
});
