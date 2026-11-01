import { randomUUID } from 'node:crypto';
import { loadEnv, type Env } from '../../src/config/env.js';

/**
 * Infra de testes: banco authapi_test (nunca o de desenvolvimento) e Redis local.
 * Em CI, DATABASE_URL_TEST e REDIS_URL vêm do ambiente.
 */
export const TEST_DATABASE_URL =
  process.env.DATABASE_URL_TEST ??
  'postgresql://authapi:authapi_dev_password@127.0.0.1:5433/authapi_test';
export const TEST_REDIS_URL = process.env.REDIS_URL ?? 'redis://127.0.0.1:6379';
/** Segredo FICTÍCIO, só para testes. Exportado para os testes forjarem tokens. */
export const TEST_JWT_SECRET = 'segredo-de-teste-ficticio-com-mais-de-32-caracteres';
/** Segredo FICTÍCIO do HMAC das chaves de rate limit (diferente do JWT, como em produção). */
export const TEST_RATE_LIMIT_SECRET = 'hmac-de-teste-ficticio-para-rate-limit-32+';
/** Raiz de todas as chaves Redis criadas por testes: a limpeza nunca sai deste namespace. */
export const TEST_RATE_LIMIT_ROOT = 'authapi-test:rl';

/**
 * Limites altos para as suítes que NÃO testam rate limit (auth, users, admin...). Elas fazem
 * dezenas de logins do mesmo IP e verificam autenticação, RBAC e auditoria, não limites.
 * Os limites reais (defaults de produção) são exercitados em rate-limit.test.ts.
 */
export const RELAXED_RATE_LIMITS: Record<string, string> = Object.fromEntries(
  [
    'LOGIN_IP',
    'LOGIN_ACCOUNT',
    'REGISTER_IP',
    'REFRESH_IP',
    'LOGOUT_USER',
    'LOGOUT_ALL_USER',
    'UPDATE_PROFILE_USER',
    'ADMIN_USERS',
    'ADMIN_USER_BY_ID',
    'ADMIN_AUDIT_EVENTS',
  ].map((name) => [`RATE_LIMIT_${name}`, '100000/1h']),
);

export interface TestEnvOptions {
  /** "default": usa os limites de produção (sem relaxar). */
  rateLimits?: 'relaxed' | 'default';
}

/**
 * Env de teste fixo e fictício, independente do .env da máquina. Cada chamada ganha um
 * namespace Redis aleatório, então contadores de testes diferentes nunca se misturam.
 */
export function testEnv(
  overrides: Record<string, string> = {},
  { rateLimits = 'relaxed' }: TestEnvOptions = {},
): Env {
  return loadEnv({
    NODE_ENV: 'test',
    LOG_LEVEL: 'silent',
    CORS_ORIGINS: 'http://localhost:5173',
    SWAGGER_ENABLED: 'true',
    DATABASE_URL: TEST_DATABASE_URL,
    REDIS_URL: TEST_REDIS_URL,
    JWT_ACCESS_SECRET: TEST_JWT_SECRET,
    RATE_LIMIT_HMAC_SECRET: TEST_RATE_LIMIT_SECRET,
    RATE_LIMIT_KEY_PREFIX: `${TEST_RATE_LIMIT_ROOT}:${randomUUID()}`,
    ...(rateLimits === 'relaxed' && RELAXED_RATE_LIMITS),
    ...overrides,
  });
}
