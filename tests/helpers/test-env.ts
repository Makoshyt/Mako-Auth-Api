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

/** Env de teste fixo e fictício, independente do .env da máquina. */
export function testEnv(overrides: Record<string, string> = {}): Env {
  return loadEnv({
    NODE_ENV: 'test',
    LOG_LEVEL: 'silent',
    CORS_ORIGINS: 'http://localhost:5173',
    SWAGGER_ENABLED: 'true',
    DATABASE_URL: TEST_DATABASE_URL,
    REDIS_URL: TEST_REDIS_URL,
    JWT_ACCESS_SECRET: TEST_JWT_SECRET,
    ...overrides,
  });
}
