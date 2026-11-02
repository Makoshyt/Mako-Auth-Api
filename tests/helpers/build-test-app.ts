import type { FastifyInstance } from 'fastify';
import type { DestinationStream } from 'pino';
import { buildApp } from '../../src/app.js';
import { createPrismaClient } from '../../src/infra/prisma.js';
import { createRedisClient, type Redis } from '../../src/infra/redis.js';
import type { AlertExplainer } from '../../src/modules/alerts/alert-explainer.js';
import type { Mailer } from '../../src/modules/mail/mailer.js';
import { TEST_RATE_LIMIT_ROOT, testEnv, type TestEnvOptions } from './test-env.js';

/**
 * Apaga só as chaves do namespace do teste, com SCAN (não bloqueia o Redis) e nunca
 * FLUSHALL/FLUSHDB. Recusa qualquer prefixo fora de TEST_RATE_LIMIT_ROOT.
 */
export async function deleteTestKeys(redis: Redis, prefix: string): Promise<void> {
  if (!prefix.startsWith(`${TEST_RATE_LIMIT_ROOT}:`)) {
    throw new Error(`limpeza recusada: "${prefix}" está fora do namespace de testes`);
  }
  let cursor = '0';
  do {
    const [next, keys] = await redis.scan(cursor, 'MATCH', `${prefix}:*`, 'COUNT', 200);
    if (keys.length > 0) await redis.del(...keys);
    cursor = next;
  } while (cursor !== '0');
}

export interface BuildTestAppOptions extends TestEnvOptions {
  /**
   * Conecta o Redis antes de montar o app (padrão). O rate limit precisa dele em toda rota
   * limitada. Use false só para simular o Redis fora do ar.
   */
  connectRedis?: boolean;
  logDestination?: DestinationStream;
  /** Provedor de email injetado (ex.: MemoryMailer para ler o token de recuperação). */
  mailer?: Mailer;
  /** Explicador de alertas injetado (ex.: falso, para testar a IA sem Ollama). */
  alertExplainer?: AlertExplainer;
}

/**
 * Monta o app com clientes reais, encerrados junto com app.close().
 * O Prisma só conecta na primeira query. Ao fechar, as chaves de rate limit deste app são
 * apagadas (somente o namespace dele).
 */
export async function buildTestApp(
  overrides: Record<string, string> = {},
  {
    connectRedis = true,
    logDestination,
    rateLimits,
    mailer,
    alertExplainer,
  }: BuildTestAppOptions = {},
): Promise<FastifyInstance> {
  const env = testEnv(overrides, { rateLimits });
  const prisma = createPrismaClient(env.DATABASE_URL);
  const redis = createRedisClient(env.REDIS_URL, { lazyConnect: true });
  redis.on('error', () => {
    // Erros de conexão são esperados nos testes de indisponibilidade; o /ready os reporta.
  });
  if (connectRedis) await redis.connect();

  const app = await buildApp({
    env,
    prisma,
    redis,
    logDestination,
    ...(mailer && { mailer }),
    ...(alertExplainer && { alertExplainer }),
  });
  app.addHook('onClose', async () => {
    if (redis.status === 'ready') await deleteTestKeys(redis, env.RATE_LIMIT_KEY_PREFIX);
    redis.disconnect();
    await prisma.$disconnect();
  });
  return app;
}
