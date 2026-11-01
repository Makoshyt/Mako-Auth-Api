import type { FastifyInstance } from 'fastify';
import type { DestinationStream } from 'pino';
import { buildApp } from '../../src/app.js';
import { createPrismaClient } from '../../src/infra/prisma.js';
import { createRedisClient } from '../../src/infra/redis.js';
import { testEnv } from './test-env.js';

/**
 * Monta o app com clientes reais, encerrados junto com app.close().
 * O Prisma só conecta na primeira query e o Redis só conecta se `connectRedis` for true,
 * então testes que não tocam em infraestrutura não abrem conexões.
 */
export async function buildTestApp(
  overrides: Record<string, string> = {},
  {
    connectRedis = false,
    logDestination,
  }: { connectRedis?: boolean; logDestination?: DestinationStream } = {},
): Promise<FastifyInstance> {
  const env = testEnv(overrides);
  const prisma = createPrismaClient(env.DATABASE_URL);
  const redis = createRedisClient(env.REDIS_URL, { lazyConnect: true });
  redis.on('error', () => {
    // Erros de conexão são esperados nos testes de indisponibilidade; o /ready os reporta.
  });
  if (connectRedis) await redis.connect();

  const app = await buildApp({ env, prisma, redis, logDestination });
  app.addHook('onClose', async () => {
    redis.disconnect();
    await prisma.$disconnect();
  });
  return app;
}
