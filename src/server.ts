import { existsSync } from 'node:fs';
import { buildApp } from './app.js';
import { EnvValidationError, loadEnv } from './config/env.js';
import { createPrismaClient } from './infra/prisma.js';
import { createRedisClient } from './infra/redis.js';

// Carrega .env com o recurso nativo do Node (sem dependência extra). Variáveis já
// definidas no ambiente têm precedência, como em CI e containers.
if (existsSync('.env')) process.loadEnvFile('.env');

async function main(): Promise<void> {
  const env = loadEnv();
  const prisma = createPrismaClient(env.DATABASE_URL);
  const redis = createRedisClient(env.REDIS_URL);
  const app = await buildApp({ env, prisma, redis });

  // Sem Redis o processo continua de pé: /ready responde 503 até a conexão voltar.
  redis.on('error', (error) => {
    app.log.warn({ err: error }, 'redis indisponível');
  });

  const shutdown = async (signal: string) => {
    app.log.info({ signal }, 'encerrando servidor');
    await app.close();
    await Promise.allSettled([prisma.$disconnect(), redis.quit()]);
    process.exit(0);
  };
  process.once('SIGINT', () => void shutdown('SIGINT'));
  process.once('SIGTERM', () => void shutdown('SIGTERM'));

  await app.listen({ host: env.HOST, port: env.PORT });
  if (env.SWAGGER_ENABLED) app.log.info(`Swagger em http://${env.HOST}:${env.PORT}/docs`);
}

main().catch((error: unknown) => {
  // O logger ainda pode não existir aqui (ex.: env inválido), então usamos stderr.
  process.stderr.write(`${error instanceof EnvValidationError ? error.message : String(error)}\n`);
  process.exit(1);
});
