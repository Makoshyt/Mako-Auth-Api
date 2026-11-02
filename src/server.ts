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

  // Encerramento gracioso: para de aceitar conexões (novas requisições recebem 503), espera as
  // em andamento, os emails pendentes e a rodada atual do motor de alertas. Se algo travar,
  // o prazo garante a saída (com código 1, para o orquestrador registrar a falha).
  const SHUTDOWN_TIMEOUT_MS = 15_000;
  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    app.log.info({ signal }, 'encerrando servidor');
    setTimeout(() => {
      app.log.error(
        { timeoutMs: SHUTDOWN_TIMEOUT_MS },
        'encerramento excedeu o prazo; forçando saída',
      );
      process.exit(1);
    }, SHUTDOWN_TIMEOUT_MS).unref();
    try {
      await app.close();
    } catch (error) {
      app.log.error({ err: error }, 'falha ao encerrar o servidor');
    }
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
