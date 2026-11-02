/**
 * Uma rodada do motor de alertas, fora da API (cron, manutenção, recuperação manual).
 *
 *   npm run alerts:process
 *
 * Usa o mesmo checkpoint e a mesma trava (advisory lock) da execução periódica dentro da API:
 * rodar junto com a API é seguro, e só um dos dois processa cada intervalo.
 * Não apaga nada e não age sobre usuários: só cria/atualiza alertas a partir da auditoria.
 *
 * Códigos de saída: 0 = ok · 1 = erro · 2 = outra instância processando · 3 = ainda atrasado.
 */
import { existsSync } from 'node:fs';
import { EnvValidationError, loadEnv } from '../src/config/env.js';
import { createPrismaClient } from '../src/infra/prisma.js';
import { engineConfigFromEnv, runDetection } from '../src/modules/alerts/detection-engine.js';

if (existsSync('.env')) process.loadEnvFile('.env');

let env;
try {
  env = loadEnv();
} catch (error) {
  console.error(error instanceof EnvValidationError ? error.message : String(error));
  process.exit(1);
}

const prisma = createPrismaClient(env.DATABASE_URL);
try {
  const result = await runDetection(prisma, engineConfigFromEnv(env));
  if (!result.acquired) {
    console.log('Outra instância está processando agora. Nada foi feito.');
    process.exitCode = 2;
  } else {
    console.log(
      `Intervalos: ${result.iterations} · alertas criados: ${result.created} · atualizados: ${result.updated} · ` +
        `avaliado até: ${result.processedUntil?.toISOString() ?? '—'} · ` +
        `atrasados reavaliados: ${result.lateEvents}`,
    );
    if (result.skippedLateEvents > 0) {
      console.warn(
        `! ${result.skippedLateEvents} evento(s) confirmaram além de ALERTS_ENGINE_MAX_LATENESS_HOURS e não foram reavaliados.`,
      );
    }
    if (result.behind) {
      console.warn('! Ainda há eventos antigos para avaliar. Rode de novo.');
      process.exitCode = 3;
    }
  }
} catch (error) {
  console.error(
    `✖ Rodada falhou (nada foi confirmado; o checkpoint não avançou): ${error instanceof Error ? error.message : String(error)}`,
  );
  process.exitCode = 1;
} finally {
  await prisma.$disconnect();
}
