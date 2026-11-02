/**
 * Retenção de alertas de segurança. Execução MANUAL e controlada (não há agendador).
 *
 *   npm run alerts:retention                                   # simulação: só conta
 *   npm run alerts:retention -- --execute --confirm <banco>    # apaga, em lotes
 *
 * Só alertas RESOLVED cuja resolução passou de ALERTS_RETENTION_DAYS. Alertas OPEN nunca são
 * apagados (são apenas contados, para revisão). Para apagar: ALERTS_RETENTION_ENABLED=true,
 * --execute e --confirm com o nome do banco. Fora de produção, só bancos *_test.
 *
 * Códigos de saída: 0 = ok · 1 = bloqueado/inválido · 3 = parou no limite de lotes.
 */
import { existsSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { createPrismaClient } from '../src/infra/prisma.js';
import {
  alertRetentionConfigSchema,
  runAlertRetention,
} from '../src/modules/alerts/alert-retention.js';
import { checkRetentionRun } from './audit-retention-guard.js';

if (existsSync('.env')) process.loadEnvFile('.env');

const { values } = parseArgs({
  options: { execute: { type: 'boolean', default: false }, confirm: { type: 'string' } },
  strict: true,
});

const config = alertRetentionConfigSchema.safeParse(process.env);
if (!config.success) {
  for (const issue of config.error.issues)
    console.error(`✖ ${issue.path.join('.')}: ${issue.message}`);
  process.exit(1);
}

const check = checkRetentionRun({
  nodeEnv: process.env.NODE_ENV,
  databaseUrl: process.env.DATABASE_URL,
  enabled: config.data.ALERTS_RETENTION_ENABLED,
  execute: values.execute,
  confirm: values.confirm,
  enabledVariable: 'ALERTS_RETENTION_ENABLED',
});
if (!check.ok) {
  for (const error of check.errors) console.error(`✖ ${error}`);
  process.exit(1);
}

const { data } = config;
console.log(`Banco: ${check.database.name} em ${check.database.host}`);
console.log(
  `Modo: ${check.mode === 'execute' ? 'EXECUÇÃO (apaga)' : 'simulação (nada é apagado)'} · ` +
    `alertas RESOLVED há mais de ${data.ALERTS_RETENTION_DAYS} dias · ` +
    `lotes de ${data.ALERTS_RETENTION_BATCH_SIZE} (máx. ${data.ALERTS_RETENTION_MAX_BATCHES})`,
);

const prisma = createPrismaClient(process.env.DATABASE_URL ?? '');
try {
  const result = await runAlertRetention(prisma, data, { dryRun: check.mode === 'dry-run' });
  console.log(
    `Vencidos: ${result.eligible} · apagados: ${result.deleted} em ${result.batches} lote(s) · ` +
      `corte ${result.cutoff.toISOString()}`,
  );
  if (result.openOlderThanCutoff > 0) {
    console.warn(
      `! ${result.openOlderThanCutoff} alerta(s) OPEN mais antigos que o corte: nunca apagados; revise-os.`,
    );
  }
  if (!result.dryRun && !result.complete) {
    console.warn('! Limite de lotes atingido: ainda há alertas vencidos. Rode de novo.');
    process.exitCode = 3;
  }
} finally {
  await prisma.$disconnect();
}
