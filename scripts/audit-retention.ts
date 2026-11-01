/**
 * Retenção da trilha de auditoria. Execução MANUAL e controlada (não há agendador).
 *
 *   npm run audit:retention                                   # simulação: só conta
 *   npm run audit:retention -- --execute --confirm <banco>    # apaga, em lotes
 *
 * Para apagar: AUDIT_RETENTION_ENABLED=true, --execute e --confirm com o nome do banco.
 * Fora de produção, só bancos *_test. Prazos e lotes vêm de AUDIT_RETENTION_* (.env.example).
 *
 * Códigos de saída: 0 = ok · 1 = bloqueado/inválido · 3 = parou no limite de lotes.
 */
import { existsSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { createPrismaClient } from '../src/infra/prisma.js';
import { retentionConfigSchema, runAuditRetention } from '../src/modules/audit/audit-retention.js';
import { checkRetentionRun } from './audit-retention-guard.js';

if (existsSync('.env')) process.loadEnvFile('.env');

const { values } = parseArgs({
  options: { execute: { type: 'boolean', default: false }, confirm: { type: 'string' } },
  strict: true,
});

const config = retentionConfigSchema.safeParse(process.env);
if (!config.success) {
  for (const issue of config.error.issues)
    console.error(`✖ ${issue.path.join('.')}: ${issue.message}`);
  process.exit(1);
}

const check = checkRetentionRun({
  nodeEnv: process.env.NODE_ENV,
  databaseUrl: process.env.DATABASE_URL,
  enabled: config.data.AUDIT_RETENTION_ENABLED,
  execute: values.execute,
  confirm: values.confirm,
});
if (!check.ok) {
  for (const error of check.errors) console.error(`✖ ${error}`);
  process.exit(1);
}

const { data } = config;
console.log(`Banco: ${check.database.name} em ${check.database.host}`);
console.log(
  `Modo: ${check.mode === 'execute' ? 'EXECUÇÃO (apaga)' : 'simulação (nada é apagado)'} · ` +
    `padrão ${data.AUDIT_RETENTION_DAYS} dias · estendida ${data.AUDIT_RETENTION_EXTENDED_DAYS} dias · ` +
    `lotes de ${data.AUDIT_RETENTION_BATCH_SIZE} (máx. ${data.AUDIT_RETENTION_MAX_BATCHES})`,
);

const prisma = createPrismaClient(process.env.DATABASE_URL ?? '');
try {
  const result = await runAuditRetention(prisma, data, { dryRun: check.mode === 'dry-run' });
  console.log(
    `Vencidos: ${result.eligible} · apagados: ${result.deleted} em ${result.batches} lote(s) · ` +
      `corte padrão ${result.cutoff.toISOString()} · corte estendido ${result.extendedCutoff.toISOString()}`,
  );
  if (!result.dryRun && !result.complete) {
    console.warn('! Limite de lotes atingido: ainda há eventos vencidos. Rode de novo.');
    process.exitCode = 3;
  }
} finally {
  await prisma.$disconnect();
}
