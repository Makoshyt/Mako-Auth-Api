import { z } from 'zod';
import type { Prisma } from '../../generated/prisma/client.js';
import type { PrismaClient } from '../../infra/prisma.js';

const DAY_MS = 86_400_000;

/**
 * Retenção de alertas. Execução MANUAL (`npm run alerts:retention`), desligada por padrão.
 * Só alertas RESOLVED, pela data de resolução: um alerta OPEN nunca é apagado, por mais antigo.
 */
export const alertRetentionConfigSchema = z.object({
  ALERTS_RETENTION_ENABLED: z.stringbool().default(false),
  ALERTS_RETENTION_DAYS: z.coerce.number().int().min(30).max(3650).default(365),
  ALERTS_RETENTION_BATCH_SIZE: z.coerce.number().int().min(1).max(10_000).default(500),
  ALERTS_RETENTION_MAX_BATCHES: z.coerce.number().int().min(1).max(10_000).default(100),
});

export type AlertRetentionConfig = z.infer<typeof alertRetentionConfigSchema>;

export interface AlertRetentionResult {
  dryRun: boolean;
  cutoff: Date;
  /** Alertas RESOLVED vencidos encontrados antes de apagar. */
  eligible: number;
  /** Alertas OPEN mais antigos que o corte: nunca apagados, informados para revisão. */
  openOlderThanCutoff: number;
  deleted: number;
  batches: number;
  /** false se parou no limite de lotes com alertas vencidos restantes. */
  complete: boolean;
}

export function expiredAlertsWhere(
  config: AlertRetentionConfig,
  now: Date,
): Prisma.SecurityAlertWhereInput {
  return {
    status: 'RESOLVED',
    resolvedAt: { lt: new Date(now.getTime() - config.ALERTS_RETENTION_DAYS * DAY_MS) },
  };
}

/**
 * Apaga alertas RESOLVED vencidos em lotes (os mais antigos primeiro), cada lote numa
 * instrução curta, até `ALERTS_RETENTION_MAX_BATCHES`. Em `dryRun` (padrão), só conta.
 * O lote é revalidado no DELETE (status e data), então um alerta que mudou no meio não sai.
 */
export async function runAlertRetention(
  prisma: PrismaClient,
  config: AlertRetentionConfig,
  { now = new Date(), dryRun = true }: { now?: Date; dryRun?: boolean } = {},
): Promise<AlertRetentionResult> {
  const where = expiredAlertsWhere(config, now);
  const cutoff = new Date(now.getTime() - config.ALERTS_RETENTION_DAYS * DAY_MS);
  const [eligible, openOlderThanCutoff] = await Promise.all([
    prisma.securityAlert.count({ where }),
    prisma.securityAlert.count({ where: { status: 'OPEN', createdAt: { lt: cutoff } } }),
  ]);
  const result: AlertRetentionResult = {
    dryRun,
    cutoff,
    eligible,
    openOlderThanCutoff,
    deleted: 0,
    batches: 0,
    complete: eligible === 0,
  };
  if (dryRun || eligible === 0) return result;

  while (result.batches < config.ALERTS_RETENTION_MAX_BATCHES) {
    const batch = await prisma.securityAlert.findMany({
      where,
      select: { id: true },
      orderBy: [{ resolvedAt: 'asc' }, { id: 'asc' }],
      take: config.ALERTS_RETENTION_BATCH_SIZE,
    });
    if (batch.length === 0) break;
    const { count } = await prisma.securityAlert.deleteMany({
      where: { AND: [where, { id: { in: batch.map((alert) => alert.id) } }] },
    });
    result.deleted += count;
    result.batches++;
    if (batch.length < config.ALERTS_RETENTION_BATCH_SIZE) break;
  }
  result.complete = (await prisma.securityAlert.count({ where })) === 0;
  return result;
}
