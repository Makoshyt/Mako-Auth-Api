import { z } from 'zod';
import type { Prisma } from '../../generated/prisma/client.js';
import type { AuditEventType } from '../../generated/prisma/enums.js';
import type { PrismaClient } from '../../infra/prisma.js';

/**
 * Eventos guardados por mais tempo: sinais de ataque e ações de responsabilização (quem mudou
 * a própria conta, quem leu dados de outras pessoas). O resto segue a retenção padrão.
 */
export const EXTENDED_RETENTION_TYPES: readonly AuditEventType[] = [
  'TOKEN_REUSE_DETECTED',
  'ACCESS_DENIED',
  'RATE_LIMIT_EXCEEDED',
  'PASSWORD_RESET_SUCCESS',
  'PROFILE_UPDATED',
  'ADMIN_USERS_LISTED',
  'ADMIN_USER_VIEWED',
  'ADMIN_AUDIT_QUERIED',
];

const DAY_MS = 86_400_000;

/** Configuração lida do ambiente pela rotina (CLI). Nada roda sozinho: não há agendador. */
export const retentionConfigSchema = z
  .object({
    AUDIT_RETENTION_ENABLED: z.stringbool().default(false),
    AUDIT_RETENTION_DAYS: z.coerce.number().int().min(30).max(3650).default(180),
    AUDIT_RETENTION_EXTENDED_DAYS: z.coerce.number().int().min(30).max(3650).default(365),
    AUDIT_RETENTION_BATCH_SIZE: z.coerce.number().int().min(1).max(10_000).default(1_000),
    AUDIT_RETENTION_MAX_BATCHES: z.coerce.number().int().min(1).max(10_000).default(100),
  })
  .refine((c) => c.AUDIT_RETENTION_EXTENDED_DAYS >= c.AUDIT_RETENTION_DAYS, {
    message: 'AUDIT_RETENTION_EXTENDED_DAYS não pode ser menor que AUDIT_RETENTION_DAYS',
    path: ['AUDIT_RETENTION_EXTENDED_DAYS'],
  });

export type RetentionConfig = z.infer<typeof retentionConfigSchema>;

export interface RetentionResult {
  dryRun: boolean;
  cutoff: Date;
  extendedCutoff: Date;
  /** Eventos vencidos encontrados antes de apagar. */
  eligible: number;
  deleted: number;
  batches: number;
  /** false se parou no limite de lotes com eventos vencidos restantes. */
  complete: boolean;
}

/**
 * Única forma de apagar eventos: o trigger `audit_events_guard` recusa DELETE/TRUNCATE fora de
 * uma transação que ligou `authapi.audit_purge` (vale só até o fim desta transação).
 */
export function deleteAuditEvents(
  prisma: PrismaClient,
  where: Prisma.AuditEventWhereInput,
): Promise<number> {
  return prisma.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT set_config('authapi.audit_purge', 'on', true)`;
    const { count } = await tx.auditEvent.deleteMany({ where });
    return count;
  });
}

export function expiredWhere(config: RetentionConfig, now: Date): Prisma.AuditEventWhereInput {
  const cutoff = new Date(now.getTime() - config.AUDIT_RETENTION_DAYS * DAY_MS);
  const extendedCutoff = new Date(now.getTime() - config.AUDIT_RETENTION_EXTENDED_DAYS * DAY_MS);
  return {
    OR: [
      { type: { notIn: [...EXTENDED_RETENTION_TYPES] }, createdAt: { lt: cutoff } },
      { type: { in: [...EXTENDED_RETENTION_TYPES] }, createdAt: { lt: extendedCutoff } },
    ],
  };
}

/**
 * Apaga eventos vencidos em lotes (os mais antigos primeiro), cada lote numa transação curta,
 * até `AUDIT_RETENTION_MAX_BATCHES`. Em `dryRun` (padrão), só conta: nada é apagado.
 */
export async function runAuditRetention(
  prisma: PrismaClient,
  config: RetentionConfig,
  { now = new Date(), dryRun = true }: { now?: Date; dryRun?: boolean } = {},
): Promise<RetentionResult> {
  const where = expiredWhere(config, now);
  const eligible = await prisma.auditEvent.count({ where });
  const result: RetentionResult = {
    dryRun,
    cutoff: new Date(now.getTime() - config.AUDIT_RETENTION_DAYS * DAY_MS),
    extendedCutoff: new Date(now.getTime() - config.AUDIT_RETENTION_EXTENDED_DAYS * DAY_MS),
    eligible,
    deleted: 0,
    batches: 0,
    complete: eligible === 0,
  };
  if (dryRun || eligible === 0) return result;

  while (result.batches < config.AUDIT_RETENTION_MAX_BATCHES) {
    const batch = await prisma.auditEvent.findMany({
      where,
      select: { id: true },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
      take: config.AUDIT_RETENTION_BATCH_SIZE,
    });
    if (batch.length === 0) break;
    result.deleted += await deleteAuditEvents(prisma, { id: { in: batch.map((e) => e.id) } });
    result.batches++;
    if (batch.length < config.AUDIT_RETENTION_BATCH_SIZE) break;
  }
  result.complete = (await prisma.auditEvent.count({ where })) === 0;
  return result;
}
