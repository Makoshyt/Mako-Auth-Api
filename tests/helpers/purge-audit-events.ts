import type { Prisma } from '../../src/generated/prisma/client.js';
import type { PrismaClient } from '../../src/infra/prisma.js';
import { deleteAuditEvents } from '../../src/modules/audit/audit-retention.js';

/**
 * Limpeza dos eventos FICTÍCIOS criados por um teste. Desde a Etapa 8, `audit_events` é
 * append-only no banco (trigger): apagar só é possível pela mesma porta da rotina de retenção.
 * Mesma assinatura do `deleteMany`, para a troca nos testes ser mecânica.
 */
export function purgeAuditEvents(
  prisma: PrismaClient,
  { where }: { where: Prisma.AuditEventWhereInput },
): Promise<number> {
  return deleteAuditEvents(prisma, where);
}
