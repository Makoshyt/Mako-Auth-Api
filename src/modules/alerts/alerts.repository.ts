import type { Prisma } from '../../generated/prisma/client.js';
import type { AlertRule, AlertSeverity, AlertStatus } from '../../generated/prisma/enums.js';
import type { PrismaClient } from '../../infra/prisma.js';

export interface ListAlertsQuery {
  page: number;
  pageSize: number;
  rule?: AlertRule;
  severity?: AlertSeverity;
  status?: AlertStatus;
  order: 'asc' | 'desc';
}

/** Projeção para o ADMIN: sem o fingerprint (identificador interno de deduplicação). */
const alertSelect = {
  id: true,
  rule: true,
  severity: true,
  status: true,
  summary: true,
  details: true,
  userId: true,
  eventCount: true,
  firstSeenAt: true,
  lastSeenAt: true,
  resolvedAt: true,
  createdAt: true,
  updatedAt: true,
} as const satisfies Prisma.SecurityAlertSelect;

export type AlertView = Prisma.SecurityAlertGetPayload<{ select: typeof alertSelect }>;

export interface AlertsRepository {
  list(query: ListAlertsQuery): Promise<{ items: AlertView[]; total: number }>;
  findById(id: string): Promise<AlertView | null>;
}

export function createAlertsRepository(prisma: PrismaClient): AlertsRepository {
  return {
    async list(query) {
      const where: Prisma.SecurityAlertWhereInput = {
        ...(query.rule !== undefined && { rule: query.rule }),
        ...(query.severity !== undefined && { severity: query.severity }),
        ...(query.status !== undefined && { status: query.status }),
      };
      const [items, total] = await prisma.$transaction([
        prisma.securityAlert.findMany({
          where,
          select: alertSelect,
          // Ordem estável: id desempata alertas criados no mesmo milissegundo.
          orderBy: [{ createdAt: query.order }, { id: query.order }],
          skip: (query.page - 1) * query.pageSize,
          take: query.pageSize,
        }),
        prisma.securityAlert.count({ where }),
      ]);
      return { items, total };
    },

    findById(id) {
      return prisma.securityAlert.findUnique({ where: { id }, select: alertSelect });
    },
  };
}
