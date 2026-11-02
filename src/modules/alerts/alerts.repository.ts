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
  resolvedById: true,
  resolutionNote: true,
  createdAt: true,
  updatedAt: true,
} as const satisfies Prisma.SecurityAlertSelect;

export type AlertView = Prisma.SecurityAlertGetPayload<{ select: typeof alertSelect }>;

export interface ResolveAlertInput {
  id: string;
  resolvedById: string;
  note: string | null;
  at: Date;
}

export interface AlertsRepository {
  list(query: ListAlertsQuery): Promise<{ items: AlertView[]; total: number }>;
  findById(id: string): Promise<AlertView | null>;
  /**
   * OPEN -> RESOLVED, condicional (WHERE status = 'OPEN'): duas resoluções simultâneas não
   * se sobrescrevem; a segunda recebe null. Nunca altera regra, contagens nem evidências.
   */
  resolve(input: ResolveAlertInput): Promise<AlertView | null>;
  /** Dos ids informados, os que ainda existem em audit_events (a retenção pode ter apagado). */
  existingEventIds(ids: readonly string[]): Promise<string[]>;
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

    async resolve({ id, resolvedById, note, at }) {
      const { count } = await prisma.securityAlert.updateMany({
        where: { id, status: 'OPEN' },
        data: { status: 'RESOLVED', resolvedAt: at, resolvedById, resolutionNote: note },
      });
      if (count === 0) return null;
      return prisma.securityAlert.findUnique({ where: { id }, select: alertSelect });
    },

    async existingEventIds(ids) {
      if (ids.length === 0) return [];
      const rows = await prisma.auditEvent.findMany({
        where: { id: { in: [...ids] } },
        select: { id: true },
      });
      return rows.map((row) => row.id);
    },
  };
}
