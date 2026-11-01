import type { Prisma } from '../../generated/prisma/client.js';
import type { PrismaClient } from '../../infra/prisma.js';
import { publicUserSelect } from '../users/users.repository.js';
import type { AdminRepository, AuditEventView, ListUsersQuery } from './admin.types.js';

/**
 * O Prisma não escapa os curingas do LIKE em `contains` (verificado no SQL gerado):
 * "a_b" casaria com "axb" e "%" com tudo. Escapamos para que o filtro seja texto literal.
 */
export const escapeLike = (value: string) => value.replace(/[\\%_]/g, '\\$&');

const auditEventSelect = {
  id: true,
  type: true,
  userId: true,
  ip: true,
  metadata: true,
  createdAt: true,
} as const satisfies Prisma.AuditEventSelect;

function userOrderBy({ sort, order }: ListUsersQuery): Prisma.UserOrderByWithRelationInput[] {
  const primary: Prisma.UserOrderByWithRelationInput =
    sort === 'email' ? { email: order } : sort === 'name' ? { name: order } : { createdAt: order };
  // Desempate pelo id: a ordem é estável e nenhum item some ou se repete entre páginas.
  return [primary, { id: order }];
}

const asMetadata = (value: Prisma.JsonValue): Record<string, unknown> | null =>
  value !== null && typeof value === 'object' && !Array.isArray(value) ? value : null;

export function createAdminRepository(prisma: PrismaClient): AdminRepository {
  return {
    async listUsers(query) {
      const where: Prisma.UserWhereInput = {
        ...(query.email !== undefined && { email: { contains: escapeLike(query.email) } }),
        ...(query.role !== undefined && { role: query.role }),
      };
      const [items, total] = await prisma.$transaction([
        prisma.user.findMany({
          where,
          select: publicUserSelect,
          orderBy: userOrderBy(query),
          skip: (query.page - 1) * query.pageSize,
          take: query.pageSize,
        }),
        prisma.user.count({ where }),
      ]);
      return { items, total };
    },

    findUserById(id) {
      return prisma.user.findUnique({ where: { id }, select: publicUserSelect });
    },

    async listAuditEvents(query) {
      const where: Prisma.AuditEventWhereInput = {
        ...(query.type !== undefined && { type: query.type }),
        ...(query.userId !== undefined && { userId: query.userId }),
        ...((query.from ?? query.to) && {
          createdAt: {
            ...(query.from && { gte: query.from }),
            ...(query.to && { lt: query.to }),
          },
        }),
      };
      const [rows, total] = await prisma.$transaction([
        prisma.auditEvent.findMany({
          where,
          select: auditEventSelect,
          orderBy: [{ createdAt: query.order }, { id: query.order }],
          skip: (query.page - 1) * query.pageSize,
          take: query.pageSize,
        }),
        prisma.auditEvent.count({ where }),
      ]);
      const items: AuditEventView[] = rows.map((row) => ({
        ...row,
        metadata: asMetadata(row.metadata),
      }));
      return { items, total };
    },
  };
}
