import { z } from 'zod';
import { AuditEventType, Role } from '../../generated/prisma/enums.js';
import { publicUserSchema, toPublicUserDto } from '../users/users.schemas.js';
import type { PublicUser } from '../users/users.types.js';
import type { AuditEventView, Page, Pagination } from './admin.types.js';

export const DEFAULT_PAGE_SIZE = 20;
export const MAX_PAGE_SIZE = 100;
/** Teto de página: limita o OFFSET a 100 mil linhas (paginação por offset fica cara além disso). */
export const MAX_PAGE = 1000;

/**
 * Query strings chegam como texto: `z.coerce` converte e os limites rejeitam o resto.
 * Parâmetro repetido (?page=1&page=2) chega como array e também é rejeitado.
 */
const paginationShape = {
  page: z.coerce.number().int().min(1).max(MAX_PAGE).default(1),
  pageSize: z.coerce
    .number()
    .int()
    .min(1)
    .max(MAX_PAGE_SIZE, `pageSize pode ser no máximo ${MAX_PAGE_SIZE}`)
    .default(DEFAULT_PAGE_SIZE),
};

const isoDate = z.iso
  .datetime({ offset: true, message: 'Use uma data ISO 8601, ex.: 2026-11-01T00:00:00Z' })
  .transform((value) => new Date(value));

/** strictObject: parâmetro desconhecido (ex.: passwordHash=..., sort=password) gera 400. */
export const listUsersQuerySchema = z.strictObject({
  ...paginationShape,
  email: z
    .string()
    .trim()
    .toLowerCase()
    .min(1)
    .max(254)
    .optional()
    .meta({ description: 'Trecho do email (sem diferenciar maiúsculas)' }),
  role: z.enum(Role).optional(),
  // Lista fechada: o campo de ordenação nunca vem livre do cliente.
  sort: z.enum(['createdAt', 'email', 'name']).default('createdAt'),
  order: z.enum(['asc', 'desc']).default('desc'),
});

export const listAuditEventsQuerySchema = z
  .strictObject({
    ...paginationShape,
    type: z.enum(AuditEventType).optional(),
    userId: z.uuid().optional(),
    from: isoDate.optional().meta({ description: 'Início do período (inclusive)' }),
    to: isoDate.optional().meta({ description: 'Fim do período (exclusive)' }),
    order: z.enum(['asc', 'desc']).default('desc'),
  })
  .refine((query) => !query.from || !query.to || query.from < query.to, {
    message: '"from" precisa ser anterior a "to"',
    path: ['from'],
  });

export const userIdParamsSchema = z.strictObject({ id: z.uuid('id precisa ser um UUID') });

const paginationSchema = z.object({
  page: z.number().int(),
  pageSize: z.number().int(),
  total: z.number().int(),
  totalPages: z.number().int(),
});

export const userListSchema = z
  .object({ data: z.array(publicUserSchema), pagination: paginationSchema })
  .meta({ id: 'UserList' });

export const auditEventSchema = z
  .object({
    id: z.uuid(),
    type: z.enum(AuditEventType),
    userId: z.uuid().nullable(),
    ip: z.string().nullable(),
    metadata: z.record(z.string(), z.unknown()).nullable(),
    createdAt: z.iso.datetime(),
  })
  .meta({ id: 'AuditEvent' });

export const auditEventListSchema = z
  .object({ data: z.array(auditEventSchema), pagination: paginationSchema })
  .meta({ id: 'AuditEventList' });

const toPagination = ({ page, pageSize }: Pagination, total: number) => ({
  page,
  pageSize,
  total,
  totalPages: Math.ceil(total / pageSize),
});

export function toUserListDto(page: Page<PublicUser>, query: Pagination) {
  return { data: page.items.map(toPublicUserDto), pagination: toPagination(query, page.total) };
}

/** Campo a campo, sem spread: um campo novo na tabela não vaza por acidente. */
export function toAuditEventListDto(page: Page<AuditEventView>, query: Pagination) {
  return {
    data: page.items.map((event) => ({
      id: event.id,
      type: event.type,
      userId: event.userId,
      ip: event.ip,
      metadata: event.metadata,
      createdAt: event.createdAt.toISOString(),
    })),
    pagination: toPagination(query, page.total),
  };
}
