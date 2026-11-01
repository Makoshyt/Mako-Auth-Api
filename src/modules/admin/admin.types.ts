import type { AuditEventType, Role } from '../../generated/prisma/enums.js';
import type { PublicUser } from '../users/users.types.js';

export interface Pagination {
  page: number;
  pageSize: number;
}

export type UserSortField = 'createdAt' | 'email' | 'name';
export type SortOrder = 'asc' | 'desc';

export interface ListUsersQuery extends Pagination {
  /** Trecho do email (já normalizado). Curingas do LIKE são tratados como texto. */
  email?: string;
  role?: Role;
  sort: UserSortField;
  order: SortOrder;
}

export interface ListAuditEventsQuery extends Pagination {
  type?: AuditEventType;
  userId?: string;
  from?: Date;
  to?: Date;
  order: SortOrder;
}

/**
 * Evento como sai para o administrador. Sem `emailHash`: o hash de email sem chave pode ser
 * revertido por dicionário, e o `userId` já identifica a conta quando ela existe.
 */
export interface AuditEventView {
  id: string;
  type: AuditEventType;
  userId: string | null;
  ip: string | null;
  metadata: Record<string, unknown> | null;
  createdAt: Date;
}

export interface Page<T> {
  items: T[];
  total: number;
}

export interface AdminRepository {
  listUsers(query: ListUsersQuery): Promise<Page<PublicUser>>;
  findUserById(id: string): Promise<PublicUser | null>;
  listAuditEvents(query: ListAuditEventsQuery): Promise<Page<AuditEventView>>;
}
