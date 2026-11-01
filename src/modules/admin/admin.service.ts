import { notFound } from '../../shared/errors.js';
import type { AuditRecorder } from '../audit/audit.recorder.js';
import type { PublicUser } from '../users/users.types.js';
import type {
  AdminRepository,
  AuditEventView,
  ListAuditEventsQuery,
  ListUsersQuery,
  Page,
} from './admin.types.js';

export interface AdminServiceDeps {
  adminRepository: AdminRepository;
  audit: AuditRecorder;
}

/** Quem está consultando: sempre o ADMIN autenticado (nunca um valor vindo do cliente). */
export interface AdminActor {
  userId: string;
  ip: string | null;
}

export type AdminService = ReturnType<typeof createAdminService>;

/**
 * Consultas administrativas, somente leitura. A autorização (ADMIN) é aplicada nas rotas,
 * por hooks do plugin inteiro; aqui ficam as regras de consulta e a responsabilização.
 *
 * Cada consulta concluída gera UM evento, gravado DEPOIS da leitura: a consulta à auditoria
 * nunca inclui o próprio registro (sem recursão) e nenhum evento é criado por item retornado
 * (sem amplificação). O volume é limitado pelo rate limit por ADMIN (Etapa 6).
 */
export function createAdminService({ adminRepository, audit }: AdminServiceDeps) {
  return {
    async listUsers(query: ListUsersQuery, actor: AdminActor): Promise<Page<PublicUser>> {
      const page = await adminRepository.listUsers(query);
      await audit.record({
        type: 'ADMIN_USERS_LISTED',
        userId: actor.userId,
        ip: actor.ip,
        metadata: {
          page: query.page,
          pageSize: query.pageSize,
          sort: query.sort,
          order: query.order,
          ...(query.role !== undefined && { role: query.role }),
          // O trecho de email pesquisado pode ser dado pessoal: registra só que houve filtro.
          emailFilter: query.email !== undefined,
          resultCount: page.items.length,
        },
      });
      return page;
    },

    async getUser(id: string, actor: AdminActor): Promise<PublicUser> {
      const user = await adminRepository.findUserById(id);
      // Registra também a busca sem resultado: sondar ids é tão relevante quanto ler um perfil.
      await audit.record({
        type: 'ADMIN_USER_VIEWED',
        userId: actor.userId,
        ip: actor.ip,
        metadata: { targetUserId: id, found: user !== null },
      });
      if (!user) throw notFound('Usuário não encontrado');
      return user;
    },

    async listAuditEvents(
      query: ListAuditEventsQuery,
      actor: AdminActor,
    ): Promise<Page<AuditEventView>> {
      const page = await adminRepository.listAuditEvents(query);
      await audit.record({
        type: 'ADMIN_AUDIT_QUERIED',
        userId: actor.userId,
        ip: actor.ip,
        metadata: {
          page: query.page,
          pageSize: query.pageSize,
          order: query.order,
          ...(query.type !== undefined && { filterType: query.type }),
          ...(query.userId !== undefined && { targetUserId: query.userId }),
          ...(query.from !== undefined && { from: query.from.toISOString() }),
          ...(query.to !== undefined && { to: query.to.toISOString() }),
          resultCount: page.items.length,
        },
      });
      return page;
    },
  };
}
