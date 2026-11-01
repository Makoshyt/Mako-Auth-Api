import { notFound } from '../../shared/errors.js';
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
}

export type AdminService = ReturnType<typeof createAdminService>;

/**
 * Consultas administrativas, somente leitura. A autorização (ADMIN) é aplicada nas rotas,
 * por hooks do plugin inteiro; aqui ficam só as regras de consulta.
 * Não há exclusão, troca de papel nem redefinição de senha nesta etapa.
 */
export function createAdminService({ adminRepository }: AdminServiceDeps) {
  return {
    listUsers(query: ListUsersQuery): Promise<Page<PublicUser>> {
      return adminRepository.listUsers(query);
    },

    async getUser(id: string): Promise<PublicUser> {
      const user = await adminRepository.findUserById(id);
      if (!user) throw notFound('Usuário não encontrado');
      return user;
    },

    listAuditEvents(query: ListAuditEventsQuery): Promise<Page<AuditEventView>> {
      return adminRepository.listAuditEvents(query);
    },
  };
}
