import { describe, expect, it } from 'vitest';
import { createAdminService } from '../../../src/modules/admin/admin.service.js';
import type { AdminRepository } from '../../../src/modules/admin/admin.types.js';
import type { PublicUser } from '../../../src/modules/users/users.types.js';

const date = new Date('2026-11-01T00:00:00.000Z');
const ana: PublicUser = {
  id: '0190a000-0000-7000-8000-000000000001',
  name: 'Ana',
  email: 'ana@example.com',
  role: 'USER',
  createdAt: date,
  updatedAt: date,
};

const repository: AdminRepository = {
  listUsers: () => Promise.resolve({ items: [ana], total: 1 }),
  findUserById: (id) => Promise.resolve(id === ana.id ? ana : null),
  listAuditEvents: () => Promise.resolve({ items: [], total: 0 }),
};
const service = createAdminService({ adminRepository: repository });

describe('AdminService', () => {
  it('getUser devolve o usuário existente', async () => {
    await expect(service.getUser(ana.id)).resolves.toEqual(ana);
  });

  it('getUser: 404 NOT_FOUND para usuário inexistente', async () => {
    await expect(service.getUser('0190a000-0000-7000-8000-0000000000ff')).rejects.toMatchObject({
      statusCode: 404,
      code: 'NOT_FOUND',
    });
  });

  it('listUsers repassa a consulta já validada ao repositório', async () => {
    await expect(
      service.listUsers({ page: 1, pageSize: 20, sort: 'createdAt', order: 'desc' }),
    ).resolves.toEqual({ items: [ana], total: 1 });
  });
});
