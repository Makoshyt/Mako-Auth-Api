import { beforeEach, describe, expect, it } from 'vitest';
import type { AuditEventInput } from '../../../src/modules/audit/audit.recorder.js';
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
let events: AuditEventInput[] = [];
const service = createAdminService({
  adminRepository: repository,
  audit: {
    record: (event) => {
      events.push(event);
      return Promise.resolve();
    },
  },
});
const actor = { userId: '0190a000-0000-7000-8000-0000000000ad', ip: '203.0.113.1' };

beforeEach(() => {
  events = [];
});

describe('AdminService', () => {
  it('getUser devolve o usuário existente', async () => {
    await expect(service.getUser(ana.id, actor)).resolves.toEqual(ana);
  });

  it('getUser: 404 NOT_FOUND para usuário inexistente', async () => {
    await expect(
      service.getUser('0190a000-0000-7000-8000-0000000000ff', actor),
    ).rejects.toMatchObject({
      statusCode: 404,
      code: 'NOT_FOUND',
    });
  });

  it('listUsers repassa a consulta já validada ao repositório', async () => {
    await expect(
      service.listUsers({ page: 1, pageSize: 20, sort: 'createdAt', order: 'desc' }, actor),
    ).resolves.toEqual({ items: [ana], total: 1 });
  });
});

describe('AdminService: auditoria das consultas', () => {
  it('listagem: ADMIN_USERS_LISTED com filtros mínimos (sem o trecho de email pesquisado)', async () => {
    await service.listUsers(
      { page: 2, pageSize: 50, sort: 'email', order: 'asc', role: 'USER', email: 'ana@exemplo' },
      actor,
    );

    expect(events).toEqual([
      {
        type: 'ADMIN_USERS_LISTED',
        userId: actor.userId,
        ip: actor.ip,
        metadata: {
          page: 2,
          pageSize: 50,
          sort: 'email',
          order: 'asc',
          role: 'USER',
          emailFilter: true,
          resultCount: 1,
        },
      },
    ]);
    expect(JSON.stringify(events)).not.toContain('ana@exemplo');
  });

  it('consulta individual: registra o alvo e se ele existia (inclusive 404)', async () => {
    await service.getUser(ana.id, actor);
    await service.getUser('0190a000-0000-7000-8000-0000000000ff', actor).catch(() => undefined);

    expect(events.map((e) => e.metadata)).toEqual([
      { targetUserId: ana.id, found: true },
      { targetUserId: '0190a000-0000-7000-8000-0000000000ff', found: false },
    ]);
  });

  it('auditoria: um único evento por consulta, gravado depois da leitura (sem recursão)', async () => {
    const order: string[] = [];
    const tracked = createAdminService({
      adminRepository: {
        ...repository,
        listAuditEvents: () => {
          order.push('leitura');
          return Promise.resolve({ items: [], total: 0 });
        },
      },
      audit: {
        record: (event) => {
          order.push(`registro:${event.type}`);
          return Promise.resolve();
        },
      },
    });

    await tracked.listAuditEvents(
      {
        page: 1,
        pageSize: 20,
        order: 'desc',
        type: 'LOGIN_FAILURE',
        userId: ana.id,
        from: new Date('2026-11-01T00:00:00Z'),
      },
      actor,
    );

    expect(order).toEqual(['leitura', 'registro:ADMIN_AUDIT_QUERIED']);
  });
});
