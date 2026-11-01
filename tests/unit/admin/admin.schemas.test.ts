import { describe, expect, it } from 'vitest';
import { escapeLike } from '../../../src/modules/admin/admin.repository.js';
import {
  listAuditEventsQuerySchema,
  listUsersQuerySchema,
  MAX_PAGE_SIZE,
  userIdParamsSchema,
} from '../../../src/modules/admin/admin.schemas.js';

/** Query strings chegam como texto, como o Fastify as entrega. */
const parseUsers = (query: Record<string, string>) => listUsersQuerySchema.safeParse(query);
const parseAudit = (query: Record<string, string>) => listAuditEventsQuerySchema.safeParse(query);

describe('listUsersQuerySchema', () => {
  it('aplica padrões seguros: página 1, 20 itens, mais recentes primeiro', () => {
    expect(listUsersQuerySchema.parse({})).toEqual({
      page: 1,
      pageSize: 20,
      sort: 'createdAt',
      order: 'desc',
    });
  });

  it('converte números e normaliza o filtro de email', () => {
    expect(
      listUsersQuerySchema.parse({ page: '3', pageSize: '50', email: '  ANA@Example.com ' }),
    ).toMatchObject({ page: 3, pageSize: 50, email: 'ana@example.com' });
  });

  it(`rejeita pageSize acima de ${MAX_PAGE_SIZE} (sem paginação ilimitada)`, () => {
    expect(parseUsers({ pageSize: String(MAX_PAGE_SIZE + 1) }).success).toBe(false);
    expect(parseUsers({ pageSize: String(MAX_PAGE_SIZE) }).success).toBe(true);
  });

  it.each([
    ['page 0', { page: '0' }],
    ['page negativa', { page: '-1' }],
    ['page acima do teto', { page: '1001' }],
    ['page fracionária', { page: '1.5' }],
    ['page não numérica', { page: 'abc' }],
    ['pageSize 0', { pageSize: '0' }],
  ])('rejeita paginação inválida: %s', (_label, query) => {
    expect(parseUsers(query).success).toBe(false);
  });

  it.each(['createdAt', 'email', 'name'])('aceita ordenar por %s', (sort) => {
    expect(parseUsers({ sort, order: 'asc' }).success).toBe(true);
  });

  it.each(['passwordHash', 'password_hash', 'role', 'id; DROP TABLE users', 'createdAt desc'])(
    'rejeita ordenação fora da lista: %s',
    (sort) => {
      expect(parseUsers({ sort }).success).toBe(false);
    },
  );

  it.each([
    ['role inexistente', { role: 'SUPERADMIN' }],
    ['role minúsculo', { role: 'admin' }],
    ['order inválido', { order: 'random' }],
    ['email vazio', { email: '   ' }],
    ['email gigante', { email: 'a'.repeat(255) }],
    ['parâmetro desconhecido', { passwordHash: 'x' }],
    ['parâmetro desconhecido', { include: 'sessions' }],
  ])('rejeita filtro inválido: %s', (_label, query) => {
    expect(parseUsers(query).success).toBe(false);
  });

  it('rejeita parâmetro repetido (chega como array)', () => {
    expect(listUsersQuerySchema.safeParse({ role: ['USER', 'ADMIN'] }).success).toBe(false);
  });
});

describe('listAuditEventsQuerySchema', () => {
  it('aceita tipo, usuário e período, convertendo as datas', () => {
    const parsed = listAuditEventsQuerySchema.parse({
      type: 'ACCESS_DENIED',
      userId: '0190a000-0000-7000-8000-000000000001',
      from: '2026-11-01T00:00:00Z',
      to: '2026-11-02T00:00:00-03:00',
    });

    expect(parsed).toMatchObject({ type: 'ACCESS_DENIED', order: 'desc', pageSize: 20 });
    expect(parsed.from?.toISOString()).toBe('2026-11-01T00:00:00.000Z');
    expect(parsed.to?.toISOString()).toBe('2026-11-02T03:00:00.000Z');
  });

  it.each([
    ['tipo inexistente', { type: 'LOGIN' }],
    ['userId que não é UUID', { userId: '1 OR 1=1' }],
    ['data não ISO', { from: '01/11/2026' }],
    ['data inválida', { from: '2026-13-45T00:00:00Z' }],
    ['from depois de to', { from: '2026-11-02T00:00:00Z', to: '2026-11-01T00:00:00Z' }],
    ['from igual a to', { from: '2026-11-01T00:00:00Z', to: '2026-11-01T00:00:00Z' }],
    ['pageSize acima do máximo', { pageSize: '101' }],
    ['ordenação por outro campo', { sort: 'ip' }],
    ['parâmetro desconhecido', { emailHash: 'abc' }],
  ])('rejeita %s', (_label, query) => {
    expect(parseAudit(query).success).toBe(false);
  });
});

describe('userIdParamsSchema', () => {
  it('aceita UUID e rejeita qualquer outra coisa', () => {
    expect(
      userIdParamsSchema.safeParse({ id: '0190a000-0000-7000-8000-000000000001' }).success,
    ).toBe(true);
    for (const id of ['me', '1', "' OR '1'='1", '../users']) {
      expect(userIdParamsSchema.safeParse({ id }).success).toBe(false);
    }
  });
});

describe('escapeLike', () => {
  it('trata %, _ e \\ como texto literal', () => {
    expect(escapeLike('a_b%c\\d')).toBe('a\\_b\\%c\\\\d');
    expect(escapeLike('ana@example.com')).toBe('ana@example.com');
  });
});
