import type { FastifyReply, FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuditEventInput } from '../../../src/modules/audit/audit.recorder.js';
import {
  authOf,
  extractBearerToken,
  requireRole,
} from '../../../src/modules/auth/auth.middleware.js';
import type { AuthContext } from '../../../src/modules/auth/auth.types.js';

let recorded: AuditEventInput[];
const record = vi.fn((event: AuditEventInput) => {
  recorded.push(event);
  return Promise.resolve();
});
beforeEach(() => {
  recorded = [];
  record.mockClear();
});

/** Requisição falsa com o mínimo que o requireRole lê. */
const request = (auth: AuthContext | null) =>
  ({
    auth,
    method: 'GET',
    ip: '203.0.113.7',
    headers: {},
    routeOptions: { url: '/api/v1/admin/users/:id' },
    server: { audit: { record } },
  }) as unknown as FastifyRequest;
const reply = {} as FastifyReply;
const user: AuthContext = {
  userId: '0190a000-0000-7000-8000-000000000001',
  sessionId: '0190a000-0000-7000-8000-000000000002',
  role: 'USER',
};

describe('extractBearerToken', () => {
  it.each([
    ['Bearer abc.def.ghi', 'abc.def.ghi'],
    ['bearer abc.def.ghi', 'abc.def.ghi'],
    ['Bearer   abc.def.ghi  ', 'abc.def.ghi'],
  ])('extrai de "%s"', (header, token) => {
    expect(extractBearerToken(header)).toBe(token);
  });

  it.each([
    ['ausente', undefined],
    ['vazio', ''],
    ['sem esquema', 'abc.def.ghi'],
    ['outro esquema', 'Basic dXNlcjpwYXNz'],
    ['Bearer sem token', 'Bearer '],
    ['dois tokens', 'Bearer a.b.c d.e.f'],
    ['token gigante', `Bearer ${'a'.repeat(2049)}`],
  ])('401 UNAUTHORIZED: %s', (_label, header) => {
    expect(() => extractBearerToken(header)).toThrow(
      expect.objectContaining({ statusCode: 401, code: 'UNAUTHORIZED' }),
    );
  });
});

describe('authOf', () => {
  it('falha fechada (401) se a rota não passou pelo authenticate', () => {
    expect(() => authOf(request(null))).toThrow(expect.objectContaining({ statusCode: 401 }));
  });
});

describe('requireRole', () => {
  it('401 sem identidade autenticada', async () => {
    await expect(requireRole('ADMIN')(request(null), reply)).rejects.toMatchObject({
      statusCode: 401,
    });
  });

  it('403 FORBIDDEN para USER em recurso ADMIN, registrando ACCESS_DENIED', async () => {
    await expect(requireRole('ADMIN')(request(user), reply)).rejects.toMatchObject({
      statusCode: 403,
      code: 'FORBIDDEN',
    });

    expect(recorded).toEqual([
      {
        type: 'ACCESS_DENIED',
        userId: user.userId,
        ip: '203.0.113.7',
        // Padrão da rota, sem ids nem query string; nenhum token ou sessão.
        metadata: {
          method: 'GET',
          route: '/api/v1/admin/users/:id',
          requiredRoles: 'ADMIN',
          role: 'USER',
        },
      },
    ]);
  });

  it('401 sem identidade não gera ACCESS_DENIED (não é uma negação de papel)', async () => {
    await requireRole('ADMIN')(request(null), reply).catch(() => undefined);

    expect(record).not.toHaveBeenCalled();
  });

  it('permite o papel exigido e listas de papéis', async () => {
    await expect(
      requireRole('ADMIN')(request({ ...user, role: 'ADMIN' }), reply),
    ).resolves.toBeUndefined();
    await expect(requireRole('USER', 'ADMIN')(request(user), reply)).resolves.toBeUndefined();
    expect(record).not.toHaveBeenCalled();
  });
});
