import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createPrismaClient, type PrismaClient } from '../../src/infra/prisma.js';
import { createUsersRepository } from '../../src/modules/users/users.repository.js';
import { createUsersService } from '../../src/modules/users/users.service.js';
import type { ErrorBody } from '../../src/shared/error-handler.js';
import { AppError } from '../../src/shared/errors.js';
import { hashPassword, verifyPassword } from '../../src/shared/password-hasher.js';
import { buildTestApp } from '../helpers/build-test-app.js';
import { TEST_DATABASE_URL } from '../helpers/test-env.js';

/** Todos os dados usam este domínio fictício e são removidos antes e depois. */
const DOMAIN = '@users-test.example.com';
const email = (local: string) => `${local}${DOMAIN}`;
const PASSWORD = 'cavalo correto bateria grampo';

let app: FastifyInstance;
let prisma: PrismaClient;

const register = (payload: Record<string, unknown>) =>
  app.inject({ method: 'POST', url: '/api/v1/auth/register', payload });

beforeAll(async () => {
  app = await buildTestApp();
  prisma = createPrismaClient(TEST_DATABASE_URL);
});

beforeEach(async () => {
  await prisma.user.deleteMany({ where: { email: { endsWith: DOMAIN } } });
});

afterAll(async () => {
  await prisma.user.deleteMany({ where: { email: { endsWith: DOMAIN } } });
  await prisma.$disconnect();
  await app.close();
});

describe('POST /api/v1/auth/register', () => {
  it('201 com dados públicos; persiste no PostgreSQL com papel USER', async () => {
    const response = await register({ name: 'Ana Souza', email: email('ana'), password: PASSWORD });

    expect(response.statusCode).toBe(201);
    const body = response.json<Record<string, unknown>>();
    expect(Object.keys(body).sort()).toEqual(
      ['createdAt', 'email', 'id', 'name', 'role', 'updatedAt'].sort(),
    );
    expect(body).toMatchObject({ name: 'Ana Souza', email: email('ana'), role: 'USER' });

    const stored = await prisma.user.findUniqueOrThrow({ where: { email: email('ana') } });
    expect(stored.id).toBe(body.id);
    expect(stored.role).toBe('USER');
  });

  it('armazena hash Argon2id verificável, nunca a senha', async () => {
    await register({ name: 'Ana Souza', email: email('hash'), password: PASSWORD });

    const stored = await prisma.user.findUniqueOrThrow({ where: { email: email('hash') } });
    expect(stored.passwordHash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    expect(stored.passwordHash).not.toContain(PASSWORD);
    await expect(verifyPassword(stored.passwordHash, PASSWORD)).resolves.toBe(true);
    await expect(verifyPassword(stored.passwordHash, 'outra senha qualquer')).resolves.toBe(false);
  });

  it('nunca devolve password nem passwordHash na resposta', async () => {
    const response = await register({ name: 'Ana', email: email('leak'), password: PASSWORD });

    expect(response.body).not.toContain(PASSWORD);
    expect(response.body).not.toContain('passwordHash');
    expect(response.body).not.toContain('argon2');
  });

  it('normaliza o email antes de gravar', async () => {
    const response = await register({
      name: 'Ana',
      email: `  ANA.Maiuscula${DOMAIN.toUpperCase()}  `,
      password: PASSWORD,
    });

    expect(response.statusCode).toBe(201);
    expect(response.json<{ email: string }>().email).toBe(email('ana.maiuscula'));
  });

  it('409 CONFLICT para email duplicado, inclusive com outra capitalização', async () => {
    await register({ name: 'Ana', email: email('dup'), password: PASSWORD });

    const response = await register({
      name: 'Outra Ana',
      email: email('DUP').toUpperCase(),
      password: PASSWORD,
    });

    expect(response.statusCode).toBe(409);
    expect(response.json<ErrorBody>().error.code).toBe('CONFLICT');
    expect(await prisma.user.count({ where: { email: email('dup') } })).toBe(1);
  });

  it('cadastros simultâneos com o mesmo email: exatamente um 201 e um 409', async () => {
    const payload = { name: 'Corrida', email: email('race'), password: PASSWORD };

    const responses = await Promise.all([register(payload), register(payload)]);

    expect(responses.map((r) => r.statusCode).sort()).toEqual([201, 409]);
  });

  it('400 para nome inválido', async () => {
    for (const name of ['', '   ', 'x'.repeat(101)]) {
      const response = await register({ name, email: email('nome'), password: PASSWORD });

      expect(response.statusCode).toBe(400);
      const { error } = response.json<ErrorBody>();
      expect(error.code).toBe('VALIDATION_ERROR');
      expect(error.details).toEqual([expect.objectContaining({ field: 'body.name' })]);
    }
  });

  it('400 VALIDATION_ERROR para senha curta, sem ecoar a senha', async () => {
    const response = await register({ name: 'Ana', email: email('curta'), password: 'curta123' });

    expect(response.statusCode).toBe(400);
    expect(response.json<ErrorBody>().error.details).toEqual([
      expect.objectContaining({ field: 'body.password' }),
    ]);
    expect(response.body).not.toContain('curta123');
  });

  it('400 WEAK_PASSWORD para senha comum, sem ecoar a senha', async () => {
    const response = await register({
      name: 'Ana',
      email: email('fraca'),
      password: 'Password2024!',
    });

    expect(response.statusCode).toBe(400);
    expect(response.json<ErrorBody>().error).toMatchObject({
      code: 'WEAK_PASSWORD',
      details: { reason: 'COMMON_PASSWORD' },
    });
    expect(response.body).not.toContain('Password2024!');
  });

  it('400 ao tentar se cadastrar como ADMIN; nada é gravado', async () => {
    const response = await register({
      name: 'Mallory',
      email: email('mallory'),
      password: PASSWORD,
      role: 'ADMIN',
    });

    expect(response.statusCode).toBe(400);
    expect(response.json<ErrorBody>().error.code).toBe('VALIDATION_ERROR');
    expect(await prisma.user.count({ where: { email: email('mallory') } })).toBe(0);
  });

  it('400 para campos inesperados', async () => {
    for (const extra of [{ id: crypto.randomUUID() }, { isAdmin: true }, { passwordHash: 'x' }]) {
      const response = await register({
        name: 'Ana',
        email: email('extra'),
        password: PASSWORD,
        ...extra,
      });

      expect(response.statusCode).toBe(400);
    }
    expect(await prisma.user.count({ where: { email: email('extra') } })).toBe(0);
  });

  it('está documentado no OpenAPI', async () => {
    const spec = (await app.inject({ method: 'GET', url: '/docs/json' })).json<{
      paths: Record<string, unknown>;
    }>();

    expect(spec.paths).toHaveProperty('/api/v1/auth/register');
  });
});

describe('rotas de perfil exigem autenticação (ativadas na Etapa 4)', () => {
  it.each(['GET', 'PATCH'] as const)('%s /api/v1/users/me sem token: 401', async (method) => {
    const response = await app.inject({
      method,
      url: '/api/v1/users/me',
      ...(method === 'PATCH' && { payload: { name: 'Tentativa' } }),
    });

    expect(response.statusCode).toBe(401);
    expect(response.json<ErrorBody>().error.code).toBe('UNAUTHORIZED');
  });

  it('não existe rota de perfil que aceite id do cliente', async () => {
    const created = await register({ name: 'Ana', email: email('idor'), password: PASSWORD });
    const { id } = created.json<{ id: string }>();

    expect((await app.inject({ method: 'GET', url: `/api/v1/users/${id}` })).statusCode).toBe(404);
  });

  it('o OpenAPI lista /users/me como protegida; só a área admin recebe id de usuário', async () => {
    const spec = (await app.inject({ method: 'GET', url: '/docs/json' })).json<{
      paths: Record<string, Record<string, { security?: unknown }>>;
    }>();

    const paths = Object.keys(spec.paths);
    expect(paths.filter((path) => path.startsWith('/api/v1/users'))).toEqual(['/api/v1/users/me']);
    // A única rota com id de usuário é administrativa e exige Bearer (o RBAC é testado em admin.test).
    expect(paths.filter((path) => path.includes('{id}'))).toEqual(['/api/v1/admin/users/{id}']);
    expect(spec.paths['/api/v1/admin/users/{id}']?.get?.security).toEqual([{ bearerAuth: [] }]);
    expect(spec.paths['/api/v1/users/me']?.get?.security).toEqual([{ bearerAuth: [] }]);
    expect(spec.paths['/api/v1/users/me']?.patch?.security).toEqual([{ bearerAuth: [] }]);
  });
});

describe('UsersService com repositório Prisma (PostgreSQL real)', () => {
  const service = () =>
    createUsersService({
      usersRepository: createUsersRepository(prisma),
      hashPassword,
      verifyPassword,
      // Este bloco testa a persistência do perfil; a auditoria é verificada em audit.test.ts.
      audit: { record: () => Promise.resolve() },
    });

  it('getProfile retorna o perfil persistido, sem passwordHash', async () => {
    const created = await service().register({
      name: 'Bia',
      email: email('bia'),
      password: PASSWORD,
    });

    const profile = await service().getProfile(created.id);

    expect(profile).toEqual(created);
    expect(profile).not.toHaveProperty('passwordHash');
  });

  it('updateProfile grava name/email e o banco avança updated_at', async () => {
    const created = await service().register({
      name: 'Bia',
      email: email('bia2'),
      password: PASSWORD,
    });
    await new Promise((resolve) => setTimeout(resolve, 5));

    const updated = await service().updateProfile(created.id, {
      name: 'Beatriz',
      email: email('beatriz'),
      currentPassword: PASSWORD,
    });

    const row = await prisma.user.findUniqueOrThrow({ where: { id: created.id } });
    expect(row).toMatchObject({ name: 'Beatriz', email: email('beatriz'), role: 'USER' });
    expect(updated.updatedAt.getTime()).toBeGreaterThan(created.updatedAt.getTime());
    expect(row.createdAt).toEqual(created.createdAt);
  });

  it('updateProfile ignora role e passwordHash forjados', async () => {
    const created = await service().register({
      name: 'Bia',
      email: email('bia3'),
      password: PASSWORD,
    });
    const before = await prisma.user.findUniqueOrThrow({ where: { id: created.id } });

    await service().updateProfile(created.id, {
      name: 'Bia Admin?',
      role: 'ADMIN',
      passwordHash: 'forjado',
    } as Parameters<ReturnType<typeof service>['updateProfile']>[1]);

    const after = await prisma.user.findUniqueOrThrow({ where: { id: created.id } });
    expect(after.role).toBe('USER');
    expect(after.passwordHash).toBe(before.passwordHash);
  });

  it('updateProfile: 409 ao usar email de outro usuário (índice único do banco)', async () => {
    const bia = await service().register({ name: 'Bia', email: email('bia4'), password: PASSWORD });
    await service().register({ name: 'Caio', email: email('caio'), password: PASSWORD });

    const error = await service()
      .updateProfile(bia.id, { email: email('caio'), currentPassword: PASSWORD })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(AppError);
    expect(error).toMatchObject({ statusCode: 409, code: 'CONFLICT' });
  });

  it('getProfile e updateProfile: 404 para usuário inexistente', async () => {
    const missing = '0190a000-0000-7000-8000-000000000000';

    await expect(service().getProfile(missing)).rejects.toMatchObject({ statusCode: 404 });
    await expect(service().updateProfile(missing, { name: 'X' })).rejects.toMatchObject({
      statusCode: 404,
    });
  });
});
