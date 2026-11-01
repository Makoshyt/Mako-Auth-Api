import { createHash } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createUsersService, type UsersService } from '../../../src/modules/users/users.service.js';
import type { AuditEventInput } from '../../../src/modules/audit/audit.recorder.js';
import type { RegisterInput, UpdateProfileInput } from '../../../src/modules/users/users.types.js';
import { AppError } from '../../../src/shared/errors.js';
import { InMemoryUsersRepository } from '../../helpers/in-memory-users-repository.js';

/**
 * Hasher falso e rápido: os testes do service não dependem do custo do Argon2.
 * Determinístico e sem conter a senha, para que o verificador falso funcione de verdade.
 */
const fakeHashSync = (password: string) =>
  `fake-sha256:${createHash('sha256').update(password).digest('hex')}`;
const fakeHash = (password: string) => Promise.resolve(fakeHashSync(password));
const fakeVerify = (encoded: string, password: string) =>
  Promise.resolve(encoded === fakeHashSync(password));

const input: RegisterInput = {
  name: 'Bruno Lima',
  email: 'bruno.lima@example.com',
  password: 'cavalo correto bateria grampo',
};

async function expectAppError(promise: Promise<unknown>, statusCode: number, code: string) {
  const error = await promise.then(
    () => {
      throw new Error('era esperado um AppError');
    },
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(AppError);
  expect(error).toMatchObject({ statusCode, code });
  return error as AppError;
}

let repository: InMemoryUsersRepository;
let service: UsersService;
let hashPassword: ReturnType<typeof vi.fn<typeof fakeHash>>;
let events: AuditEventInput[];

beforeEach(() => {
  repository = new InMemoryUsersRepository();
  hashPassword = vi.fn(fakeHash);
  events = [];
  service = createUsersService({
    usersRepository: repository,
    hashPassword,
    verifyPassword: fakeVerify,
    audit: {
      record: (event) => {
        events.push(event);
        return Promise.resolve();
      },
    },
  });
});

describe('UsersService.register', () => {
  it('cria o usuário com papel USER e retorna só dados públicos', async () => {
    const user = await service.register(input);

    expect(user).toMatchObject({ name: input.name, email: input.email, role: 'USER' });
    expect(user).not.toHaveProperty('passwordHash');
    expect(user).not.toHaveProperty('password');
  });

  it('armazena o hash produzido pelo hasher, nunca a senha', async () => {
    const user = await service.register(input);

    expect(hashPassword).toHaveBeenCalledWith(input.password);
    const stored = repository.stored.get(user.id);
    expect(stored?.passwordHash).toBe(fakeHashSync(input.password));
    expect(JSON.stringify(stored)).not.toContain(input.password);
  });

  it('ignora role mesmo que o chamador force o campo (defesa além do schema)', async () => {
    const forged = { ...input, role: 'ADMIN' } as RegisterInput;

    const user = await service.register(forged);

    expect(user.role).toBe('USER');
  });

  it('409 CONFLICT para email já cadastrado', async () => {
    await service.register(input);

    await expectAppError(service.register({ ...input, name: 'Outra Pessoa' }), 409, 'CONFLICT');
  });

  it('400 WEAK_PASSWORD para senha comum, sem gastar hash', async () => {
    const error = await expectAppError(
      service.register({ ...input, password: 'Password2024!' }),
      400,
      'WEAK_PASSWORD',
    );

    expect(error.details).toEqual({ reason: 'COMMON_PASSWORD' });
    expect(hashPassword).not.toHaveBeenCalled();
  });

  it('400 WEAK_PASSWORD para senha curta (o service valida mesmo fora do HTTP)', async () => {
    const error = await expectAppError(
      service.register({ ...input, password: 'curta' }),
      400,
      'WEAK_PASSWORD',
    );

    expect(error.details).toEqual({ reason: 'TOO_SHORT' });
  });

  it('400 WEAK_PASSWORD quando a senha contém o email do usuário', async () => {
    const error = await expectAppError(
      service.register({ ...input, password: 'bruno.lima@example.com' }),
      400,
      'WEAK_PASSWORD',
    );

    expect(error.details).toEqual({ reason: 'CONTAINS_PERSONAL_DATA' });
  });

  it('a mensagem de erro nunca contém a senha enviada', async () => {
    const password = 'Password2024!';
    const error = await expectAppError(
      service.register({ ...input, password }),
      400,
      'WEAK_PASSWORD',
    );

    expect(JSON.stringify({ message: error.message, details: error.details })).not.toContain(
      password,
    );
  });
});

describe('UsersService.getProfile', () => {
  it('retorna o próprio perfil pelo id autenticado', async () => {
    const created = await service.register(input);

    const profile = await service.getProfile(created.id);

    expect(profile).toEqual(created);
    expect(profile).not.toHaveProperty('passwordHash');
  });

  it('404 NOT_FOUND para usuário inexistente', async () => {
    await expectAppError(
      service.getProfile('0190a000-0000-7000-8000-000000000000'),
      404,
      'NOT_FOUND',
    );
  });
});

describe('UsersService.updateProfile', () => {
  it('atualiza nome e email e avança updatedAt', async () => {
    const created = await service.register(input);

    const updated = await service.updateProfile(created.id, {
      name: 'Bruno L. Lima',
      email: 'bruno.novo@example.com',
      currentPassword: input.password,
    });

    expect(updated).toMatchObject({ name: 'Bruno L. Lima', email: 'bruno.novo@example.com' });
    expect(updated.updatedAt.getTime()).toBeGreaterThan(created.updatedAt.getTime());
    expect(updated.createdAt).toEqual(created.createdAt);
  });

  it('não altera role nem senha, mesmo que o chamador force os campos', async () => {
    const created = await service.register(input);
    const hashBefore = repository.stored.get(created.id)?.passwordHash;
    const forged = {
      name: 'Bruno Hacker',
      role: 'ADMIN',
      passwordHash: 'hash-forjado',
    } as UpdateProfileInput;

    const updated = await service.updateProfile(created.id, forged);

    expect(updated.role).toBe('USER');
    expect(updated.name).toBe('Bruno Hacker');
    expect(repository.stored.get(created.id)?.passwordHash).toBe(hashBefore);
  });

  it('400 quando não há nenhum campo permitido para atualizar', async () => {
    const created = await service.register(input);

    await expectAppError(
      service.updateProfile(created.id, { role: 'ADMIN' } as UpdateProfileInput),
      400,
      'BAD_REQUEST',
    );
  });

  it('409 CONFLICT ao trocar para o email de outro usuário', async () => {
    const bruno = await service.register(input);
    await service.register({ ...input, email: 'carla.dias@example.com', name: 'Carla Dias' });

    await expectAppError(
      service.updateProfile(bruno.id, {
        email: 'carla.dias@example.com',
        currentPassword: input.password,
      }),
      409,
      'CONFLICT',
    );
  });

  it('permite "trocar" para o próprio email atual', async () => {
    const created = await service.register(input);

    await expect(
      service.updateProfile(created.id, { email: input.email, currentPassword: input.password }),
    ).resolves.toMatchObject({ email: input.email });
    // O email não mudou de fato: nenhuma sessão é revogada.
    expect(repository.updateOptions.at(-1)).toEqual({});
  });

  it('troca de email: revoga as demais sessões e preserva a atual', async () => {
    const created = await service.register(input);

    await service.updateProfile(
      created.id,
      { email: 'bruno.novo@example.com', currentPassword: input.password },
      { currentSessionId: 'sessao-atual' },
    );

    expect(repository.updateOptions.at(-1)).toEqual({
      revokeOtherSessions: { keepSessionId: 'sessao-atual' },
    });
  });

  it('trocar só o nome não exige senha nem revoga sessões', async () => {
    const created = await service.register(input);

    await service.updateProfile(created.id, { name: 'Bruno Lima Jr.' });

    expect(repository.updateOptions.at(-1)).toEqual({});
  });

  it('400 CURRENT_PASSWORD_REQUIRED ao trocar email sem a senha atual', async () => {
    const created = await service.register(input);

    await expectAppError(
      service.updateProfile(created.id, { email: 'bruno.novo@example.com' }),
      400,
      'CURRENT_PASSWORD_REQUIRED',
    );
  });

  it('403 INVALID_CURRENT_PASSWORD com senha atual errada; nada é alterado', async () => {
    const created = await service.register(input);

    await expectAppError(
      service.updateProfile(created.id, {
        email: 'bruno.novo@example.com',
        currentPassword: 'senha errada mas comprida',
      }),
      403,
      'INVALID_CURRENT_PASSWORD',
    );
    expect(repository.stored.get(created.id)?.email).toBe(input.email);
    expect(repository.updateOptions).toEqual([]);
  });

  it('404 NOT_FOUND para usuário inexistente', async () => {
    await expectAppError(
      service.updateProfile('0190a000-0000-7000-8000-000000000000', { name: 'Ninguém' }),
      404,
      'NOT_FOUND',
    );
  });
});

describe('UsersService: auditoria de perfil', () => {
  const ip = '203.0.113.5';

  it('PROFILE_UPDATED depois de gravar, com os campos e sem os valores', async () => {
    const created = await service.register(input);

    await service.updateProfile(
      created.id,
      { name: 'Bruno Novo', email: 'bruno.novo@example.com', currentPassword: input.password },
      { currentSessionId: 's1', ip },
    );

    expect(events).toEqual([
      {
        type: 'PROFILE_UPDATED',
        userId: created.id,
        ip,
        metadata: { fields: 'email,name', emailChanged: true, otherSessionsRevoked: true },
      },
    ]);
    const stored = JSON.stringify(events);
    expect(stored).not.toContain('bruno.novo@example.com');
    expect(stored).not.toContain('Bruno Novo');
    expect(stored).not.toContain(input.password);
  });

  it('só o nome: emailChanged false e nenhuma sessão revogada', async () => {
    const created = await service.register(input);

    await service.updateProfile(created.id, { name: 'Bruno L.' }, { ip });

    expect(events.at(-1)?.metadata).toEqual({
      fields: 'name',
      emailChanged: false,
      otherSessionsRevoked: false,
    });
  });

  it('senha atual errada: PROFILE_UPDATE_DENIED e nenhum PROFILE_UPDATED', async () => {
    const created = await service.register(input);

    await service
      .updateProfile(
        created.id,
        { email: 'x@example.com', currentPassword: 'senha errada longa' },
        { ip },
      )
      .catch(() => undefined);

    expect(events).toEqual([
      {
        type: 'PROFILE_UPDATE_DENIED',
        userId: created.id,
        ip,
        metadata: { reason: 'INVALID_CURRENT_PASSWORD' },
      },
    ]);
    expect(JSON.stringify(events)).not.toContain('x@example.com');
  });

  it('email em uso: PROFILE_UPDATE_DENIED (EMAIL_IN_USE) e nenhum PROFILE_UPDATED', async () => {
    const bruno = await service.register(input);
    await service.register({ ...input, email: 'carla@example.com', name: 'Carla Dias' });

    await service
      .updateProfile(
        bruno.id,
        { email: 'carla@example.com', currentPassword: input.password },
        { ip },
      )
      .catch(() => undefined);

    expect(events.map((e) => [e.type, e.metadata])).toEqual([
      ['PROFILE_UPDATE_DENIED', { reason: 'EMAIL_IN_USE' }],
    ]);
  });

  it('validação recusada antes de qualquer gravação não gera evento', async () => {
    const created = await service.register(input);

    await service.updateProfile(created.id, {}).catch(() => undefined);
    await service.updateProfile(created.id, { email: 'novo@example.com' }).catch(() => undefined);

    expect(events).toEqual([]);
  });
});
