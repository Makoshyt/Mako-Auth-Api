import { createHash } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuditEventInput, AuditRecorder } from '../../../src/modules/audit/audit.recorder.js';
import { createAuthService, type AuthService } from '../../../src/modules/auth/auth.service.js';
import type { ClientInfo } from '../../../src/modules/auth/auth.types.js';
import { createAccessTokenSigner } from '../../../src/modules/auth/tokens.js';
import { AppError } from '../../../src/shared/errors.js';
import { InMemoryAuthRepository } from '../../helpers/in-memory-auth-repository.js';

const SECRET = 'segredo-ficticio-de-teste-com-32-caracteres-ou-mais';
const PASSWORD = 'cavalo correto bateria grampo';
const client: ClientInfo = { ip: '203.0.113.10', userAgent: 'vitest' };
const USER_ID = '0190a000-0000-7000-8000-0000000000aa';

const fakeHashSync = (password: string) =>
  `fake-sha256:${createHash('sha256').update(password).digest('hex')}`;

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

let clock: Date;
let repository: InMemoryAuthRepository;
let events: AuditEventInput[];
let verifyPassword: ReturnType<
  typeof vi.fn<(encoded: string, password: string) => Promise<boolean>>
>;
let service: AuthService;

const advance = (ms: number) => {
  clock = new Date(clock.getTime() + ms);
};

beforeEach(() => {
  clock = new Date('2026-06-01T12:00:00.000Z');
  repository = new InMemoryAuthRepository();
  repository.addUser({
    id: USER_ID,
    email: 'bruno.lima@example.com',
    role: 'USER',
    passwordHash: fakeHashSync(PASSWORD),
  });
  events = [];
  const audit: AuditRecorder = {
    record: (event) => {
      events.push(event);
      return Promise.resolve();
    },
  };
  verifyPassword = vi.fn((encoded: string, password: string) =>
    Promise.resolve(encoded === fakeHashSync(password)),
  );
  service = createAuthService({
    authRepository: repository,
    accessTokens: createAccessTokenSigner(SECRET, 900),
    hashPassword: (password) => Promise.resolve(fakeHashSync(password)),
    verifyPassword,
    audit,
    config: { refreshTokenTtlDays: 7, sessionAbsoluteTtlDays: 30, refreshReuseGraceSeconds: 10 },
    now: () => clock,
  });
});

const login = () => service.login('bruno.lima@example.com', PASSWORD, client);

describe('AuthService.login', () => {
  it('cria a sessão e devolve access token + refresh token', async () => {
    const pair = await login();

    expect(pair).toMatchObject({ tokenType: 'Bearer', expiresIn: 900 });
    expect(repository.sessions.size).toBe(1);
    const [session] = repository.sessions.values();
    expect(session).toMatchObject({ userId: USER_ID, revokedAt: null, client });
    expect(session?.expiresAt.toISOString()).toBe('2026-07-01T12:00:00.000Z');
    expect(pair.refreshTokenExpiresAt.toISOString()).toBe('2026-06-08T12:00:00.000Z');
    expect(events).toEqual([expect.objectContaining({ type: 'LOGIN_SUCCESS', userId: USER_ID })]);
  });

  it('guarda apenas o hash do refresh token', async () => {
    const { refreshToken } = await login();

    const [stored] = repository.tokens.values();
    expect(stored?.tokenHash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify([...repository.tokens.values()])).not.toContain(refreshToken);
  });

  it('senha errada: 401 INVALID_CREDENTIALS, sem sessão, com auditoria', async () => {
    const error = await expectAppError(
      service.login('bruno.lima@example.com', 'senha errada porém longa', client),
      401,
      'INVALID_CREDENTIALS',
    );

    expect(error.message).toBe('Email ou senha inválidos');
    expect(repository.sessions.size).toBe(0);
    expect(events).toEqual([
      expect.objectContaining({
        type: 'LOGIN_FAILURE',
        userId: USER_ID,
        metadata: { reason: 'INVALID_PASSWORD' },
      }),
    ]);
  });

  it('email inexistente: mesma resposta e verificação contra hash fictício', async () => {
    const error = await expectAppError(
      service.login('ninguem@example.com', PASSWORD, client),
      401,
      'INVALID_CREDENTIALS',
    );

    expect(error.message).toBe('Email ou senha inválidos');
    // O Argon2id roda mesmo sem conta: o tempo de resposta não denuncia o email.
    expect(verifyPassword).toHaveBeenCalledTimes(1);
    expect(verifyPassword.mock.calls[0]?.[1]).toBe(PASSWORD);
    expect(events).toEqual([
      expect.objectContaining({ type: 'LOGIN_FAILURE', metadata: { reason: 'UNKNOWN_EMAIL' } }),
    ]);
  });

  it('os eventos de auditoria nunca contêm a senha', async () => {
    await service.login('bruno.lima@example.com', 'senha errada porém longa', client).catch(() => {
      // esperado
    });
    await login();

    expect(JSON.stringify(events)).not.toContain(PASSWORD);
    expect(JSON.stringify(events)).not.toContain('senha errada porém longa');
  });
});

describe('AuthService.authenticate', () => {
  it('aceita o access token de uma sessão ativa', async () => {
    const { accessToken } = await login();

    const auth = await service.authenticate(accessToken);

    expect(auth).toMatchObject({ userId: USER_ID, role: 'USER' });
    expect(repository.sessions.has(auth.sessionId)).toBe(true);
  });

  it('usa o papel ATUAL do banco, não o do token', async () => {
    const { accessToken } = await login();
    const user = repository.users.get(USER_ID);
    if (user) user.role = 'ADMIN';

    await expect(service.authenticate(accessToken)).resolves.toMatchObject({ role: 'ADMIN' });
  });

  it('401 TOKEN_EXPIRED depois de 15 minutos', async () => {
    const { accessToken } = await login();
    advance(15 * 60 * 1000);

    await expectAppError(service.authenticate(accessToken), 401, 'TOKEN_EXPIRED');
  });

  it('401 INVALID_TOKEN para token inválido', async () => {
    await expectAppError(service.authenticate('x.y.z'), 401, 'INVALID_TOKEN');
  });

  it('401 INVALID_SESSION para sessão revogada, mesmo com o JWT ainda no prazo', async () => {
    const { accessToken } = await login();
    const auth = await service.authenticate(accessToken);
    await service.logout(auth, client);

    await expectAppError(service.authenticate(accessToken), 401, 'INVALID_SESSION');
  });

  it('401 INVALID_SESSION para sessão expirada', async () => {
    const { accessToken } = await login();
    const [session] = repository.sessions.values();
    if (session) session.expiresAt = new Date(clock.getTime() - 1);

    await expectAppError(service.authenticate(accessToken), 401, 'INVALID_SESSION');
  });

  it('401 INVALID_SESSION se a sessão não existir mais (usuário excluído)', async () => {
    const { accessToken } = await login();
    repository.sessions.clear();

    await expectAppError(service.authenticate(accessToken), 401, 'INVALID_SESSION');
  });
});

describe('AuthService.refresh', () => {
  it('rotaciona: devolve um par novo e o token antigo deixa de valer', async () => {
    const first = await login();
    advance(1000);

    const second = await service.refresh(first.refreshToken, client);

    expect(second.refreshToken).not.toBe(first.refreshToken);
    expect(second.accessToken).not.toBe(first.accessToken);
    await expect(service.authenticate(second.accessToken)).resolves.toMatchObject({
      userId: USER_ID,
    });
    expect([...repository.tokens.values()].filter((t) => t.usedAt === null)).toHaveLength(1);
  });

  it('401 INVALID_REFRESH_TOKEN para token desconhecido', async () => {
    await expectAppError(
      service.refresh('token-que-nunca-existiu', client),
      401,
      'INVALID_REFRESH_TOKEN',
    );
  });

  it('reuso dentro da janela de 10 s: 409, nenhum token emitido, sessão preservada', async () => {
    const first = await login();
    const second = await service.refresh(first.refreshToken, client);
    advance(9_999);

    await expectAppError(
      service.refresh(first.refreshToken, client),
      409,
      'REFRESH_TOKEN_ALREADY_ROTATED',
    );

    const [session] = repository.sessions.values();
    expect(session?.revokedAt).toBeNull();
    expect(repository.tokens.size).toBe(2);
    expect(events.map((event) => event.type)).not.toContain('TOKEN_REUSE_DETECTED');
    // O par vencedor continua funcionando.
    await expect(service.refresh(second.refreshToken, client)).resolves.toBeTruthy();
  });

  it('reuso fora da janela: 401, sessão revogada e evento TOKEN_REUSE_DETECTED', async () => {
    const first = await login();
    const second = await service.refresh(first.refreshToken, client);
    advance(10_000);

    await expectAppError(service.refresh(first.refreshToken, client), 401, 'REFRESH_TOKEN_REUSED');

    const [session] = repository.sessions.values();
    expect(session).toMatchObject({ revokedReason: 'TOKEN_REUSE' });
    expect(events).toContainEqual(
      expect.objectContaining({ type: 'TOKEN_REUSE_DETECTED', userId: USER_ID }),
    );
    // A família inteira cai: o token "legítimo" mais recente também.
    await expectAppError(
      service.refresh(second.refreshToken, client),
      401,
      'INVALID_REFRESH_TOKEN',
    );
    await expectAppError(service.authenticate(second.accessToken), 401, 'INVALID_SESSION');
  });

  it('com janela 0, toda reutilização revoga (modo estrito)', async () => {
    const strict = createAuthService({
      authRepository: repository,
      accessTokens: createAccessTokenSigner(SECRET, 900),
      hashPassword: (password) => Promise.resolve(fakeHashSync(password)),
      verifyPassword,
      audit: { record: () => Promise.resolve() },
      config: { refreshTokenTtlDays: 7, sessionAbsoluteTtlDays: 30, refreshReuseGraceSeconds: 0 },
      now: () => clock,
    });
    const first = await strict.login('bruno.lima@example.com', PASSWORD, client);
    await strict.refresh(first.refreshToken, client);

    await expectAppError(strict.refresh(first.refreshToken, client), 401, 'REFRESH_TOKEN_REUSED');
  });

  it('a rotação nunca estende a validade absoluta da sessão', async () => {
    let pair = await login();
    // 29 dias e meio depois, rotacionando a cada 3 dias.
    for (let day = 0; day < 9; day++) {
      advance(3 * 24 * 60 * 60 * 1000);
      pair = await service.refresh(pair.refreshToken, client);
    }
    advance(2.5 * 24 * 60 * 60 * 1000);
    pair = await service.refresh(pair.refreshToken, client);

    expect(pair.refreshTokenExpiresAt.toISOString()).toBe('2026-07-01T12:00:00.000Z');
    advance(12 * 60 * 60 * 1000); // passa dos 30 dias
    await expectAppError(service.refresh(pair.refreshToken, client), 401, 'INVALID_REFRESH_TOKEN');
  });

  it('401 para refresh token de sessão revogada por logout', async () => {
    const pair = await login();
    await service.logout(await service.authenticate(pair.accessToken), client);

    await expectAppError(service.refresh(pair.refreshToken, client), 401, 'INVALID_REFRESH_TOKEN');
  });

  it('401 para refresh token expirado (7 dias sem uso)', async () => {
    const pair = await login();
    advance(7 * 24 * 60 * 60 * 1000);

    await expectAppError(service.refresh(pair.refreshToken, client), 401, 'INVALID_REFRESH_TOKEN');
  });
});

describe('AuthService.logout / logoutAll', () => {
  it('logout revoga só a sessão atual e é idempotente', async () => {
    const a = await login();
    const b = await login();
    const auth = await service.authenticate(a.accessToken);

    await service.logout(auth, client);
    await service.logout(auth, client); // repetição não falha nem gera evento duplicado

    await expectAppError(service.authenticate(a.accessToken), 401, 'INVALID_SESSION');
    await expect(service.authenticate(b.accessToken)).resolves.toBeTruthy();
    expect(events.filter((event) => event.type === 'LOGOUT')).toHaveLength(1);
  });

  it('logoutAll revoga todas as sessões do usuário', async () => {
    const a = await login();
    const b = await login();

    const revoked = await service.logoutAll(await service.authenticate(a.accessToken), client);

    expect(revoked).toBe(2);
    await expectAppError(service.authenticate(a.accessToken), 401, 'INVALID_SESSION');
    await expectAppError(service.authenticate(b.accessToken), 401, 'INVALID_SESSION');
  });

  it('não revoga sessão de outro usuário, mesmo com o sessionId dela', async () => {
    const victim = await login();
    const victimAuth = await service.authenticate(victim.accessToken);

    await service.logout({ ...victimAuth, userId: '0190a000-0000-7000-8000-0000000000bb' }, client);

    await expect(service.authenticate(victim.accessToken)).resolves.toBeTruthy();
  });
});
