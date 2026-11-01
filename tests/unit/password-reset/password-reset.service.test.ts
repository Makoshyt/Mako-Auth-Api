import { createHash, randomUUID } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuditEventInput } from '../../../src/modules/audit/audit.recorder.js';
import { MemoryMailer } from '../../../src/modules/mail/memory-mailer.js';
import type {
  PasswordResetRepository,
  ResetCompletion,
  ResetTokenRecord,
} from '../../../src/modules/password-reset/password-reset.repository.js';
import {
  createPasswordResetService,
  type PasswordResetService,
} from '../../../src/modules/password-reset/password-reset.service.js';
import { createBackgroundTasks } from '../../../src/shared/background-tasks.js';

const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');
const client = { ip: '203.0.113.9', userAgent: 'vitest' };
const USER = { id: randomUUID(), email: 'bruno.lima@example.com', name: 'Bruno Lima' };
const NEW_PASSWORD = 'nova frase longa e segura';

/** Mesmas regras do repositório Prisma: consumo condicional e invalidação dos demais tokens. */
class InMemoryResetRepository implements PasswordResetRepository {
  readonly users = new Map([[USER.email, USER]]);
  readonly tokens: (Omit<ResetTokenRecord, 'user'> & { tokenHash: string })[] = [];
  passwordHash = 'hash-antigo';
  revokedSessions = 0;
  readonly calls: string[] = [];

  findUserIdByEmail(email: string) {
    this.calls.push('findUserIdByEmail');
    return Promise.resolve(this.users.get(email)?.id ?? null);
  }
  createToken(data: { userId: string; tokenHash: string; expiresAt: Date }) {
    this.tokens.push({ id: randomUUID(), usedAt: null, ...data });
    return Promise.resolve();
  }
  findToken(tokenHash: string) {
    const token = this.tokens.find((t) => t.tokenHash === tokenHash);
    return Promise.resolve(
      token ? { ...token, user: { email: USER.email, name: USER.name } } : null,
    );
  }
  completeReset(data: { tokenId: string; userId: string; passwordHash: string; now: Date }) {
    const token = this.tokens.find((t) => t.id === data.tokenId);
    if (!token || token.usedAt !== null || token.expiresAt <= data.now) {
      return Promise.resolve<ResetCompletion>({ completed: false });
    }
    for (const t of this.tokens)
      if (t.userId === data.userId && t.usedAt === null) t.usedAt = data.now;
    this.passwordHash = data.passwordHash;
    this.revokedSessions = 2;
    return Promise.resolve<ResetCompletion>({ completed: true, revokedSessions: 2 });
  }
}

let clock: Date;
let repository: InMemoryResetRepository;
let mailer: MemoryMailer;
let events: AuditEventInput[];
let tasks: ReturnType<typeof createBackgroundTasks>;
let service: PasswordResetService;
const hashPassword = vi.fn((password: string) =>
  Promise.resolve(`argon2-fake:${sha256(password)}`),
);

beforeEach(() => {
  clock = new Date('2026-11-01T12:00:00.000Z');
  repository = new InMemoryResetRepository();
  mailer = new MemoryMailer();
  events = [];
  tasks = createBackgroundTasks((_name, error) => {
    throw error;
  });
  hashPassword.mockClear();
  service = createPasswordResetService({
    repository,
    hashPassword,
    mailer,
    audit: { record: (event) => (events.push(event), Promise.resolve()) },
    tasks,
    tokenTtlMinutes: 15,
    now: () => clock,
  });
});

async function requestToken(): Promise<string> {
  service.requestReset(USER.email, client);
  await tasks.idle();
  const token = mailer.lastResetToken(USER.email);
  if (!token) throw new Error('nenhum token enviado');
  return token;
}

describe('requestReset', () => {
  it('conta existente: token aleatório de 256 bits enviado por email; no banco só o SHA-256', async () => {
    const token = await requestToken();

    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(repository.tokens).toHaveLength(1);
    expect(repository.tokens[0]?.tokenHash).toBe(sha256(token));
    expect(JSON.stringify(repository.tokens)).not.toContain(token);
    expect(repository.tokens[0]?.expiresAt.toISOString()).toBe('2026-11-01T12:15:00.000Z');
    expect(events).toEqual([
      expect.objectContaining({
        type: 'PASSWORD_RESET_REQUEST',
        userId: USER.id,
        metadata: { outcome: 'TOKEN_ISSUED' },
      }),
    ]);
    expect(JSON.stringify(events)).not.toContain(token);
  });

  it('conta inexistente: nada é gravado nem enviado; só a auditoria interna', async () => {
    service.requestReset('ninguem@example.com', client);
    await tasks.idle();

    expect(repository.tokens).toHaveLength(0);
    expect(mailer.sent).toHaveLength(0);
    expect(events).toEqual([
      expect.objectContaining({
        type: 'PASSWORD_RESET_REQUEST',
        metadata: { outcome: 'UNKNOWN_EMAIL' },
      }),
    ]);
  });

  it('retorna antes de qualquer consulta: o tempo da resposta não depende da conta', async () => {
    service.requestReset(USER.email, client);

    expect(repository.calls).toEqual([]);
    expect(mailer.sent).toHaveLength(0);
    await tasks.idle();
    expect(repository.calls).toEqual(['findUserIdByEmail']);
  });

  it('cada pedido gera um token diferente', async () => {
    const first = await requestToken();
    const second = await requestToken();

    expect(first).not.toBe(second);
  });
});

describe('resetPassword', () => {
  it('sucesso: grava o novo hash, consome o token e audita a revogação das sessões', async () => {
    const token = await requestToken();

    await service.resetPassword(token, NEW_PASSWORD, client);

    expect(hashPassword).toHaveBeenCalledWith(NEW_PASSWORD);
    expect(repository.passwordHash).toBe(`argon2-fake:${sha256(NEW_PASSWORD)}`);
    expect(repository.tokens[0]?.usedAt).toEqual(clock);
    expect(events.at(-1)).toEqual({
      type: 'PASSWORD_RESET_SUCCESS',
      userId: USER.id,
      ip: client.ip,
      metadata: { revokedSessions: 2 },
    });
    expect(JSON.stringify(events)).not.toContain(NEW_PASSWORD);
  });

  it.each([
    ['inexistente', () => Promise.resolve('token-que-nunca-existiu')],
    [
      'já usado',
      async () => {
        const token = await requestToken();
        await service.resetPassword(token, NEW_PASSWORD, client);
        return token;
      },
    ],
    [
      'expirado (15 min)',
      async () => {
        const token = await requestToken();
        clock = new Date(clock.getTime() + 15 * 60_000);
        return token;
      },
    ],
  ])('token %s: 400 INVALID_RESET_TOKEN com a mesma mensagem', async (_label, prepare) => {
    const token = await prepare();

    await expect(
      service.resetPassword(token, 'outra frase longa qualquer', client),
    ).rejects.toMatchObject({
      statusCode: 400,
      code: 'INVALID_RESET_TOKEN',
      message: 'Link de recuperação inválido ou expirado',
    });
  });

  it('ainda vale 1 ms antes de expirar', async () => {
    const token = await requestToken();
    clock = new Date(clock.getTime() + 15 * 60_000 - 1);

    await expect(service.resetPassword(token, NEW_PASSWORD, client)).resolves.toBeUndefined();
  });

  it.each([
    ['curta', 'curta123', 'TOO_SHORT'],
    ['comum', 'Password2024!', 'COMMON_PASSWORD'],
    ['com o email do usuário', 'bruno.lima@example.com', 'CONTAINS_PERSONAL_DATA'],
  ])('senha %s: 400 WEAK_PASSWORD e o token NÃO é consumido', async (_label, password, reason) => {
    const token = await requestToken();

    await expect(service.resetPassword(token, password, client)).rejects.toMatchObject({
      code: 'WEAK_PASSWORD',
      details: { reason },
    });
    expect(repository.tokens[0]?.usedAt).toBeNull();
    expect(hashPassword).not.toHaveBeenCalled();
    await expect(service.resetPassword(token, NEW_PASSWORD, client)).resolves.toBeUndefined();
  });

  it('se outra requisição consumir o token antes, responde token inválido', async () => {
    const token = await requestToken();
    vi.spyOn(repository, 'completeReset').mockResolvedValueOnce({ completed: false });

    await expect(service.resetPassword(token, NEW_PASSWORD, client)).rejects.toMatchObject({
      code: 'INVALID_RESET_TOKEN',
    });
    expect(events.map((e) => e.type)).not.toContain('PASSWORD_RESET_SUCCESS');
  });

  it('o reset consome também os outros tokens ativos da conta', async () => {
    const older = await requestToken();
    const newer = await requestToken();

    await service.resetPassword(newer, NEW_PASSWORD, client);

    await expect(
      service.resetPassword(older, 'outra frase longa qualquer', client),
    ).rejects.toMatchObject({
      code: 'INVALID_RESET_TOKEN',
    });
  });
});
