import { createHash } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createPrismaClient, type PrismaClient } from '../../src/infra/prisma.js';
import { TEST_DATABASE_URL } from '../helpers/test-env.js';
import { purgeAuditEvents } from '../helpers/purge-audit-events.js';

/**
 * Verifica, no PostgreSQL real, as restrições da migration init:
 * relacionamentos, cascatas, índices únicos (inclusive o parcial) e CHECKs manuais.
 * Todos os dados usam o domínio fictício db-test.example.com e são removidos ao final.
 */
const DOMAIN = '@db-test.example.com';
const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

let prisma: PrismaClient;

async function cleanup(): Promise<void> {
  await prisma.securityAlert.deleteMany({ where: { fingerprint: { startsWith: 'db-test:' } } });
  await purgeAuditEvents(prisma, {
    where: { metadata: { path: ['suite'], equals: 'db-test' } },
  });
  await prisma.user.deleteMany({ where: { email: { endsWith: DOMAIN } } });
}

function createUser(local: string) {
  return prisma.user.create({
    data: { email: `${local}${DOMAIN}`, name: 'Usuário Fictício', passwordHash: 'hash-ficticio' },
  });
}

/** Serializa o erro da violação para checar código/constraint, independente de como o adapter o embrulha. */
async function errorText(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    return JSON.stringify(error, Object.getOwnPropertyNames(error));
  }
  throw new Error('era esperada uma violação de restrição');
}

beforeAll(async () => {
  prisma = createPrismaClient(TEST_DATABASE_URL);
  await cleanup();
});

afterAll(async () => {
  await cleanup();
  await prisma.$disconnect();
});

describe('users', () => {
  it('gera id UUID v7 e aplica padrões (role USER, timestamps)', async () => {
    const user = await createUser('defaults');

    expect(user.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-/);
    expect(user.role).toBe('USER');
    expect(user.createdAt).toBeInstanceOf(Date);
  });

  it('impede emails duplicados (índice único)', async () => {
    await createUser('duplicado');

    expect(await errorText(createUser('duplicado'))).toMatch(/P2002|unique/i);
  });

  it('CHECK: rejeita email não normalizado, mesmo que a aplicação falhe em normalizar', async () => {
    const error = await errorText(
      prisma.user.create({
        data: { email: `Maiusculo${DOMAIN}`, name: 'X', passwordHash: 'h' },
      }),
    );

    expect(error).toContain('users_email_normalized_chk');
  });
});

describe('sessions e refresh tokens', () => {
  it('CHECK: revoked_at e revoked_reason andam juntos', async () => {
    const user = await createUser('sessao-check');
    const expiresAt = new Date(Date.now() + 60_000);

    const error = await errorText(
      prisma.session.create({ data: { userId: user.id, expiresAt, revokedAt: new Date() } }),
    );
    expect(error).toContain('sessions_revocation_consistent_chk');

    await expect(
      prisma.session.create({
        data: { userId: user.id, expiresAt, revokedAt: new Date(), revokedReason: 'LOGOUT' },
      }),
    ).resolves.toBeDefined();
  });

  it('CHECK: token_hash precisa ser SHA-256 em hexadecimal', async () => {
    const user = await createUser('token-hash');
    const session = await prisma.session.create({
      data: { userId: user.id, expiresAt: new Date(Date.now() + 60_000) },
    });

    const error = await errorText(
      prisma.refreshToken.create({
        data: { sessionId: session.id, tokenHash: 'token-em-texto-puro', expiresAt: new Date() },
      }),
    );
    expect(error).toContain('refresh_tokens_token_hash_hex_chk');
  });

  it('excluir o usuário remove sessões e tokens em cascata', async () => {
    const user = await createUser('cascata');
    const session = await prisma.session.create({
      data: { userId: user.id, expiresAt: new Date(Date.now() + 60_000) },
    });
    await prisma.refreshToken.create({
      data: { sessionId: session.id, tokenHash: sha256('rt-ficticio'), expiresAt: new Date() },
    });

    await prisma.user.delete({ where: { id: user.id } });

    expect(await prisma.session.count({ where: { id: session.id } })).toBe(0);
    expect(await prisma.refreshToken.count({ where: { sessionId: session.id } })).toBe(0);
  });
});

describe('audit events', () => {
  it('preservam o histórico quando o usuário é excluído (user_id vira NULL)', async () => {
    const user = await createUser('auditoria');
    const event = await prisma.auditEvent.create({
      data: { type: 'LOGIN_SUCCESS', userId: user.id, metadata: { suite: 'db-test' } },
    });

    await prisma.user.delete({ where: { id: user.id } });

    const after = await prisma.auditEvent.findUniqueOrThrow({ where: { id: event.id } });
    expect(after.userId).toBeNull();
  });
});

describe('security alerts', () => {
  const base = {
    rule: 'BRUTE_FORCE_ACCOUNT',
    severity: 'MEDIUM',
    summary: 'Alerta fictício',
    details: { failures: 5 },
    firstSeenAt: new Date(),
    lastSeenAt: new Date(),
  } as const;

  it('índice parcial: no máximo um alerta OPEN por fingerprint', async () => {
    await prisma.securityAlert.create({ data: { ...base, fingerprint: 'db-test:a' } });

    const error = await errorText(
      prisma.securityAlert.create({ data: { ...base, fingerprint: 'db-test:a' } }),
    );
    expect(error).toMatch(/P2002|unique/i);
  });

  it('índice parcial: alertas RESOLVED com o mesmo fingerprint são permitidos', async () => {
    const resolved = { ...base, status: 'RESOLVED', resolvedAt: new Date() } as const;
    await prisma.securityAlert.create({ data: { ...resolved, fingerprint: 'db-test:b' } });
    await prisma.securityAlert.create({ data: { ...resolved, fingerprint: 'db-test:b' } });

    await expect(
      prisma.securityAlert.create({ data: { ...base, fingerprint: 'db-test:b' } }),
    ).resolves.toBeDefined();
  });

  it('CHECK: status RESOLVED exige resolved_at', async () => {
    const error = await errorText(
      prisma.securityAlert.create({
        data: { ...base, fingerprint: 'db-test:c', status: 'RESOLVED' },
      }),
    );
    expect(error).toContain('security_alerts_resolution_consistent_chk');
  });
});
