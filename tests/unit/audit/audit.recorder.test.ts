import { describe, expect, it, vi } from 'vitest';
import type { PrismaClient } from '../../../src/infra/prisma.js';
import { createAuditRecorder, hashEmail } from '../../../src/modules/audit/audit.recorder.js';

const fakePrisma = (create: (args: unknown) => Promise<unknown>) =>
  ({ auditEvent: { create } }) as unknown as PrismaClient;

describe('AuditRecorder', () => {
  it('grava o SHA-256 do email, nunca o email', async () => {
    const create = vi.fn((_args: unknown) => Promise.resolve({}));
    const recorder = createAuditRecorder(fakePrisma(create), () => undefined);

    await recorder.record({
      type: 'LOGIN_FAILURE',
      email: 'ana@example.com',
      ip: '203.0.113.1',
      metadata: { reason: 'UNKNOWN_EMAIL' },
    });

    expect(create).toHaveBeenCalledWith({
      data: {
        type: 'LOGIN_FAILURE',
        userId: null,
        emailHash: hashEmail('ana@example.com'),
        ip: '203.0.113.1',
        metadata: { reason: 'UNKNOWN_EMAIL' },
      },
    });
    expect(JSON.stringify(create.mock.calls)).not.toContain('ana@example.com');
  });

  it('falha ao gravar: não lança (o fluxo segue) e entrega o erro só ao onError', async () => {
    const dbError = new Error('connection refused at 10.0.0.5:5432 (detalhe interno)');
    const onError = vi.fn();
    const recorder = createAuditRecorder(
      fakePrisma(() => Promise.reject(dbError)),
      onError,
    );

    await expect(recorder.record({ type: 'ACCESS_DENIED', userId: null })).resolves.toBeUndefined();
    expect(onError).toHaveBeenCalledWith(dbError);
  });
});
