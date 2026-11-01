import { createHash } from 'node:crypto';
import type { AuditEventType } from '../../generated/prisma/enums.js';
import type { PrismaClient } from '../../infra/prisma.js';

export interface AuditEventInput {
  type: AuditEventType;
  userId?: string | null;
  /** Email já normalizado. Só o hash é gravado. */
  email?: string;
  ip?: string | null;
  /** Contexto mínimo. Nunca inclua senhas, tokens ou segredos aqui. */
  metadata?: Record<string, string | number | boolean>;
}

export interface AuditRecorder {
  record(event: AuditEventInput): Promise<void>;
}

export const hashEmail = (email: string) =>
  createHash('sha256').update(email, 'utf8').digest('hex');

/**
 * Grava eventos de auditoria em modo best effort: uma falha ao auditar é registrada no log,
 * mas não derruba o login nem o logout (o usuário não deve ser bloqueado por isso).
 */
export function createAuditRecorder(
  prisma: PrismaClient,
  onError: (error: unknown) => void,
): AuditRecorder {
  return {
    async record({ type, userId, email, ip, metadata }) {
      try {
        await prisma.auditEvent.create({
          data: {
            type,
            userId: userId ?? null,
            emailHash: email === undefined ? null : hashEmail(email),
            ip: ip ?? null,
            ...(metadata && { metadata }),
          },
        });
      } catch (error) {
        onError(error);
      }
    },
  };
}
