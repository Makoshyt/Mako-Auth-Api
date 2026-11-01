import type { PrismaClient } from '../../infra/prisma.js';

export interface ResetTokenRecord {
  id: string;
  userId: string;
  expiresAt: Date;
  usedAt: Date | null;
  /** Para a política de senha (a nova senha não pode conter nome ou email). */
  user: { email: string; name: string };
}

export type ResetCompletion = { completed: true; revokedSessions: number } | { completed: false };

export interface PasswordResetRepository {
  findUserIdByEmail(email: string): Promise<string | null>;
  createToken(data: { userId: string; tokenHash: string; expiresAt: Date }): Promise<void>;
  findToken(tokenHash: string): Promise<ResetTokenRecord | null>;
  /**
   * Numa única transação: consome o token (só se ainda válido), grava o novo hash de senha,
   * invalida os demais tokens da conta e revoga todas as sessões. Ou tudo, ou nada.
   */
  completeReset(data: {
    tokenId: string;
    userId: string;
    passwordHash: string;
    now: Date;
  }): Promise<ResetCompletion>;
}

export function createPasswordResetRepository(prisma: PrismaClient): PasswordResetRepository {
  return {
    async findUserIdByEmail(email) {
      const user = await prisma.user.findUnique({ where: { email }, select: { id: true } });
      return user?.id ?? null;
    },

    async createToken({ userId, tokenHash, expiresAt }) {
      await prisma.passwordResetToken.create({ data: { userId, tokenHash, expiresAt } });
    },

    findToken(tokenHash) {
      return prisma.passwordResetToken.findUnique({
        where: { tokenHash },
        select: {
          id: true,
          userId: true,
          expiresAt: true,
          usedAt: true,
          user: { select: { email: true, name: true } },
        },
      });
    },

    completeReset({ tokenId, userId, passwordHash, now }) {
      return prisma.$transaction(async (tx) => {
        // Consumo condicional: com duas requisições simultâneas, a segunda espera o commit da
        // primeira, reavalia o WHERE (used_at já preenchido) e atualiza zero linhas.
        const consumed = await tx.passwordResetToken.updateMany({
          where: { id: tokenId, userId, usedAt: null, expiresAt: { gt: now } },
          data: { usedAt: now },
        });
        if (consumed.count === 0) return { completed: false };

        await tx.user.update({
          where: { id: userId },
          data: { passwordHash, passwordChangedAt: now },
        });
        // Outros links pedidos antes deixam de valer: só um reset por pedido.
        await tx.passwordResetToken.updateMany({
          where: { userId, usedAt: null },
          data: { usedAt: now },
        });
        // Quem estiver logado com a senha antiga (inclusive um invasor) é desconectado.
        const revoked = await tx.session.updateMany({
          where: { userId, revokedAt: null },
          data: { revokedAt: now, revokedReason: 'PASSWORD_RESET' },
        });
        return { completed: true, revokedSessions: revoked.count };
      });
    },
  };
}
