import type { Prisma } from '../../generated/prisma/client.js';
import type { PrismaClient } from '../../infra/prisma.js';
import type { AuthRepository, SessionState } from './auth.types.js';

const sessionStateSelect = {
  id: true,
  userId: true,
  expiresAt: true,
  revokedAt: true,
  user: { select: { role: true } },
} as const satisfies Prisma.SessionSelect;

type SessionRow = Prisma.SessionGetPayload<{ select: typeof sessionStateSelect }>;

const toSessionState = ({ user, ...session }: SessionRow): SessionState => ({
  ...session,
  role: user.role,
});

export function createAuthRepository(prisma: PrismaClient): AuthRepository {
  return {
    findCredentialsByEmail(email) {
      return prisma.user.findUnique({
        where: { email },
        select: { id: true, role: true, passwordHash: true },
      });
    },

    async createSession({ userId, expiresAt, client, refreshTokenHash, refreshTokenExpiresAt }) {
      const session = await prisma.session.create({
        data: {
          userId,
          expiresAt,
          ip: client.ip,
          userAgent: client.userAgent,
          // Escrita aninhada: sessão e primeiro token entram juntos ou nenhum entra.
          refreshTokens: {
            create: { tokenHash: refreshTokenHash, expiresAt: refreshTokenExpiresAt },
          },
        },
        select: { id: true },
      });
      return { sessionId: session.id };
    },

    async findSession(sessionId) {
      const session = await prisma.session.findUnique({
        where: { id: sessionId },
        select: sessionStateSelect,
      });
      return session && toSessionState(session);
    },

    async findRefreshToken(tokenHash) {
      const token = await prisma.refreshToken.findUnique({
        where: { tokenHash },
        select: {
          id: true,
          usedAt: true,
          expiresAt: true,
          session: { select: sessionStateSelect },
        },
      });
      return token && { ...token, session: toSessionState(token.session) };
    },

    rotateRefreshToken({ tokenId, sessionId, now, newTokenHash, newTokenExpiresAt }) {
      return prisma.$transaction(async (tx) => {
        // UPDATE ... WHERE used_at IS NULL: a linha fica travada até o commit, e uma
        // requisição concorrente reavalia a condição depois dele, encontrando used_at preenchido.
        const consumed = await tx.refreshToken.updateMany({
          where: { id: tokenId, usedAt: null, expiresAt: { gt: now } },
          data: { usedAt: now },
        });

        if (consumed.count === 0) {
          const current = await tx.refreshToken.findUnique({
            where: { id: tokenId },
            select: { usedAt: true },
          });
          return { rotated: false, usedAt: current?.usedAt ?? null };
        }

        await tx.refreshToken.create({
          data: { sessionId, tokenHash: newTokenHash, expiresAt: newTokenExpiresAt },
        });
        await tx.session.update({ where: { id: sessionId }, data: { lastUsedAt: now } });
        return { rotated: true };
      });
    },

    async revokeSession(sessionId, userId, reason, now) {
      // userId no WHERE: mesmo com um sessionId alheio, nada de outro usuário é revogado.
      const { count } = await prisma.session.updateMany({
        where: { id: sessionId, userId, revokedAt: null },
        data: { revokedAt: now, revokedReason: reason },
      });
      return count;
    },

    async revokeAllSessions(userId, reason, now) {
      const { count } = await prisma.session.updateMany({
        where: { userId, revokedAt: null },
        data: { revokedAt: now, revokedReason: reason },
      });
      return count;
    },
  };
}
