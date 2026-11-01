import { randomUUID } from 'node:crypto';
import type {
  AuthRepository,
  ClientInfo,
  SessionState,
  StoredRefreshToken,
  UserCredentials,
} from '../../src/modules/auth/auth.types.js';
import type { SessionRevokeReason } from '../../src/generated/prisma/enums.js';

interface StoredSession extends SessionState {
  revokedReason: SessionRevokeReason | null;
  client: ClientInfo;
}

interface StoredToken {
  id: string;
  sessionId: string;
  tokenHash: string;
  usedAt: Date | null;
  expiresAt: Date;
}

/**
 * Repositório falso para testes unitários do AuthService. Mesmas regras do repositório
 * Prisma (consumo condicional do token, revogação restrita ao dono), sem banco.
 * A concorrência real é testada na integração, contra o PostgreSQL.
 */
export class InMemoryAuthRepository implements AuthRepository {
  readonly users = new Map<string, UserCredentials & { email: string }>();
  readonly sessions = new Map<string, StoredSession>();
  readonly tokens = new Map<string, StoredToken>();

  addUser(user: UserCredentials & { email: string }): void {
    this.users.set(user.id, user);
  }

  private state(session: StoredSession): SessionState {
    const role = this.users.get(session.userId)?.role ?? 'USER';
    return {
      id: session.id,
      userId: session.userId,
      role,
      expiresAt: session.expiresAt,
      revokedAt: session.revokedAt,
    };
  }

  findCredentialsByEmail(email: string): Promise<UserCredentials | null> {
    const user = [...this.users.values()].find((candidate) => candidate.email === email);
    return Promise.resolve(
      user ? { id: user.id, role: user.role, passwordHash: user.passwordHash } : null,
    );
  }

  createSession(data: {
    userId: string;
    expiresAt: Date;
    client: ClientInfo;
    refreshTokenHash: string;
    refreshTokenExpiresAt: Date;
  }): Promise<{ sessionId: string }> {
    const sessionId = randomUUID();
    this.sessions.set(sessionId, {
      id: sessionId,
      userId: data.userId,
      role: 'USER',
      expiresAt: data.expiresAt,
      revokedAt: null,
      revokedReason: null,
      client: data.client,
    });
    this.addToken(sessionId, data.refreshTokenHash, data.refreshTokenExpiresAt);
    return Promise.resolve({ sessionId });
  }

  private addToken(sessionId: string, tokenHash: string, expiresAt: Date): void {
    const id = randomUUID();
    this.tokens.set(id, { id, sessionId, tokenHash, usedAt: null, expiresAt });
  }

  findSession(sessionId: string): Promise<SessionState | null> {
    const session = this.sessions.get(sessionId);
    return Promise.resolve(session ? this.state(session) : null);
  }

  findRefreshToken(tokenHash: string): Promise<StoredRefreshToken | null> {
    const token = [...this.tokens.values()].find((candidate) => candidate.tokenHash === tokenHash);
    const session = token && this.sessions.get(token.sessionId);
    if (!token || !session) return Promise.resolve(null);
    return Promise.resolve({
      id: token.id,
      usedAt: token.usedAt,
      expiresAt: token.expiresAt,
      session: this.state(session),
    });
  }

  rotateRefreshToken(data: {
    tokenId: string;
    sessionId: string;
    now: Date;
    newTokenHash: string;
    newTokenExpiresAt: Date;
  }): Promise<{ rotated: true } | { rotated: false; usedAt: Date | null }> {
    const token = this.tokens.get(data.tokenId);
    if (!token || token.usedAt !== null || token.expiresAt <= data.now) {
      return Promise.resolve({ rotated: false, usedAt: token?.usedAt ?? null });
    }
    token.usedAt = data.now;
    this.addToken(data.sessionId, data.newTokenHash, data.newTokenExpiresAt);
    return Promise.resolve({ rotated: true });
  }

  revokeSession(
    sessionId: string,
    userId: string,
    reason: SessionRevokeReason,
    now: Date,
  ): Promise<number> {
    const session = this.sessions.get(sessionId);
    if (!session || session.userId !== userId || session.revokedAt !== null) {
      return Promise.resolve(0);
    }
    session.revokedAt = now;
    session.revokedReason = reason;
    return Promise.resolve(1);
  }

  revokeAllSessions(userId: string, reason: SessionRevokeReason, now: Date): Promise<number> {
    let count = 0;
    for (const session of this.sessions.values()) {
      if (session.userId === userId && session.revokedAt === null) {
        session.revokedAt = now;
        session.revokedReason = reason;
        count++;
      }
    }
    return Promise.resolve(count);
  }
}
