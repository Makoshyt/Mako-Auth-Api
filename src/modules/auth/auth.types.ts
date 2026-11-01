import type { Role, SessionRevokeReason } from '../../generated/prisma/enums.js';

/** Identidade autenticada de uma requisição. Sempre derivada do JWT + banco, nunca do cliente. */
export interface AuthContext {
  userId: string;
  sessionId: string;
  /** Papel ATUAL lido do banco a cada requisição (não o do token). */
  role: Role;
}

/** Metadados da requisição guardados na sessão e na auditoria. */
export interface ClientInfo {
  ip: string | null;
  userAgent: string | null;
}

export interface TokenPair {
  accessToken: string;
  tokenType: 'Bearer';
  /** Segundos até o access token expirar. */
  expiresIn: number;
  refreshToken: string;
  refreshTokenExpiresAt: Date;
}

/** Uso interno do login. Nunca sai do módulo. */
export interface UserCredentials {
  id: string;
  role: Role;
  passwordHash: string;
}

export interface SessionState {
  id: string;
  userId: string;
  role: Role;
  expiresAt: Date;
  revokedAt: Date | null;
}

export interface StoredRefreshToken {
  id: string;
  usedAt: Date | null;
  expiresAt: Date;
  session: SessionState;
}

export type RotationResult = { rotated: true } | { rotated: false; usedAt: Date | null };

export interface AuthRepository {
  findCredentialsByEmail(email: string): Promise<UserCredentials | null>;
  /** Cria a sessão e o primeiro refresh token na mesma transação. */
  createSession(data: {
    userId: string;
    expiresAt: Date;
    client: ClientInfo;
    refreshTokenHash: string;
    refreshTokenExpiresAt: Date;
  }): Promise<{ sessionId: string }>;
  findSession(sessionId: string): Promise<SessionState | null>;
  findRefreshToken(tokenHash: string): Promise<StoredRefreshToken | null>;
  /**
   * Consome o token (used_at) e grava o sucessor numa transação. Só UMA chamada concorrente
   * consegue consumir; as demais recebem `rotated: false` com o used_at do vencedor.
   */
  rotateRefreshToken(data: {
    tokenId: string;
    sessionId: string;
    now: Date;
    newTokenHash: string;
    newTokenExpiresAt: Date;
  }): Promise<RotationResult>;
  /** Revoga a sessão se ela pertencer ao usuário e ainda estiver ativa. Retorna 0 ou 1. */
  revokeSession(
    sessionId: string,
    userId: string,
    reason: SessionRevokeReason,
    now: Date,
  ): Promise<number>;
  /** Revoga todas as sessões ativas do usuário. Retorna quantas foram revogadas. */
  revokeAllSessions(userId: string, reason: SessionRevokeReason, now: Date): Promise<number>;
}
