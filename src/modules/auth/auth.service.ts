import { randomBytes } from 'node:crypto';
import { AppError } from '../../shared/errors.js';
import type { AuditRecorder } from '../audit/audit.recorder.js';
import type {
  AuthContext,
  AuthRepository,
  ClientInfo,
  StoredRefreshToken,
  TokenPair,
} from './auth.types.js';
import {
  AccessTokenError,
  generateRefreshToken,
  hashRefreshToken,
  type AccessTokenSigner,
} from './tokens.js';

const DAY_MS = 24 * 60 * 60 * 1000;

export interface AuthServiceConfig {
  refreshTokenTtlDays: number;
  sessionAbsoluteTtlDays: number;
  refreshReuseGraceSeconds: number;
}

export interface AuthServiceDeps {
  authRepository: AuthRepository;
  accessTokens: AccessTokenSigner;
  hashPassword: (password: string) => Promise<string>;
  verifyPassword: (encoded: string, password: string) => Promise<boolean>;
  audit: AuditRecorder;
  config: AuthServiceConfig;
  /** Relógio injetável: os testes simulam a passagem do tempo sem esperar. */
  now?: () => Date;
}

export type AuthService = ReturnType<typeof createAuthService>;

// Mensagem única para email inexistente e senha errada: não revela quais emails existem.
const invalidCredentials = () =>
  new AppError(401, 'INVALID_CREDENTIALS', 'Email ou senha inválidos');
const invalidRefreshToken = () =>
  new AppError(401, 'INVALID_REFRESH_TOKEN', 'Refresh token inválido ou expirado');
const invalidSession = () => new AppError(401, 'INVALID_SESSION', 'Sessão inválida ou encerrada');

export function createAuthService({
  authRepository,
  accessTokens,
  hashPassword,
  verifyPassword,
  audit,
  config,
  now = () => new Date(),
}: AuthServiceDeps) {
  /**
   * Hash fictício, com os mesmos parâmetros dos reais, para verificar a senha quando o email
   * não existe. Assim as duas respostas 401 custam o mesmo Argon2id e o tempo não denuncia
   * quais contas existem. Calculado já na criação, para não pesar no primeiro login.
   */
  const dummyHash = hashPassword(randomBytes(32).toString('base64url'));

  async function issueTokens(
    userId: string,
    sessionId: string,
    role: AuthContext['role'],
    refreshToken: string,
    refreshTokenExpiresAt: Date,
    at: Date,
  ): Promise<TokenPair> {
    return {
      accessToken: await accessTokens.sign({ userId, sessionId, role }, at),
      tokenType: 'Bearer',
      expiresIn: accessTokens.ttlSeconds,
      refreshToken,
      refreshTokenExpiresAt,
    };
  }

  /** O refresh token nunca vale mais que a própria sessão (validade absoluta). */
  const refreshExpiry = (at: Date, sessionExpiresAt: Date) =>
    new Date(
      Math.min(at.getTime() + config.refreshTokenTtlDays * DAY_MS, sessionExpiresAt.getTime()),
    );

  async function handleReuse(
    token: StoredRefreshToken,
    usedAt: Date,
    at: Date,
    client: ClientInfo,
  ): Promise<never> {
    const elapsedMs = at.getTime() - usedAt.getTime();

    // Dentro da janela: provável corrida legítima (duas abas, retry). Nada é emitido e a
    // sessão continua ativa; o cliente usa o par devolvido à requisição vencedora.
    if (elapsedMs < config.refreshReuseGraceSeconds * 1000) {
      throw new AppError(
        409,
        'REFRESH_TOKEN_ALREADY_ROTATED',
        'Este refresh token acabou de ser trocado por outro. Use o par de tokens mais recente.',
      );
    }

    // Fora da janela: o token antigo está em mãos de alguém. Revoga a família inteira.
    await authRepository.revokeSession(token.session.id, token.session.userId, 'TOKEN_REUSE', at);
    await audit.record({
      type: 'TOKEN_REUSE_DETECTED',
      userId: token.session.userId,
      ip: client.ip,
      metadata: { sessionId: token.session.id, secondsSinceRotation: Math.floor(elapsedMs / 1000) },
    });
    throw new AppError(
      401,
      'REFRESH_TOKEN_REUSED',
      'Refresh token reutilizado. Por segurança, a sessão foi encerrada.',
    );
  }

  return {
    async login(email: string, password: string, client: ClientInfo): Promise<TokenPair> {
      const credentials = await authRepository.findCredentialsByEmail(email);

      if (!credentials) {
        await verifyPassword(await dummyHash, password);
        await audit.record({
          type: 'LOGIN_FAILURE',
          email,
          ip: client.ip,
          metadata: { reason: 'UNKNOWN_EMAIL' },
        });
        throw invalidCredentials();
      }

      if (!(await verifyPassword(credentials.passwordHash, password))) {
        await audit.record({
          type: 'LOGIN_FAILURE',
          userId: credentials.id,
          email,
          ip: client.ip,
          metadata: { reason: 'INVALID_PASSWORD' },
        });
        throw invalidCredentials();
      }

      const at = now();
      const sessionExpiresAt = new Date(at.getTime() + config.sessionAbsoluteTtlDays * DAY_MS);
      const refreshToken = generateRefreshToken();
      const refreshTokenExpiresAt = refreshExpiry(at, sessionExpiresAt);
      const { sessionId } = await authRepository.createSession({
        userId: credentials.id,
        expiresAt: sessionExpiresAt,
        client,
        refreshTokenHash: hashRefreshToken(refreshToken),
        refreshTokenExpiresAt,
      });

      await audit.record({
        type: 'LOGIN_SUCCESS',
        userId: credentials.id,
        email,
        ip: client.ip,
        metadata: { sessionId },
      });
      return issueTokens(
        credentials.id,
        sessionId,
        credentials.role,
        refreshToken,
        refreshTokenExpiresAt,
        at,
      );
    },

    async refresh(refreshToken: string, client: ClientInfo): Promise<TokenPair> {
      const at = now();
      const stored = await authRepository.findRefreshToken(hashRefreshToken(refreshToken));
      if (!stored) throw invalidRefreshToken();

      const { session } = stored;
      // Sessão encerrada (logout, reuso detectado) ou vencida: nenhum token dela vale mais.
      if (session.revokedAt !== null || session.expiresAt <= at) throw invalidRefreshToken();
      if (stored.usedAt !== null) return handleReuse(stored, stored.usedAt, at, client);
      if (stored.expiresAt <= at) throw invalidRefreshToken();

      const nextToken = generateRefreshToken();
      const nextExpiresAt = refreshExpiry(at, session.expiresAt);
      const result = await authRepository.rotateRefreshToken({
        tokenId: stored.id,
        sessionId: session.id,
        now: at,
        newTokenHash: hashRefreshToken(nextToken),
        newTokenExpiresAt: nextExpiresAt,
      });

      if (!result.rotated) {
        // Perdeu a corrida para uma requisição concorrente com o mesmo token.
        if (result.usedAt) return handleReuse(stored, result.usedAt, at, client);
        throw invalidRefreshToken();
      }
      // Papel ATUAL do banco: um rebaixamento vale já no próximo access token.
      return issueTokens(session.userId, session.id, session.role, nextToken, nextExpiresAt, at);
    },

    /** Valida o access token e confirma no banco que a sessão continua ativa. */
    async authenticate(accessToken: string): Promise<AuthContext> {
      const at = now();
      let claims;
      try {
        claims = await accessTokens.verify(accessToken, at);
      } catch (error) {
        if (error instanceof AccessTokenError && error.reason === 'EXPIRED') {
          throw new AppError(401, 'TOKEN_EXPIRED', 'Access token expirado');
        }
        throw new AppError(401, 'INVALID_TOKEN', 'Access token inválido');
      }

      const session = await authRepository.findSession(claims.sid);
      if (
        !session ||
        session.userId !== claims.sub ||
        session.revokedAt !== null ||
        session.expiresAt <= at
      ) {
        throw invalidSession();
      }
      return { userId: session.userId, sessionId: session.id, role: session.role };
    },

    /** Encerra a sessão autenticada. Concorrência ou repetição não geram erro (idempotente). */
    async logout(auth: AuthContext, client: ClientInfo): Promise<void> {
      const revoked = await authRepository.revokeSession(
        auth.sessionId,
        auth.userId,
        'LOGOUT',
        now(),
      );
      if (revoked > 0) {
        await audit.record({
          type: 'LOGOUT',
          userId: auth.userId,
          ip: client.ip,
          metadata: { sessionId: auth.sessionId },
        });
      }
    },

    /** Encerra todas as sessões do usuário autenticado, inclusive a atual. */
    async logoutAll(auth: AuthContext, client: ClientInfo): Promise<number> {
      const revoked = await authRepository.revokeAllSessions(auth.userId, 'LOGOUT_ALL', now());
      await audit.record({
        type: 'LOGOUT_ALL',
        userId: auth.userId,
        ip: client.ip,
        metadata: { revokedSessions: revoked },
      });
      return revoked;
    },
  };
}
