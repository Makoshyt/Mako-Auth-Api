import { createHash, randomBytes } from 'node:crypto';
import { errors, jwtVerify, SignJWT } from 'jose';
import { z } from 'zod';
import type { Role } from '../../generated/prisma/enums.js';

/** Única lista de algoritmos aceita: impede `alg: none`, troca para HS512/RS256 etc. */
const ALGORITHM = 'HS256';
const ISSUER = 'authapi-pro';
const AUDIENCE = 'authapi-pro:api';
const OPAQUE_TOKEN_BYTES = 32;

export interface AccessTokenClaims {
  /** id do usuário */
  sub: string;
  /** id da sessão: permite revogar o token antes do exp */
  sid: string;
  /** papel no momento da emissão; a autorização usa o papel ATUAL do banco */
  role: Role;
  iat: number;
  exp: number;
}

export type AccessTokenFailure = 'EXPIRED' | 'INVALID';

export class AccessTokenError extends Error {
  constructor(public readonly reason: AccessTokenFailure) {
    super(reason === 'EXPIRED' ? 'access token expirado' : 'access token inválido');
    this.name = 'AccessTokenError';
  }
}

/** A assinatura válida não basta: o conteúdo também precisa ter o formato esperado. */
const claimsSchema = z.object({
  sub: z.uuid(),
  sid: z.uuid(),
  role: z.enum(['USER', 'ADMIN']),
  iat: z.number().int(),
  exp: z.number().int(),
});

export interface AccessTokenSigner {
  readonly ttlSeconds: number;
  sign(input: { userId: string; sessionId: string; role: Role }, now?: Date): Promise<string>;
  /** Lança AccessTokenError. */
  verify(token: string, now?: Date): Promise<AccessTokenClaims>;
}

export function createAccessTokenSigner(secret: string, ttlSeconds: number): AccessTokenSigner {
  const key = new TextEncoder().encode(secret);

  return {
    ttlSeconds,

    async sign({ userId, sessionId, role }, now = new Date()) {
      const iat = Math.floor(now.getTime() / 1000);
      return new SignJWT({ sid: sessionId, role })
        .setProtectedHeader({ alg: ALGORITHM, typ: 'JWT' })
        .setSubject(userId)
        .setIssuer(ISSUER)
        .setAudience(AUDIENCE)
        .setIssuedAt(iat)
        .setExpirationTime(iat + ttlSeconds)
        .sign(key);
    },

    async verify(token, now = new Date()) {
      try {
        const { payload } = await jwtVerify(token, key, {
          algorithms: [ALGORITHM],
          issuer: ISSUER,
          audience: AUDIENCE,
          requiredClaims: ['sub', 'sid', 'role', 'iat', 'exp'],
          currentDate: now,
        });
        const claims = claimsSchema.safeParse(payload);
        if (!claims.success) throw new AccessTokenError('INVALID');
        return claims.data;
      } catch (error) {
        if (error instanceof AccessTokenError) throw error;
        if (error instanceof errors.JWTExpired) throw new AccessTokenError('EXPIRED');
        // Assinatura, algoritmo, formato, iss/aud: todos viram o mesmo "inválido".
        throw new AccessTokenError('INVALID');
      }
    },
  };
}

/**
 * Token opaco: 256 bits aleatórios em base64url (43 caracteres). Não carrega dados, só serve
 * de chave. Usado para refresh tokens e tokens de recuperação de senha (nunca um no lugar do
 * outro: cada um vive na própria tabela).
 */
export function generateOpaqueToken(): string {
  return randomBytes(OPAQUE_TOKEN_BYTES).toString('base64url');
}

/**
 * Só o SHA-256 vai para o banco. Um vazamento da tabela não entrega tokens utilizáveis,
 * e como o token tem 256 bits de entropia, um hash rápido (sem salt) é suficiente.
 */
export function hashOpaqueToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export const generateRefreshToken = generateOpaqueToken;
export const hashRefreshToken = hashOpaqueToken;
