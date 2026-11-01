import { z } from 'zod';
import { emailSchema } from '../users/users.schemas.js';
import type { TokenPair } from './auth.types.js';

/**
 * Login não aplica a política de senha (senhas antigas continuam entrando); só limita o
 * tamanho. 256 unidades UTF-16 cobrem os 128 code points máximos do cadastro e impedem
 * que alguém force o Argon2id a processar megabytes.
 */
export const loginBodySchema = z.strictObject({
  email: emailSchema,
  password: z.string().min(1, 'Senha é obrigatória').max(256, 'Senha muito longa'),
});

export const refreshBodySchema = z.strictObject({
  refreshToken: z
    .string()
    .min(1, 'refreshToken é obrigatório')
    .max(512, 'refreshToken inválido')
    .meta({ description: 'Refresh token opaco recebido no login ou no último refresh' }),
});

export const tokenPairSchema = z
  .object({
    accessToken: z.string().meta({ description: 'JWT HS256. Envie como Authorization: Bearer' }),
    tokenType: z.literal('Bearer'),
    expiresIn: z.number().int().meta({ description: 'Segundos até o access token expirar' }),
    refreshToken: z.string().meta({ description: 'Opaco e de uso único: guarde o mais recente' }),
    refreshTokenExpiresAt: z.iso.datetime(),
  })
  .meta({ id: 'TokenPair' });

export function toTokenPairDto(pair: TokenPair): z.infer<typeof tokenPairSchema> {
  return {
    accessToken: pair.accessToken,
    tokenType: pair.tokenType,
    expiresIn: pair.expiresIn,
    refreshToken: pair.refreshToken,
    refreshTokenExpiresAt: pair.refreshTokenExpiresAt.toISOString(),
  };
}
