import { z } from 'zod';
import { codePointLength, PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH } from './password-policy.js';
import type { PublicUser } from './users.types.js';

// Caracteres de controle (Cc) e de formatação (Cf: bidi, zero-width) permitem nomes
// "invisíveis" ou exibidos invertidos em telas administrativas (ex.: RIGHT-TO-LEFT OVERRIDE).
const UNSAFE_NAME_CHARS = /[\p{Cc}\p{Cf}]/u;

/** Email: trim + minúsculas ANTES da validação; é a forma que vai para o banco. */
export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .max(254, 'Email muito longo')
  .pipe(z.email('Email inválido'))
  .meta({ example: 'ana.souza@example.com' });

export const nameSchema = z
  .string()
  .normalize('NFC')
  .trim()
  .transform((value) => value.replace(/\s+/g, ' '))
  .pipe(
    z
      .string()
      .min(1, 'Nome é obrigatório')
      .max(100, 'Nome pode ter no máximo 100 caracteres')
      .refine((value) => !UNSAFE_NAME_CHARS.test(value), 'Nome contém caracteres não permitidos'),
  )
  .meta({ example: 'Ana Souza' });

/**
 * Apenas o formato (tamanho). As regras de conteúdo (senha comum, dados pessoais...) ficam
 * no service, que é a fronteira de domínio e também é usado fora do HTTP.
 * O tamanho conta code points, como a política: "🔐" vale 1 caractere.
 */
export const passwordSchema = z
  .string()
  .refine((value) => codePointLength(value) >= PASSWORD_MIN_LENGTH, {
    message: `A senha precisa ter pelo menos ${PASSWORD_MIN_LENGTH} caracteres`,
  })
  .refine((value) => codePointLength(value) <= PASSWORD_MAX_LENGTH, {
    message: `A senha pode ter no máximo ${PASSWORD_MAX_LENGTH} caracteres`,
  })
  .meta({
    description: `Entre ${PASSWORD_MIN_LENGTH} e ${PASSWORD_MAX_LENGTH} caracteres. Passphrases são recomendadas.`,
    example: 'cavalo correto bateria grampo',
  });

/** strictObject: qualquer campo extra (role, isAdmin, id...) gera 400. */
export const registerBodySchema = z.strictObject({
  name: nameSchema,
  email: emailSchema,
  password: passwordSchema,
});

/** strictObject: role, password, passwordHash, id... geram 400. */
export const updateProfileBodySchema = z
  .strictObject({
    name: nameSchema.optional(),
    email: emailSchema.optional(),
    currentPassword: z
      .string()
      .min(1)
      .max(256)
      .optional()
      .meta({ description: 'Obrigatória para trocar o email' }),
  })
  .refine((body) => body.name !== undefined || body.email !== undefined, {
    message: 'Informe ao menos um campo: name ou email',
  })
  .refine((body) => body.email === undefined || body.currentPassword !== undefined, {
    message: 'Para trocar o email, informe a senha atual em currentPassword',
    path: ['currentPassword'],
  });

export const publicUserSchema = z
  .object({
    id: z.uuid(),
    name: z.string(),
    email: z.email(),
    role: z.enum(['USER', 'ADMIN']),
    createdAt: z.iso.datetime(),
    updatedAt: z.iso.datetime(),
  })
  .meta({ id: 'PublicUser' });

export type PublicUserDto = z.infer<typeof publicUserSchema>;

/** Converte para o formato da resposta HTTP, escolhendo campo a campo (sem spread). */
export function toPublicUserDto(user: PublicUser): PublicUserDto {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    createdAt: user.createdAt.toISOString(),
    updatedAt: user.updatedAt.toISOString(),
  };
}
