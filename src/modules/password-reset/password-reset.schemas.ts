import { z } from 'zod';
import { emailSchema, passwordSchema } from '../users/users.schemas.js';

/** strictObject: nenhum campo além do email (ex.: userId) é aceito. */
export const forgotPasswordBodySchema = z.strictObject({ email: emailSchema });

/**
 * Sem email ou userId: a conta afetada é SEMPRE a dona do token. A nova senha passa pela
 * mesma validação de tamanho do cadastro; o conteúdo é checado pela política no service.
 */
export const resetPasswordBodySchema = z.strictObject({
  token: z
    .string()
    .min(1, 'token é obrigatório')
    .max(512, 'token inválido')
    .meta({ description: 'Token recebido no link de recuperação (após #token=)' }),
  newPassword: passwordSchema,
});

export const FORGOT_PASSWORD_MESSAGE =
  'Se o email estiver cadastrado, você receberá as instruções para redefinir a senha.';

export const messageSchema = z.object({ message: z.string() });
