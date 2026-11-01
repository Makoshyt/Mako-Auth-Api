import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { errorResponseSchema, failClosedResponses } from '../../shared/http-schemas.js';
import { clientInfo } from '../auth/auth.middleware.js';
import {
  FORGOT_PASSWORD_MESSAGE,
  forgotPasswordBodySchema,
  messageSchema,
  resetPasswordBodySchema,
} from './password-reset.schemas.js';
import type { PasswordResetService } from './password-reset.service.js';

interface PasswordResetRoutesOptions {
  passwordResetService: PasswordResetService;
}

/**
 * Recuperação de senha (públicas, mas limitadas):
 *  - forgot-password: por IP em onRequest e, se passar, por conta (HMAC do email) em preHandler.
 *  - reset-password: por IP. Todas falham fechado (503) com o Redis fora do ar.
 */
export const passwordResetRoutes: FastifyPluginAsyncZod<PasswordResetRoutesOptions> = async (
  app,
  options,
) => {
  const { passwordResetService } = options;

  app.post(
    '/auth/forgot-password',
    {
      onRequest: app.rateLimit.hook('forgotPasswordIp'),
      preHandler: app.rateLimit.hook('forgotPasswordAccount'),
      schema: {
        tags: ['Auth'],
        summary: 'Solicita a recuperação de senha',
        description:
          'Sempre 202 com a mesma mensagem, exista ou não a conta. Se existir, um link de uso ' +
          'único (15 min) é enviado por email. O token nunca aparece na resposta.',
        body: forgotPasswordBodySchema,
        response: {
          202: messageSchema,
          400: errorResponseSchema.describe('Email em formato inválido'),
          ...failClosedResponses,
        },
      },
    },
    async (request, reply) => {
      passwordResetService.requestReset(request.body.email, clientInfo(request));
      return reply.code(202).send({ message: FORGOT_PASSWORD_MESSAGE });
    },
  );

  app.post(
    '/auth/reset-password',
    {
      onRequest: app.rateLimit.hook('resetPasswordIp'),
      schema: {
        tags: ['Auth'],
        summary: 'Redefine a senha com o token recebido por email',
        description:
          'Consome o token (uso único), grava a nova senha e encerra TODAS as sessões da conta. ' +
          'Não faz login: entre de novo com a nova senha.',
        body: resetPasswordBodySchema,
        response: {
          200: messageSchema,
          400: errorResponseSchema.describe(
            'INVALID_RESET_TOKEN (inválido, expirado ou já usado), WEAK_PASSWORD ou dados inválidos',
          ),
          ...failClosedResponses,
        },
      },
    },
    async (request) => {
      const { token, newPassword } = request.body;
      await passwordResetService.resetPassword(token, newPassword, clientInfo(request));
      return { message: 'Senha redefinida. Entre novamente com a nova senha.' };
    },
  );
};
