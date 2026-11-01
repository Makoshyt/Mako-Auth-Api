import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { bearerAuth, errorResponseSchema } from '../../shared/http-schemas.js';
import { authOf } from '../auth/auth.middleware.js';
import {
  publicUserSchema,
  registerBodySchema,
  toPublicUserDto,
  updateProfileBodySchema,
} from './users.schemas.js';
import type { UsersService } from './users.service.js';

interface UsersRoutesOptions {
  usersService: UsersService;
}

/**
 * Cadastro (público) e perfil do próprio usuário (autenticado).
 *
 * As rotas de perfil não recebem id: o usuário é SEMPRE o do token (`authOf`). Não existe
 * rota que aceite um id de usuário vindo do cliente, então não há como ler ou alterar
 * o perfil de outra pessoa (IDOR).
 */
export const usersRoutes: FastifyPluginAsyncZod<UsersRoutesOptions> = async (app, options) => {
  const { usersService } = options;

  app.post(
    '/auth/register',
    {
      schema: {
        tags: ['Auth'],
        summary: 'Cadastro de usuário',
        description:
          'Cria uma conta com papel USER. Campos extras (como role) são rejeitados com 400. ' +
          'O email é normalizado (trim + minúsculas).',
        body: registerBodySchema,
        response: {
          201: publicUserSchema,
          400: errorResponseSchema.describe('Dados inválidos ou senha fraca (WEAK_PASSWORD)'),
          409: errorResponseSchema.describe('Email já cadastrado'),
        },
      },
    },
    async (request, reply) => {
      const user = await usersService.register(request.body);
      return reply.code(201).send(toPublicUserDto(user));
    },
  );

  app.get(
    '/users/me',
    {
      onRequest: app.authenticate,
      schema: {
        tags: ['Users'],
        summary: 'Perfil do usuário autenticado',
        security: bearerAuth,
        response: {
          200: publicUserSchema,
          401: errorResponseSchema.describe(
            'Token ausente, inválido, expirado ou sessão encerrada',
          ),
        },
      },
    },
    async (request) => {
      return toPublicUserDto(await usersService.getProfile(authOf(request).userId));
    },
  );

  app.patch(
    '/users/me',
    {
      onRequest: app.authenticate,
      schema: {
        tags: ['Users'],
        summary: 'Atualiza nome e/ou email do usuário autenticado',
        description:
          'Aceita apenas name, email e currentPassword. Trocar o email exige currentPassword ' +
          'e encerra as demais sessões do usuário (a atual continua válida). ' +
          'Campos como role ou password geram 400.',
        security: bearerAuth,
        body: updateProfileBodySchema,
        response: {
          200: publicUserSchema,
          400: errorResponseSchema.describe('Dados inválidos ou campo não permitido'),
          401: errorResponseSchema.describe(
            'Token ausente, inválido, expirado ou sessão encerrada',
          ),
          403: errorResponseSchema.describe('INVALID_CURRENT_PASSWORD'),
          409: errorResponseSchema.describe('Email já cadastrado'),
        },
      },
    },
    async (request) => {
      const auth = authOf(request);
      const user = await usersService.updateProfile(auth.userId, request.body, {
        currentSessionId: auth.sessionId,
      });
      return toPublicUserDto(user);
    },
  );
};
