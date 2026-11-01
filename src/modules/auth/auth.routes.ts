import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import { bearerAuth, errorResponseSchema } from '../../shared/http-schemas.js';
import { authOf, clientInfo } from './auth.middleware.js';
import {
  loginBodySchema,
  refreshBodySchema,
  tokenPairSchema,
  toTokenPairDto,
} from './auth.schemas.js';
import type { AuthService } from './auth.service.js';

interface AuthRoutesOptions {
  authService: AuthService;
}

/**
 * Login, refresh e logout. O cadastro (POST /auth/register) fica no módulo users.
 * Rate limit por IP e por conta chega na Etapa 6; até lá, a única proteção contra força
 * bruta é o custo do Argon2id e a trilha de auditoria (LOGIN_FAILURE).
 */
export const authRoutes: FastifyPluginAsyncZod<AuthRoutesOptions> = async (app, options) => {
  const { authService } = options;

  app.post(
    '/auth/login',
    {
      schema: {
        tags: ['Auth'],
        summary: 'Login',
        description:
          'Cria uma sessão e devolve um access token (JWT, 15 min) e um refresh token opaco. ' +
          'Email inexistente e senha errada têm a mesma resposta 401.',
        body: loginBodySchema,
        response: {
          200: tokenPairSchema,
          400: errorResponseSchema.describe('Dados inválidos'),
          401: errorResponseSchema.describe('INVALID_CREDENTIALS'),
        },
      },
    },
    async (request) => {
      const { email, password } = request.body;
      return toTokenPairDto(await authService.login(email, password, clientInfo(request)));
    },
  );

  app.post(
    '/auth/refresh',
    {
      schema: {
        tags: ['Auth'],
        summary: 'Troca o refresh token por um novo par (rotação)',
        description:
          'O refresh token é de uso único. Reapresentar um token já trocado há menos de ' +
          '10 s devolve 409 sem emitir tokens; depois disso, a sessão inteira é revogada.',
        body: refreshBodySchema,
        response: {
          200: tokenPairSchema,
          400: errorResponseSchema.describe('Dados inválidos'),
          401: errorResponseSchema.describe('INVALID_REFRESH_TOKEN ou REFRESH_TOKEN_REUSED'),
          409: errorResponseSchema.describe('REFRESH_TOKEN_ALREADY_ROTATED (corrida legítima)'),
        },
      },
    },
    async (request) => {
      const pair = await authService.refresh(request.body.refreshToken, clientInfo(request));
      return toTokenPairDto(pair);
    },
  );

  app.post(
    '/auth/logout',
    {
      // onRequest: autentica antes de ler e validar o corpo (anônimo recebe 401, não 400).
      onRequest: app.authenticate,
      schema: {
        tags: ['Auth'],
        summary: 'Encerra a sessão atual',
        description:
          'Revoga a sessão do access token. O access token e os refresh tokens dela deixam ' +
          'de valer imediatamente.',
        security: bearerAuth,
        response: {
          204: z.null().describe('Sessão encerrada'),
          401: errorResponseSchema.describe('Token ausente, inválido ou sessão já encerrada'),
        },
      },
    },
    async (request, reply) => {
      await authService.logout(authOf(request), clientInfo(request));
      return reply.code(204).send(null);
    },
  );

  app.post(
    '/auth/logout-all',
    {
      onRequest: app.authenticate,
      schema: {
        tags: ['Auth'],
        summary: 'Encerra todas as sessões do usuário',
        description: 'Revoga todas as sessões do usuário autenticado, inclusive a atual.',
        security: bearerAuth,
        response: {
          204: z.null().describe('Sessões encerradas'),
          401: errorResponseSchema.describe('Token ausente, inválido ou sessão já encerrada'),
        },
      },
    },
    async (request, reply) => {
      await authService.logoutAll(authOf(request), clientInfo(request));
      return reply.code(204).send(null);
    },
  );
};
