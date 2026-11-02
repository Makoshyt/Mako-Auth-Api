import type { FastifyRequest } from 'fastify';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { bearerAuth, errorResponseSchema, rateLimitResponses } from '../../shared/http-schemas.js';
import { authOf, clientInfo, requireRole } from '../auth/auth.middleware.js';
import { publicUserSchema, toPublicUserDto } from '../users/users.schemas.js';
import {
  auditEventListSchema,
  listAuditEventsQuerySchema,
  listUsersQuerySchema,
  toAuditEventListDto,
  toUserListDto,
  userIdParamsSchema,
  userListSchema,
} from './admin.schemas.js';
import type { AdminActor, AdminService } from './admin.service.js';
import {
  alertIdParamsSchema,
  explanationResponseSchema,
  listAlertsQuerySchema,
  securityAlertListSchema,
  securityAlertSchema,
  toAlertDto,
  toExplanationDto,
} from '../alerts/alerts.schemas.js';
import type { AlertsService } from '../alerts/alerts.service.js';

interface AdminRoutesOptions {
  adminService: AdminService;
  alertsService: AlertsService;
}

/** O ADMIN da requisição, derivado do token e do IP da conexão. */
const actorOf = (request: FastifyRequest): AdminActor => ({
  userId: authOf(request).userId,
  ip: clientInfo(request).ip,
});

const protectedResponses = {
  400: errorResponseSchema.describe('Parâmetros inválidos'),
  401: errorResponseSchema.describe('Token ausente, inválido, expirado ou sessão encerrada'),
  403: errorResponseSchema.describe('Autenticado, mas sem o papel ADMIN'),
  ...rateLimitResponses,
};

/**
 * Rotas administrativas (somente leitura).
 *
 * Os hooks valem para TODAS as rotas deste plugin, então não há como esquecer a proteção
 * numa rota nova. Rodam em onRequest, antes da validação: um anônimo recebe 401 e um USER
 * recebe 403, sem descobrir nada sobre os parâmetros aceitos.
 */
export const adminRoutes: FastifyPluginAsyncZod<AdminRoutesOptions> = async (app, options) => {
  const { adminService, alertsService } = options;

  // Toda rota admin PRECISA declarar `config.rateLimit`: sem isso, o servidor nem sobe.
  app.addHook('onRoute', (route) => {
    if (!route.config?.rateLimit) {
      throw new Error(
        `rota admin ${route.method.toString()} ${route.url} sem política de rate limit`,
      );
    }
  });
  // Ordem: quem é (401) → limite por usuário (429) → papel (403). O limite antes do papel
  // também contém um USER insistindo em rotas admin (cada 403 grava um ACCESS_DENIED).
  app.addHook('onRequest', app.authenticate);
  app.addHook('onRequest', app.rateLimit.fromRouteConfig());
  app.addHook('onRequest', requireRole('ADMIN'));

  app.get(
    '/users',
    {
      config: { rateLimit: 'adminUsers' },
      schema: {
        tags: ['Admin'],
        summary: 'Lista usuários (paginado)',
        description:
          'Filtros: email (trecho), role. Ordenação: sort = createdAt | email | name, ' +
          'order = asc | desc. pageSize máximo de 100.',
        security: bearerAuth,
        querystring: listUsersQuerySchema,
        response: { 200: userListSchema, ...protectedResponses },
      },
    },
    async (request) => {
      const page = await adminService.listUsers(request.query, actorOf(request));
      return toUserListDto(page, request.query);
    },
  );

  app.get(
    '/users/:id',
    {
      config: { rateLimit: 'adminUserById' },
      schema: {
        tags: ['Admin'],
        summary: 'Consulta um usuário pelo id',
        security: bearerAuth,
        params: userIdParamsSchema,
        response: {
          200: publicUserSchema,
          ...protectedResponses,
          404: errorResponseSchema.describe('Usuário não encontrado'),
        },
      },
    },
    async (request) =>
      toPublicUserDto(await adminService.getUser(request.params.id, actorOf(request))),
  );

  app.get(
    '/audit-events',
    {
      config: { rateLimit: 'adminAuditEvents' },
      schema: {
        tags: ['Admin'],
        summary: 'Consulta a trilha de auditoria (paginado)',
        description:
          'Filtros: type, userId, from (inclusive) e to (exclusive) em ISO 8601. ' +
          'Ordenação estável por createdAt e id. pageSize máximo de 100.',
        security: bearerAuth,
        querystring: listAuditEventsQuerySchema,
        response: { 200: auditEventListSchema, ...protectedResponses },
      },
    },
    async (request) => {
      const page = await adminService.listAuditEvents(request.query, actorOf(request));
      return toAuditEventListDto(page, request.query);
    },
  );

  app.get(
    '/security-alerts',
    {
      config: { rateLimit: 'adminSecurityAlerts' },
      schema: {
        tags: ['Admin'],
        summary: 'Lista alertas de segurança (paginado)',
        description:
          'Filtros: rule, severity, status. Ordenação estável por createdAt e id. ' +
          'pageSize máximo de 100. Somente leitura: não há exclusão nem ações automáticas.',
        security: bearerAuth,
        querystring: listAlertsQuerySchema,
        response: { 200: securityAlertListSchema, ...protectedResponses },
      },
    },
    async (request) => {
      const { items, total } = await alertsService.list(request.query, actorOf(request));
      return {
        data: items.map(toAlertDto),
        pagination: {
          page: request.query.page,
          pageSize: request.query.pageSize,
          total,
          totalPages: Math.ceil(total / request.query.pageSize),
        },
      };
    },
  );

  app.get(
    '/security-alerts/:id',
    {
      config: { rateLimit: 'adminSecurityAlertById' },
      schema: {
        tags: ['Admin'],
        summary: 'Consulta um alerta de segurança',
        security: bearerAuth,
        params: alertIdParamsSchema,
        response: {
          200: securityAlertSchema,
          ...protectedResponses,
          404: errorResponseSchema.describe('Alerta não encontrado'),
        },
      },
    },
    async (request) => toAlertDto(await alertsService.get(request.params.id, actorOf(request))),
  );

  app.post(
    '/security-alerts/:id/explanation',
    {
      config: { rateLimit: 'adminSecurityAlertExplain' },
      schema: {
        tags: ['Admin'],
        summary: 'Explicação do alerta por IA local (opcional)',
        description:
          'Gera, sob demanda, uma explicação em texto com um modelo LOCAL (Ollama). Desligada ' +
          'por padrão (status "disabled"). Não é gravada, não altera o alerta e não executa ' +
          'nenhuma ação: é apoio à análise humana. Recebe só evidências minimizadas.',
        security: bearerAuth,
        params: alertIdParamsSchema,
        response: {
          200: explanationResponseSchema,
          ...protectedResponses,
          404: errorResponseSchema.describe('Alerta não encontrado'),
        },
      },
    },
    async (request) =>
      toExplanationDto(await alertsService.explain(request.params.id, actorOf(request))),
  );
};
