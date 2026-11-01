import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import type { FastifyInstance } from 'fastify';
import { jsonSchemaTransform, jsonSchemaTransformObject } from 'fastify-type-provider-zod';

/**
 * Gera o documento OpenAPI a partir dos schemas Zod das rotas
 * e publica a interface em /docs (JSON em /docs/json).
 */
export async function registerSwagger(app: FastifyInstance): Promise<void> {
  await app.register(swagger, {
    openapi: {
      openapi: '3.1.0',
      info: {
        title: 'AuthAPI Pro',
        description:
          'API REST de autenticação e gerenciamento de usuários. ' +
          'Erros seguem o formato { error: { code, message, requestId, details? } }.',
        version: '0.1.0',
      },
      tags: [
        { name: 'Health', description: 'Sondas de liveness e readiness' },
        { name: 'Auth', description: 'Cadastro, login, refresh e logout' },
        { name: 'Users', description: 'Perfil do usuário autenticado (exige Bearer token)' },
        { name: 'Admin', description: 'Consultas administrativas (exige papel ADMIN)' },
      ],
      components: {
        securitySchemes: {
          bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
        },
      },
    },
    transform: jsonSchemaTransform,
    transformObject: jsonSchemaTransformObject,
  });

  await app.register(swaggerUi, { routePrefix: '/docs' });
}
