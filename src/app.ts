import { randomUUID } from 'node:crypto';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
  type ZodTypeProvider,
} from 'fastify-type-provider-zod';
import type { DestinationStream } from 'pino';
import type { Env } from './config/env.js';
import { buildLoggerOptions } from './infra/logger.js';
import type { PrismaClient } from './infra/prisma.js';
import type { Redis } from './infra/redis.js';
import { createAdminRepository } from './modules/admin/admin.repository.js';
import { adminRoutes } from './modules/admin/admin.routes.js';
import { createAdminService } from './modules/admin/admin.service.js';
import { createAuditRecorder } from './modules/audit/audit.recorder.js';
import { registerAuthentication } from './modules/auth/auth.middleware.js';
import { createAuthRepository } from './modules/auth/auth.repository.js';
import { authRoutes } from './modules/auth/auth.routes.js';
import { createAuthService } from './modules/auth/auth.service.js';
import { createAccessTokenSigner } from './modules/auth/tokens.js';
import { healthRoutes } from './modules/health/health.routes.js';
import { databaseCheck, redisCheck } from './modules/health/readiness.js';
import { createUsersRepository } from './modules/users/users.repository.js';
import { usersRoutes } from './modules/users/users.routes.js';
import { createUsersService } from './modules/users/users.service.js';
import { registerSwagger } from './plugins/swagger.js';
import { registerErrorHandling } from './shared/error-handler.js';
import { hashPassword, verifyPassword } from './shared/password-hasher.js';

export interface AppDependencies {
  env: Env;
  prisma: PrismaClient;
  redis: Redis;
  /** Destino alternativo para os logs (usado nos testes que inspecionam o que é logado). */
  logDestination?: DestinationStream;
}

/**
 * Composition root: cria a instância do Fastify e conecta plugins e módulos.
 * Não chama listen(), então os testes usam app.inject() sem abrir porta.
 * As conexões (prisma, redis) são criadas e encerradas por quem chama (server.ts ou testes).
 */
export async function buildApp({
  env,
  prisma,
  redis,
  logDestination,
}: AppDependencies): Promise<FastifyInstance> {
  const app = Fastify({
    logger: buildLoggerOptions(env, logDestination),
    genReqId: () => randomUUID(),
    trustProxy: env.TRUST_PROXY,
    // Payloads de autenticação são pequenos; limitar reduz superfície de abuso.
    bodyLimit: 16 * 1024,
  }).withTypeProvider<ZodTypeProvider>();

  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  registerErrorHandling(app, { exposeStack: env.NODE_ENV === 'development' });

  await app.register(cors, {
    // Lista vazia = nenhuma origem cross-origin permitida.
    origin: env.CORS_ORIGINS.length > 0 ? env.CORS_ORIGINS : false,
  });

  // O swagger precisa ser registrado antes das rotas para coletá-las.
  if (env.SWAGGER_ENABLED) await registerSwagger(app);

  // Montagem manual das dependências: repository -> service -> rotas.
  const usersService = createUsersService({
    usersRepository: createUsersRepository(prisma),
    hashPassword,
    verifyPassword,
  });
  // Falhas de auditoria vão só para o log; o cliente nunca vê o detalhe (nem recebe 500).
  const audit = createAuditRecorder(prisma, (error) => {
    app.log.error({ err: error }, 'falha ao gravar evento de auditoria');
  });
  const authService = createAuthService({
    authRepository: createAuthRepository(prisma),
    accessTokens: createAccessTokenSigner(env.JWT_ACCESS_SECRET, env.JWT_ACCESS_TTL_SECONDS),
    hashPassword,
    verifyPassword,
    audit,
    config: {
      refreshTokenTtlDays: env.REFRESH_TOKEN_TTL_DAYS,
      sessionAbsoluteTtlDays: env.SESSION_ABSOLUTE_TTL_DAYS,
      refreshReuseGraceSeconds: env.REFRESH_REUSE_GRACE_SECONDS,
    },
  });

  const adminService = createAdminService({ adminRepository: createAdminRepository(prisma) });

  // No contexto raiz: `app.authenticate` e `request.auth` ficam visíveis para todos os módulos.
  registerAuthentication(app, authService, audit);

  // Helmet fica no contexto encapsulado da API: a CSP restritiva vale para as
  // respostas JSON, sem quebrar os assets da interface do Swagger em /docs.
  await app.register(async (api) => {
    await api.register(helmet);
    await api.register(healthRoutes, {
      readinessChecks: [databaseCheck(prisma), redisCheck(redis)],
    });
    await api.register(usersRoutes, { prefix: '/api/v1', usersService });
    await api.register(authRoutes, { prefix: '/api/v1', authService });
    await api.register(adminRoutes, { prefix: '/api/v1/admin', adminService });
  });

  return app;
}
