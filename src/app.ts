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
import {
  createOllamaExplainer,
  disabledExplainer,
  type AlertExplainer,
} from './modules/alerts/alert-explainer.js';
import { buildDetectionRules } from './modules/alerts/alert-rules.js';
import { createAlertsRepository } from './modules/alerts/alerts.repository.js';
import { createAlertsService } from './modules/alerts/alerts.service.js';
import { createEngineScheduler, runDetection } from './modules/alerts/detection-engine.js';
import { createAuditRecorder } from './modules/audit/audit.recorder.js';
import { registerAuthentication } from './modules/auth/auth.middleware.js';
import { createAuthRepository } from './modules/auth/auth.repository.js';
import { authRoutes } from './modules/auth/auth.routes.js';
import { createAuthService } from './modules/auth/auth.service.js';
import { createAccessTokenSigner } from './modules/auth/tokens.js';
import { healthRoutes } from './modules/health/health.routes.js';
import { createMailer, type Mailer } from './modules/mail/mailer.js';
import { createPasswordResetRepository } from './modules/password-reset/password-reset.repository.js';
import { passwordResetRoutes } from './modules/password-reset/password-reset.routes.js';
import { createPasswordResetService } from './modules/password-reset/password-reset.service.js';
import { buildPolicies } from './modules/rate-limit/rate-limit.policies.js';
import { createRedisRateLimitStore } from './modules/rate-limit/rate-limit.store.js';
import { createRateLimiter, registerRateLimiting } from './modules/rate-limit/rate-limiter.js';
import { databaseCheck, redisCheck } from './modules/health/readiness.js';
import { createUsersRepository } from './modules/users/users.repository.js';
import { usersRoutes } from './modules/users/users.routes.js';
import { createUsersService } from './modules/users/users.service.js';
import { registerSwagger } from './plugins/swagger.js';
import { createBackgroundTasks, type BackgroundTasks } from './shared/background-tasks.js';
import { registerErrorHandling } from './shared/error-handler.js';
import { hashPassword, verifyPassword } from './shared/password-hasher.js';

/**
 * Converte TRUST_PROXY para o Fastify. Um número N vira a função equivalente
 * "confia nos N saltos mais próximos" (é o que o proxy-addr faz com números); os tipos do
 * Fastify só aceitam a forma de função.
 */
export function trustProxyOption(value: Env['TRUST_PROXY']) {
  return typeof value === 'number' ? (_address: string, hop: number) => hop < value : value;
}

export interface AppDependencies {
  env: Env;
  prisma: PrismaClient;
  redis: Redis;
  /** Destino alternativo para os logs (usado nos testes que inspecionam o que é logado). */
  logDestination?: DestinationStream;
  /** Provedor de email. Padrão: o escolhido por MAIL_PROVIDER. Os testes injetam o MemoryMailer. */
  mailer?: Mailer;
  /** Explicador de alertas. Padrão: Ollama local se ALERTS_AI_ENABLED, senão desligado. */
  alertExplainer?: AlertExplainer;
}

declare module 'fastify' {
  interface FastifyInstance {
    /** Tarefas disparadas após a resposta (ex.: email de recuperação). `idle()` espera todas. */
    backgroundTasks: BackgroundTasks;
  }
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
  mailer: injectedMailer,
  alertExplainer,
}: AppDependencies): Promise<FastifyInstance> {
  const app = Fastify({
    logger: buildLoggerOptions(env, logDestination),
    genReqId: () => randomUUID(),
    trustProxy: trustProxyOption(env.TRUST_PROXY),
    // Payloads de autenticação são pequenos; limitar reduz superfície de abuso.
    bodyLimit: 16 * 1024,
  }).withTypeProvider<ZodTypeProvider>();

  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  registerErrorHandling(app, { exposeStack: env.NODE_ENV === 'development' });

  await app.register(cors, {
    // Lista vazia = nenhuma origem cross-origin permitida.
    origin: env.CORS_ORIGINS.length > 0 ? env.CORS_ORIGINS : false,
    // Sem isto, um front-end em outra origem não consegue ler quanto tempo esperar após um 429.
    exposedHeaders: [
      'Retry-After',
      'X-RateLimit-Limit',
      'X-RateLimit-Remaining',
      'X-RateLimit-Reset',
    ],
  });

  // O swagger precisa ser registrado antes das rotas para coletá-las.
  if (env.SWAGGER_ENABLED) await registerSwagger(app);

  // Montagem manual das dependências: repository -> service -> rotas.

  // Falhas de auditoria vão só para o log; o cliente nunca vê o detalhe (nem recebe 500).
  const audit = createAuditRecorder(prisma, (error) => {
    app.log.error({ err: error }, 'falha ao gravar evento de auditoria');
  });
  const usersService = createUsersService({
    usersRepository: createUsersRepository(prisma),
    hashPassword,
    verifyPassword,
    audit,
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

  const adminService = createAdminService({
    adminRepository: createAdminRepository(prisma),
    audit,
  });

  // Erros de tarefas em segundo plano vão só para o log (sem token nem email: só a mensagem).
  const backgroundTasks = createBackgroundTasks((name, error) => {
    app.log.error(
      { task: name, reason: error instanceof Error ? error.message : 'erro desconhecido' },
      'falha em tarefa em segundo plano',
    );
  });
  app.decorate('backgroundTasks', backgroundTasks);
  // No encerramento, espera emails pendentes antes de as conexões serem fechadas.
  app.addHook('onClose', () => backgroundTasks.idle());

  const mailer = injectedMailer ?? createMailer(env, app.log);
  if (env.NODE_ENV === 'production' && mailer.name === 'log') {
    app.log.warn('MAIL_PROVIDER=log em produção: emails de recuperação NÃO serão entregues');
  }
  const alertsService = createAlertsService({
    repository: createAlertsRepository(prisma),
    explainer:
      alertExplainer ??
      (env.ALERTS_AI_ENABLED
        ? createOllamaExplainer({
            baseUrl: env.OLLAMA_URL,
            model: env.OLLAMA_MODEL,
            timeoutMs: env.OLLAMA_TIMEOUT_MS,
          })
        : disabledExplainer),
    audit,
  });

  // Motor de alertas: rodadas periódicas FORA do caminho das requisições, a partir do checkpoint
  // persistido. Começa quando o servidor fica pronto e para (esperando a rodada atual) ao fechar.
  if (env.ALERTS_ENGINE_ENABLED) {
    const scheduler = createEngineScheduler(
      () =>
        runDetection(prisma, {
          rules: buildDetectionRules(env),
          lagMs: env.ALERTS_ENGINE_LAG_SECONDS * 1000,
          initialLookbackMs: env.ALERTS_ENGINE_INITIAL_LOOKBACK_HOURS * 3_600_000,
          dedupWindowMs: env.ALERTS_DEDUP_WINDOW_HOURS * 3_600_000,
        }),
      env.ALERTS_ENGINE_INTERVAL_SECONDS * 1000,
      (result) => {
        if (result.created > 0 || result.updated > 0 || result.behind) {
          app.log.info(
            { created: result.created, updated: result.updated, behind: result.behind },
            'motor de alertas: rodada concluída',
          );
        }
      },
      (error) => {
        app.log.error(
          { reason: error instanceof Error ? error.message : 'erro desconhecido' },
          'motor de alertas: rodada falhou; será repetida a partir do checkpoint',
        );
      },
    );
    app.addHook('onReady', async () => {
      scheduler.start();
    });
    app.addHook('onClose', () => scheduler.stop());
  }

  const passwordResetService = createPasswordResetService({
    repository: createPasswordResetRepository(prisma),
    hashPassword,
    mailer,
    audit,
    tasks: backgroundTasks,
    tokenTtlMinutes: env.PASSWORD_RESET_TOKEN_TTL_MINUTES,
  });

  // No contexto raiz: `app.authenticate` e `request.auth` ficam visíveis para todos os módulos.
  registerAuthentication(app, authService, audit);
  // Contadores no Redis compartilhado: o limite vale para todas as instâncias da API juntas.
  registerRateLimiting(
    app,
    createRateLimiter({
      store: createRedisRateLimitStore(redis),
      policies: buildPolicies(env),
      hmacSecret: env.RATE_LIMIT_HMAC_SECRET,
      keyPrefix: env.RATE_LIMIT_KEY_PREFIX,
    }),
  );

  // Helmet fica no contexto encapsulado da API: a CSP restritiva vale para as
  // respostas JSON, sem quebrar os assets da interface do Swagger em /docs.
  await app.register(async (api) => {
    await api.register(helmet);
    await api.register(healthRoutes, {
      readinessChecks: [databaseCheck(prisma), redisCheck(redis)],
    });
    await api.register(usersRoutes, { prefix: '/api/v1', usersService });
    await api.register(authRoutes, { prefix: '/api/v1', authService });
    await api.register(adminRoutes, { prefix: '/api/v1/admin', adminService, alertsService });
    await api.register(passwordResetRoutes, { prefix: '/api/v1', passwordResetService });
  });

  return app;
}
