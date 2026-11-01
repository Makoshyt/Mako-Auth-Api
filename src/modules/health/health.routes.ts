import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import { runReadinessChecks, type ReadinessCheck } from './readiness.js';

const healthResponse = z.object({
  status: z.literal('ok'),
  uptimeSeconds: z.number().describe('Tempo desde o início do processo, em segundos'),
  timestamp: z.iso.datetime(),
});

const checkStatus = z.enum(['up', 'down']);

const readyResponse = z.object({
  status: z.enum(['ready', 'not_ready']),
  checks: z.record(z.string(), checkStatus).meta({
    example: { database: 'up', redis: 'up' },
  }),
});

interface HealthRoutesOptions {
  readinessChecks: ReadinessCheck[];
}

export const healthRoutes: FastifyPluginAsyncZod<HealthRoutesOptions> = async (app, options) => {
  /** Liveness: o processo está de pé. Não toca em dependências externas. */
  app.get(
    '/health',
    {
      schema: {
        tags: ['Health'],
        summary: 'Liveness do processo',
        response: { 200: healthResponse },
      },
    },
    () => ({
      status: 'ok' as const,
      uptimeSeconds: Math.round(process.uptime()),
      timestamp: new Date().toISOString(),
    }),
  );

  /**
   * Readiness: a instância consegue atender tráfego (PostgreSQL e Redis acessíveis).
   * Responde 503 se qualquer dependência falhar; o motivo vai só para o log.
   */
  app.get(
    '/ready',
    {
      schema: {
        tags: ['Health'],
        summary: 'Readiness: PostgreSQL e Redis',
        response: { 200: readyResponse, 503: readyResponse },
      },
    },
    async (request, reply) => {
      const result = await runReadinessChecks(options.readinessChecks, (name, error) => {
        request.log.warn({ check: name, err: error }, 'readiness check falhou');
      });
      return reply
        .code(result.ready ? 200 : 503)
        .send({ status: result.ready ? 'ready' : 'not_ready', checks: result.checks });
    },
  );
};
