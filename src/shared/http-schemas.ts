import { z } from 'zod';

/** Formato único de erro (ver error-handler.ts), para documentar as respostas no OpenAPI. */
export const errorResponseSchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    requestId: z.string(),
    details: z.unknown().optional(),
  }),
});

/** Rotas protegidas: exibe o cadeado e envia o token pelo botão "Authorize" do Swagger. */
export const bearerAuth = [{ bearerAuth: [] }];

/** Respostas do rate limit, para documentar no OpenAPI as rotas limitadas. */
export const rateLimitResponses = {
  429: errorResponseSchema.describe(
    'RATE_LIMITED: limite excedido. Veja Retry-After e X-RateLimit-* nos cabeçalhos',
  ),
};

/** Rotas que falham fechado: sem o Redis, respondem 503 em vez de liberar tentativas. */
export const failClosedResponses = {
  ...rateLimitResponses,
  503: errorResponseSchema.describe('SERVICE_UNAVAILABLE: proteção contra abuso indisponível'),
};
