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
