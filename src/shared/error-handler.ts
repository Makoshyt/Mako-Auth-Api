import type { FastifyError, FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { hasZodFastifySchemaValidationErrors } from 'fastify-type-provider-zod';
import { AppError } from './errors.js';

/**
 * Formato único de erro de toda a API:
 * { "error": { "code", "message", "requestId", "details"? } }
 */
export interface ErrorBody {
  error: {
    code: string;
    message: string;
    requestId: string;
    details?: unknown;
    stack?: string;
  };
}

interface ErrorHandlerOptions {
  /** Inclui stack trace na resposta de erros 500. Ligado apenas em development. */
  exposeStack: boolean;
}

function body(
  request: FastifyRequest,
  code: string,
  message: string,
  details?: unknown,
): ErrorBody {
  return {
    error: {
      code,
      message,
      requestId: request.id,
      ...(details !== undefined && { details }),
    },
  };
}

export function registerErrorHandling(app: FastifyInstance, options: ErrorHandlerOptions): void {
  app.setErrorHandler((error: FastifyError, request: FastifyRequest, reply: FastifyReply) => {
    // 1. Entrada inválida segundo o schema Zod da rota.
    if (hasZodFastifySchemaValidationErrors(error)) {
      const details = error.validation.map((issue) => {
        const path = issue.instancePath.split('/').filter(Boolean);
        return { field: [error.validationContext, ...path].join('.'), message: issue.message };
      });
      return reply
        .code(400)
        .send(body(request, 'VALIDATION_ERROR', 'Dados de entrada inválidos', details));
    }

    // 2. Erros de domínio lançados pelos services.
    if (error instanceof AppError) {
      return reply
        .code(error.statusCode)
        .send(body(request, error.code, error.message, error.details));
    }

    // 3. Erros 4xx do próprio Fastify (JSON malformado, payload grande, content-type...).
    //    As mensagens desses erros descrevem a requisição, não o servidor, então são seguras.
    if (error.statusCode !== undefined && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send(body(request, error.code, error.message));
    }

    // 4. Qualquer outra coisa é falha inesperada: registra tudo no log, devolve mensagem genérica.
    request.log.error({ err: error }, 'erro não tratado');
    const response = body(request, 'INTERNAL_ERROR', 'Erro interno do servidor');
    if (options.exposeStack && error.stack) response.error.stack = error.stack;
    return reply.code(500).send(response);
  });

  app.setNotFoundHandler((request, reply) => {
    return reply
      .code(404)
      .send(body(request, 'NOT_FOUND', `Rota ${request.method} ${request.url} não encontrada`));
  });
}
