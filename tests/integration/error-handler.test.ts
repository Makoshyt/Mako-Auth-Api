import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { z } from 'zod';
import type { ErrorBody } from '../../src/shared/error-handler.js';
import { AppError, conflict } from '../../src/shared/errors.js';
import { buildTestApp } from '../helpers/build-test-app.js';

/** Registra rotas exclusivas de teste para exercitar cada ramo do error handler. */
function addTestRoutes(app: FastifyInstance): void {
  const typed = app.withTypeProvider<ZodTypeProvider>();

  typed.post(
    '/test/validation',
    { schema: { body: z.object({ email: z.email(), age: z.number().int().min(18) }) } },
    () => ({ ok: true }),
  );
  typed.get('/test/app-error', () => {
    throw conflict('Email já cadastrado');
  });
  typed.get('/test/app-error-details', () => {
    throw new AppError(422, 'UNPROCESSABLE', 'Regra violada', { rule: 'exemplo' });
  });
  typed.get('/test/crash', () => {
    throw new Error('falha interna com detalhe sensível: senha=fake123');
  });
}

async function build(nodeEnv: 'test' | 'production' | 'development'): Promise<FastifyInstance> {
  const app = await buildTestApp({ NODE_ENV: nodeEnv, LOG_LEVEL: 'silent' });
  addTestRoutes(app);
  return app;
}

describe('error handler global', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await build('test');
  });

  afterAll(async () => {
    await app.close();
  });

  it('400 VALIDATION_ERROR com detalhes por campo para corpo inválido', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/test/validation',
      payload: { email: 'nao-e-email', age: 10 },
    });

    expect(response.statusCode).toBe(400);
    const { error } = response.json<ErrorBody>();
    expect(error.code).toBe('VALIDATION_ERROR');
    expect(error.requestId).toBeTruthy();
    expect(error.details).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ field: 'body.email' }),
        expect.objectContaining({ field: 'body.age' }),
      ]),
    );
  });

  it('400 para JSON malformado, no mesmo formato de erro', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/test/validation',
      headers: { 'content-type': 'application/json' },
      payload: '{"email": ',
    });

    expect(response.statusCode).toBe(400);
    const { error } = response.json<ErrorBody>();
    expect(error.code).toBe('FST_ERR_CTP_INVALID_JSON_BODY');
  });

  it('413 quando o corpo excede o limite de 16 KB', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/test/validation',
      payload: { email: 'a@example.com', age: 20, padding: 'x'.repeat(20 * 1024) },
    });

    expect(response.statusCode).toBe(413);
  });

  it('converte AppError no status e código definidos pelo domínio', async () => {
    const response = await app.inject({ method: 'GET', url: '/test/app-error' });

    expect(response.statusCode).toBe(409);
    expect(response.json<ErrorBody>().error).toMatchObject({
      code: 'CONFLICT',
      message: 'Email já cadastrado',
    });
  });

  it('inclui details do AppError quando fornecidos', async () => {
    const response = await app.inject({ method: 'GET', url: '/test/app-error-details' });

    expect(response.statusCode).toBe(422);
    expect(response.json<ErrorBody>().error.details).toEqual({ rule: 'exemplo' });
  });

  it('404 padronizado para rota inexistente', async () => {
    const response = await app.inject({ method: 'GET', url: '/rota-inexistente' });

    expect(response.statusCode).toBe(404);
    expect(response.json<ErrorBody>().error.code).toBe('NOT_FOUND');
  });
});

describe('erros inesperados (500)', () => {
  it('em produção: mensagem genérica, sem stack e sem a mensagem original', async () => {
    const app = await build('production');
    const response = await app.inject({ method: 'GET', url: '/test/crash' });
    await app.close();

    expect(response.statusCode).toBe(500);
    const { error } = response.json<ErrorBody>();
    expect(error.code).toBe('INTERNAL_ERROR');
    expect(error.message).toBe('Erro interno do servidor');
    expect(error.stack).toBeUndefined();
    expect(response.body).not.toContain('senha=fake123');
  });

  it('em development: inclui stack para depuração local', async () => {
    const app = await build('development');
    const response = await app.inject({ method: 'GET', url: '/test/crash' });
    await app.close();

    expect(response.statusCode).toBe(500);
    expect(response.json<ErrorBody>().error.stack).toContain('Error:');
  });
});
