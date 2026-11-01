import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildTestApp } from '../helpers/build-test-app.js';

describe('GET /health', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  it('responde 200 com status, uptime e timestamp', async () => {
    const response = await app.inject({ method: 'GET', url: '/health' });

    expect(response.statusCode).toBe(200);
    const body = response.json<{ status: string; uptimeSeconds: number; timestamp: string }>();
    expect(body.status).toBe('ok');
    expect(body.uptimeSeconds).toBeGreaterThanOrEqual(0);
    expect(new Date(body.timestamp).toISOString()).toBe(body.timestamp);
  });

  it('aplica headers de segurança do helmet', async () => {
    const response = await app.inject({ method: 'GET', url: '/health' });

    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['content-security-policy']).toBeDefined();
    expect(response.headers['x-powered-by']).toBeUndefined();
  });

  it('gera um request id único por requisição (UUID)', async () => {
    const [first, second] = await Promise.all([
      app.inject({ method: 'GET', url: '/nao-existe' }),
      app.inject({ method: 'GET', url: '/nao-existe' }),
    ]);
    const firstId = first.json<{ error: { requestId: string } }>().error.requestId;
    const secondId = second.json<{ error: { requestId: string } }>().error.requestId;

    expect(firstId).toMatch(/^[0-9a-f-]{36}$/);
    expect(firstId).not.toBe(secondId);
  });
});

describe('CORS', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildTestApp({ CORS_ORIGINS: 'http://localhost:5173' });
  });

  afterAll(async () => {
    await app.close();
  });

  it('libera a origem configurada', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/health',
      headers: { origin: 'http://localhost:5173' },
    });

    expect(response.headers['access-control-allow-origin']).toBe('http://localhost:5173');
  });

  it('não libera origem fora da lista', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/health',
      headers: { origin: 'http://malicioso.example.com' },
    });

    expect(response.headers['access-control-allow-origin']).toBeUndefined();
  });
});

describe('Swagger', () => {
  it('publica o documento OpenAPI com a rota /health', async () => {
    const app = await buildTestApp({ SWAGGER_ENABLED: 'true' });
    const response = await app.inject({ method: 'GET', url: '/docs/json' });
    await app.close();

    expect(response.statusCode).toBe(200);
    const spec = response.json<{ openapi: string; paths: Record<string, unknown> }>();
    expect(spec.openapi).toBe('3.1.0');
    expect(spec.paths).toHaveProperty('/health');
  });

  it('não expõe /docs quando SWAGGER_ENABLED=false', async () => {
    const app = await buildTestApp({ SWAGGER_ENABLED: 'false' });
    const response = await app.inject({ method: 'GET', url: '/docs/json' });
    await app.close();

    expect(response.statusCode).toBe(404);
  });
});
