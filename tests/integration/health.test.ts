import { requestTimeoutMs } from '../../src/app.js';
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

  it('serve a interface e os arquivos estáticos do Swagger UI (@fastify/static + glob)', async () => {
    const app = await buildTestApp({ SWAGGER_ENABLED: 'true' });
    const page = await app.inject({ method: 'GET', url: '/docs' });
    const asset = await app.inject({ method: 'GET', url: '/docs/static/swagger-ui.css' });
    const bundle = await app.inject({ method: 'GET', url: '/docs/static/swagger-ui-bundle.js' });
    const traversals = await Promise.all(
      ['/docs/static/../../package.json', '/docs/static/%2e%2e/%2e%2e/package.json'].map((url) =>
        app.inject({ method: 'GET', url }),
      ),
    );
    await app.close();

    expect(page.statusCode).toBe(200);
    expect(page.headers['content-type']).toContain('text/html');
    expect(asset.statusCode).toBe(200);
    expect(bundle.statusCode).toBe(200);
    // Path traversal a partir dos estáticos do Swagger: nunca entrega arquivos do projeto.
    for (const response of traversals) {
      expect(response.statusCode).toBe(404);
      expect(response.body).not.toContain('authapi-pro');
    }
  });

  it('não expõe /docs quando SWAGGER_ENABLED=false', async () => {
    const app = await buildTestApp({ SWAGGER_ENABLED: 'false' });
    const response = await app.inject({ method: 'GET', url: '/docs/json' });
    await app.close();

    expect(response.statusCode).toBe(404);
  });
});

describe('timeouts do servidor', () => {
  it('requestTimeout definido (o padrão do Fastify é sem limite) e acima do timeout do Ollama', async () => {
    const app = await buildTestApp({ OLLAMA_TIMEOUT_MS: '60000' });
    // O valor efetivo no servidor HTTP do Node (o que de fato corta a requisição).
    const { requestTimeout } = app.server;
    await app.close();

    expect(requestTimeout).toBe(70_000);
    expect(requestTimeoutMs({ OLLAMA_TIMEOUT_MS: 20_000 })).toBe(30_000);
  });
});
