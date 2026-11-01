import { describe, expect, it } from 'vitest';
import { buildTestApp } from '../helpers/build-test-app.js';

describe('GET /ready', () => {
  it('200 quando PostgreSQL e Redis estão acessíveis', async () => {
    const app = await buildTestApp();
    const response = await app.inject({ method: 'GET', url: '/ready' });
    await app.close();

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      status: 'ready',
      checks: { database: 'up', redis: 'up' },
    });
  });

  it('503 quando as dependências estão fora do ar, sem expor o motivo', async () => {
    // Porta 1: nada escuta ali, a conexão é recusada imediatamente.
    const app = await buildTestApp(
      {
        DATABASE_URL: 'postgresql://ficticio:SenhaFicticia@127.0.0.1:1/inexistente',
        REDIS_URL: 'redis://127.0.0.1:1',
      },
      // Redis fora do ar de propósito: não tenta conectar ao montar o app.
      { connectRedis: false },
    );
    const response = await app.inject({ method: 'GET', url: '/ready' });
    await app.close();

    expect(response.statusCode).toBe(503);
    expect(response.json()).toEqual({
      status: 'not_ready',
      checks: { database: 'down', redis: 'down' },
    });
    expect(response.body).not.toMatch(/ECONNREFUSED|SenhaFicticia|127\.0\.0\.1/);
  });

  it('/health continua 200 mesmo com dependências fora do ar (liveness ≠ readiness)', async () => {
    const app = await buildTestApp(
      {
        DATABASE_URL: 'postgresql://ficticio:x@127.0.0.1:1/inexistente',
        REDIS_URL: 'redis://127.0.0.1:1',
      },
      // Redis fora do ar de propósito: não tenta conectar ao montar o app.
      { connectRedis: false },
    );
    const response = await app.inject({ method: 'GET', url: '/health' });
    await app.close();

    expect(response.statusCode).toBe(200);
  });
});
