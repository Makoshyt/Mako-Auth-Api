import { describe, expect, it, vi } from 'vitest';
import { runReadinessChecks } from '../../src/modules/health/readiness.js';

const up = (name: string) => ({ name, check: () => Promise.resolve() });
const down = (name: string, message = 'connection refused') => ({
  name,
  check: () => Promise.reject(new Error(message)),
});

describe('runReadinessChecks', () => {
  it('fica pronto quando todas as dependências respondem', async () => {
    const onFailure = vi.fn();

    const result = await runReadinessChecks([up('database'), up('redis')], onFailure);

    expect(result).toEqual({ ready: true, checks: { database: 'up', redis: 'up' } });
    expect(onFailure).not.toHaveBeenCalled();
  });

  it('não fica pronto se uma dependência falha, e reporta o erro só para o callback', async () => {
    const onFailure = vi.fn();

    const result = await runReadinessChecks([up('database'), down('redis')], onFailure);

    expect(result).toEqual({ ready: false, checks: { database: 'up', redis: 'down' } });
    expect(onFailure).toHaveBeenCalledWith('redis', expect.any(Error));
  });

  it('marca como down uma dependência que não responde dentro do timeout', async () => {
    const hanging = { name: 'database', check: () => new Promise(() => undefined) };
    const onFailure = vi.fn();

    const started = Date.now();
    const result = await runReadinessChecks([hanging], onFailure, 50);

    expect(result.checks.database).toBe('down');
    expect(Date.now() - started).toBeLessThan(1_000);
    const [name, error] = onFailure.mock.calls[0] as [string, Error];
    expect(name).toBe('database');
    expect(error.message).toContain('timeout');
  });

  it('executa as verificações em paralelo', async () => {
    const slow = (name: string) => ({
      name,
      check: () => new Promise((resolve) => setTimeout(resolve, 100)),
    });

    const started = Date.now();
    await runReadinessChecks([slow('a'), slow('b'), slow('c')], vi.fn());

    expect(Date.now() - started).toBeLessThan(250);
  });
});
