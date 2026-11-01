import type { PrismaClient } from '../../infra/prisma.js';
import type { Redis } from '../../infra/redis.js';

export interface ReadinessCheck {
  name: string;
  /** Resolve se a dependência está disponível; rejeita caso contrário. */
  check: () => Promise<unknown>;
}

export type CheckStatus = 'up' | 'down';

export interface ReadinessResult {
  ready: boolean;
  checks: Record<string, CheckStatus>;
}

const CHECK_TIMEOUT_MS = 2_000;

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(new Error(`timeout após ${ms} ms`));
      }, ms).unref();
    }),
  ]);
}

/**
 * Executa as verificações em paralelo, cada uma com timeout próprio.
 * `onFailure` recebe o erro para log; a resposta HTTP expõe apenas "up"/"down".
 */
export async function runReadinessChecks(
  checks: ReadinessCheck[],
  onFailure: (name: string, error: unknown) => void,
  timeoutMs = CHECK_TIMEOUT_MS,
): Promise<ReadinessResult> {
  const results = await Promise.all(
    checks.map(async ({ name, check }): Promise<[string, CheckStatus]> => {
      try {
        await withTimeout(check(), timeoutMs);
        return [name, 'up'];
      } catch (error) {
        onFailure(name, error);
        return [name, 'down'];
      }
    }),
  );

  return {
    ready: results.every(([, status]) => status === 'up'),
    checks: Object.fromEntries(results),
  };
}

export function databaseCheck(prisma: PrismaClient): ReadinessCheck {
  return { name: 'database', check: () => prisma.$queryRaw`SELECT 1` };
}

export function redisCheck(redis: Redis): ReadinessCheck {
  return { name: 'redis', check: () => redis.ping() };
}
