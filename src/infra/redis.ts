import { Redis } from 'ioredis';

export type { Redis };

interface RedisClientOptions {
  /** Não conecta até o primeiro comando. Usado em testes que não dependem do Redis. */
  lazyConnect?: boolean;
}

export function createRedisClient(url: string, options: RedisClientOptions = {}): Redis {
  return new Redis(url, {
    lazyConnect: options.lazyConnect ?? false,
    connectTimeout: 5_000,
    // Sem fila offline: com o Redis fora do ar, comandos falham na hora em vez de
    // acumular. O /ready reporta a falha e o rate limit decide o que fazer (Etapa 6).
    enableOfflineQueue: false,
    maxRetriesPerRequest: 1,
  });
}
