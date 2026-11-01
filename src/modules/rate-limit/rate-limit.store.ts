import type { Redis } from '../../infra/redis.js';

export interface RateLimitHit {
  /** Requisições contadas na janela atual, incluindo esta. */
  count: number;
  /** Milissegundos até a janela expirar. */
  ttlMs: number;
}

/** Contador com janela. Implementado sobre o Redis; os testes unitários usam um falso. */
export interface RateLimitStore {
  hit(key: string, windowMs: number): Promise<RateLimitHit>;
}

/**
 * Janela fixa iniciada no primeiro acesso, num único script Lua: o Redis executa scripts de
 * forma atômica, então N instâncias da API incrementando a mesma chave ao mesmo tempo nunca
 * perdem contagens nem deixam uma chave sem TTL. Só usa INCR, PTTL e PEXPIRE, todos O(1)
 * (nada de KEYS, SCAN ou comandos bloqueantes no caminho da requisição).
 *
 * `ttl < 0` cobre uma chave que, por qualquer motivo, exista sem expiração: ela recebe TTL em
 * vez de bloquear alguém para sempre.
 */
const HIT_SCRIPT = `
local count = redis.call('INCR', KEYS[1])
local ttl = redis.call('PTTL', KEYS[1])
if count == 1 or ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {count, ttl}
`;

export function createRedisRateLimitStore(redis: Redis): RateLimitStore {
  return {
    async hit(key, windowMs) {
      const reply = await redis.eval(HIT_SCRIPT, 1, key, windowMs);
      if (!Array.isArray(reply) || typeof reply[0] !== 'number' || typeof reply[1] !== 'number') {
        throw new Error('resposta inesperada do script de rate limit');
      }
      return { count: reply[0], ttlMs: reply[1] };
    },
  };
}
