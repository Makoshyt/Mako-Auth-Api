import type {
  RateLimitHit,
  RateLimitStore,
} from '../../src/modules/rate-limit/rate-limit.store.js';

/**
 * Store falso com a MESMA semântica do script Lua (janela fixa iniciada no primeiro acesso),
 * com relógio controlável. A atomicidade e o TTL reais são testados contra o Redis.
 */
export class InMemoryRateLimitStore implements RateLimitStore {
  now = 0;
  readonly entries = new Map<string, { count: number; expiresAt: number }>();
  /** Janelas recebidas, para verificar o TTL pedido ao store. */
  readonly windows: number[] = [];

  hit(key: string, windowMs: number): Promise<RateLimitHit> {
    this.windows.push(windowMs);
    const current = this.entries.get(key);
    const entry =
      current && current.expiresAt > this.now
        ? { ...current, count: current.count + 1 }
        : { count: 1, expiresAt: this.now + windowMs };
    this.entries.set(key, entry);
    return Promise.resolve({ count: entry.count, ttlMs: entry.expiresAt - this.now });
  }
}
