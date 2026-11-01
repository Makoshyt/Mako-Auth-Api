import { createHmac } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { AppError } from '../../shared/errors.js';
import type { AuthHook } from '../auth/auth.middleware.js';
import { authOf, clientInfo } from '../auth/auth.middleware.js';
import { rateLimitIpKey } from './client-ip.js';
import type {
  PolicyName,
  RateLimitPolicies,
  RateLimitPolicy,
  RateLimitScope,
} from './rate-limit.policies.js';
import type { RateLimitHit, RateLimitStore } from './rate-limit.store.js';

declare module 'fastify' {
  interface FastifyInstance {
    rateLimit: RateLimiter;
  }
  interface FastifyContextConfig {
    /** Política aplicada pelo hook `rateLimit.fromRouteConfig()` (usado no plugin admin). */
    rateLimit?: PolicyName;
  }
}

export interface RateLimiterDeps {
  store: RateLimitStore;
  policies: RateLimitPolicies;
  /** Chave do HMAC que pseudonimiza os identificadores nas chaves do Redis. */
  hmacSecret: string;
  keyPrefix: string;
  /** Tempo máximo esperando o Redis antes de tratar como indisponível. */
  storeTimeoutMs?: number;
}

export interface RateLimiter {
  readonly policies: RateLimitPolicies;
  /** Hook que aplica a política. Para scope "user", use DEPOIS do `authenticate`. */
  hook(name: PolicyName): AuthHook;
  /** Hook que aplica a política declarada em `config.rateLimit` da rota. */
  fromRouteConfig(): AuthHook;
  /** Chave Redis de um identificador (exposta para testes e diagnóstico; nunca é logada). */
  keyFor(policy: RateLimitPolicy, scope: RateLimitScope, identifier: string): string;
}

const tooManyRequests = (retryAfterSeconds: number) =>
  // Mesma mensagem para IP, conta e usuário: a resposta não diz QUAL limite estourou,
  // então também não revela nada sobre a existência de uma conta.
  new AppError(
    429,
    'RATE_LIMITED',
    `Muitas requisições. Tente novamente em ${retryAfterSeconds} s.`,
    {
      retryAfterSeconds,
    },
  );

const serviceUnavailable = () =>
  new AppError(
    503,
    'SERVICE_UNAVAILABLE',
    'Serviço temporariamente indisponível. Tente novamente em instantes.',
  );

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(new Error(`rate limit store: timeout após ${ms} ms`));
      }, ms).unref();
    }),
  ]);
}

/** Identificador da requisição para o escopo da política. null = política não se aplica. */
function identify(scope: RateLimitScope, request: FastifyRequest): string | null {
  switch (scope) {
    case 'ip':
      return rateLimitIpKey(request.ip);
    case 'user':
      // authOf falha fechada (401) se a rota esqueceu o authenticate antes deste hook.
      return authOf(request).userId;
    case 'account': {
      // Roda em preHandler: o corpo já foi validado e o email normalizado pelo Zod.
      const email = (request.body as { email?: unknown } | undefined)?.email;
      return typeof email === 'string' ? email : null;
    }
  }
}

export function createRateLimiter({
  store,
  policies,
  hmacSecret,
  keyPrefix,
  storeTimeoutMs = 1_000,
}: RateLimiterDeps): RateLimiter {
  /**
   * `<prefixo>:<política>:<escopo>:<HMAC-SHA256(escopo:valor)>`. O HMAC (e não um SHA-256
   * simples) impede que quem leia o Redis teste emails ou IPs candidatos por dicionário; o
   * escopo dentro do HMAC e no nome separa contadores de rotas e tipos diferentes.
   */
  function keyFor(policy: RateLimitPolicy, scope: RateLimitScope, identifier: string): string {
    const digest = createHmac('sha256', hmacSecret).update(`${scope}:${identifier}`).digest('hex');
    return `${keyPrefix}:${policy.name}:${scope}:${digest}`;
  }

  function setHeaders(
    reply: FastifyReply,
    policy: RateLimitPolicy,
    hit: RateLimitHit,
    resetSeconds: number,
  ) {
    reply.header('X-RateLimit-Limit', policy.max);
    reply.header('X-RateLimit-Remaining', Math.max(0, policy.max - hit.count));
    reply.header('X-RateLimit-Reset', resetSeconds);
  }

  async function enforce(policy: RateLimitPolicy, request: FastifyRequest, reply: FastifyReply) {
    const identifier = identify(policy.scope, request);
    if (identifier === null) return;

    let hit: RateLimitHit;
    try {
      hit = await withTimeout(
        store.hit(keyFor(policy, policy.scope, identifier), policy.windowMs),
        storeTimeoutMs,
      );
    } catch (error) {
      // Só a política e a mensagem do erro: nada de chave, IP, email ou id no log.
      request.log.error(
        {
          policy: policy.name,
          reason: error instanceof Error ? error.message : 'erro desconhecido',
        },
        'rate limit indisponível',
      );
      if (policy.onStoreFailure === 'closed') {
        reply.header('Retry-After', 10);
        throw serviceUnavailable();
      }
      return;
    }

    const resetSeconds = Math.max(1, Math.ceil(hit.ttlMs / 1000));
    if (policy.exposeHeaders) setHeaders(reply, policy, hit, resetSeconds);
    if (hit.count <= policy.max) return;

    // Primeira requisição bloqueada desta chave na janela: o contador (atômico) passa por
    // max + 1 uma única vez, então há no máximo UM evento e UM log por chave e janela,
    // por mais 429 que o atacante receba depois.
    if (hit.count === policy.max + 1) {
      request.log.warn({ policy: policy.name, scope: policy.scope }, 'rate limit excedido');
      await request.server.audit.record({
        type: 'RATE_LIMIT_EXCEEDED',
        userId: policy.scope === 'user' ? identifier : null,
        ...(policy.scope === 'account' && { email: identifier }),
        ip: clientInfo(request).ip,
        metadata: {
          policy: policy.name,
          scope: policy.scope,
          limit: policy.max,
          windowSeconds: policy.windowMs / 1000,
        },
      });
    }
    reply.header('Retry-After', resetSeconds);
    throw tooManyRequests(resetSeconds);
  }

  return {
    policies,
    keyFor,
    hook(name) {
      const policy = policies[name];
      return (request, reply) => enforce(policy, request, reply);
    },
    fromRouteConfig() {
      return async (request, reply) => {
        const name = request.routeOptions.config.rateLimit;
        if (!name)
          throw new Error(`rota ${request.routeOptions.url ?? '?'} sem política de rate limit`);
        await enforce(policies[name], request, reply);
      };
    },
  };
}

export function registerRateLimiting(app: FastifyInstance, limiter: RateLimiter): void {
  app.decorate('rateLimit', limiter);
}
