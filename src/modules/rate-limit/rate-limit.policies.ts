import type { Env } from '../../config/env.js';

/**
 * - ip: endereço de origem (respeita TRUST_PROXY; IPv6 agrupado por /64);
 * - account: email normalizado do corpo (login), pseudonimizado por HMAC;
 * - user: id do usuário autenticado (sempre depois do `authenticate`).
 */
export type RateLimitScope = 'ip' | 'account' | 'user';

/**
 * Com o Redis fora do ar:
 * - closed: responde 503. Para rotas em que liberar geral permitiria força bruta.
 * - open: deixa passar e registra no log. Para ações que não são vetor de ataque e cujo
 *   bloqueio prejudica o usuário (encerrar a própria sessão) ou leituras administrativas.
 */
export type StoreFailureMode = 'closed' | 'open';

type RateLimitEnvKey = {
  [K in keyof Env]: Env[K] extends { max: number; windowMs: number } ? K : never;
}[keyof Env];

interface PolicyDefinition {
  envKey: RateLimitEnvKey;
  scope: RateLimitScope;
  onStoreFailure: StoreFailureMode;
  /**
   * Cabeçalhos X-RateLimit-* nas respostas. Desligado no limite por conta: o "remaining" de
   * um email revelaria quantas tentativas OUTRAS pessoas fizeram contra ele.
   */
  exposeHeaders: boolean;
}

export const POLICY_DEFINITIONS = {
  loginIp: {
    envKey: 'RATE_LIMIT_LOGIN_IP',
    scope: 'ip',
    onStoreFailure: 'closed',
    exposeHeaders: true,
  },
  loginAccount: {
    envKey: 'RATE_LIMIT_LOGIN_ACCOUNT',
    scope: 'account',
    onStoreFailure: 'closed',
    exposeHeaders: false,
  },
  register: {
    envKey: 'RATE_LIMIT_REGISTER_IP',
    scope: 'ip',
    onStoreFailure: 'closed',
    exposeHeaders: true,
  },
  refresh: {
    envKey: 'RATE_LIMIT_REFRESH_IP',
    scope: 'ip',
    onStoreFailure: 'closed',
    exposeHeaders: true,
  },
  logout: {
    envKey: 'RATE_LIMIT_LOGOUT_USER',
    scope: 'user',
    onStoreFailure: 'open',
    exposeHeaders: true,
  },
  logoutAll: {
    envKey: 'RATE_LIMIT_LOGOUT_ALL_USER',
    scope: 'user',
    onStoreFailure: 'open',
    exposeHeaders: true,
  },
  // Fechado: a troca de email confere a senha atual, e isso não pode virar força bruta.
  updateProfile: {
    envKey: 'RATE_LIMIT_UPDATE_PROFILE_USER',
    scope: 'user',
    onStoreFailure: 'closed',
    exposeHeaders: true,
  },
  adminUsers: {
    envKey: 'RATE_LIMIT_ADMIN_USERS',
    scope: 'user',
    onStoreFailure: 'open',
    exposeHeaders: true,
  },
  adminUserById: {
    envKey: 'RATE_LIMIT_ADMIN_USER_BY_ID',
    scope: 'user',
    onStoreFailure: 'open',
    exposeHeaders: true,
  },
  adminAuditEvents: {
    envKey: 'RATE_LIMIT_ADMIN_AUDIT_EVENTS',
    scope: 'user',
    onStoreFailure: 'open',
    exposeHeaders: true,
  },
  // Recuperação de senha (Etapa 7): todas fecham, pois liberar geral permitiria disparar
  // emails em massa ou testar tokens sem limite enquanto o Redis estiver fora.
  forgotPasswordIp: {
    envKey: 'RATE_LIMIT_FORGOT_PASSWORD_IP',
    scope: 'ip',
    onStoreFailure: 'closed',
    exposeHeaders: true,
  },
  forgotPasswordAccount: {
    envKey: 'RATE_LIMIT_FORGOT_PASSWORD_ACCOUNT',
    scope: 'account',
    onStoreFailure: 'closed',
    exposeHeaders: false,
  },
  resetPasswordIp: {
    envKey: 'RATE_LIMIT_RESET_PASSWORD_IP',
    scope: 'ip',
    onStoreFailure: 'closed',
    exposeHeaders: true,
  },
  // Alertas (Etapa 9): leituras de ADMIN; a explicação por IA é mais cara, por isso mais restrita.
  adminSecurityAlerts: {
    envKey: 'RATE_LIMIT_ADMIN_SECURITY_ALERTS',
    scope: 'user',
    onStoreFailure: 'open',
    exposeHeaders: true,
  },
  adminSecurityAlertById: {
    envKey: 'RATE_LIMIT_ADMIN_SECURITY_ALERT_BY_ID',
    scope: 'user',
    onStoreFailure: 'open',
    exposeHeaders: true,
  },
  adminSecurityAlertExplain: {
    envKey: 'RATE_LIMIT_ADMIN_SECURITY_ALERT_EXPLAIN',
    scope: 'user',
    onStoreFailure: 'closed',
    exposeHeaders: true,
  },
  // Escrita (Etapa 10): fail-closed, como as demais operações que alteram estado.
  adminSecurityAlertUpdate: {
    envKey: 'RATE_LIMIT_ADMIN_SECURITY_ALERT_UPDATE',
    scope: 'user',
    onStoreFailure: 'closed',
    exposeHeaders: true,
  },
} as const satisfies Record<string, PolicyDefinition>;

export type PolicyName = keyof typeof POLICY_DEFINITIONS;

export interface RateLimitPolicy extends PolicyDefinition {
  name: PolicyName;
  max: number;
  windowMs: number;
}

export type RateLimitPolicies = Record<PolicyName, RateLimitPolicy>;

export function buildPolicies(env: Env): RateLimitPolicies {
  const entries = Object.entries(POLICY_DEFINITIONS).map(([name, definition]) => [
    name,
    { name, ...definition, ...env[definition.envKey] },
  ]);
  return Object.fromEntries(entries) as RateLimitPolicies;
}
