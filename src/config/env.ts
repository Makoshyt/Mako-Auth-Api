import { isIP } from 'node:net';
import { z } from 'zod';

const csvList = z
  .string()
  .default('')
  .transform((value) =>
    value
      .split(',')
      .map((item) => item.trim())
      .filter((item) => item.length > 0),
  );

/** IP ou CIDR (ex.: 10.0.0.0/8, ::1/128) aceito em TRUST_PROXY. */
function isIpOrCidr(value: string): boolean {
  const [address = '', prefix, ...rest] = value.split('/');
  const version = isIP(address);
  if (version === 0 || rest.length > 0) return false;
  if (prefix === undefined) return true;
  const bits = Number(prefix);
  return /^\d{1,3}$/.test(prefix) && bits >= 0 && bits <= (version === 4 ? 32 : 128);
}

/**
 * TRUST_PROXY decide de onde vem o IP do cliente (usado no rate limit e na auditoria):
 *  - "false" (padrão): o IP é o da conexão TCP; X-Forwarded-For é ignorado.
 *  - número N (1 a 10): confia nos N saltos de proxy mais próximos. Com 1 proxy reverso, use 1.
 *  - lista de IPs/CIDRs: confia apenas nesses proxies.
 * "true" é RECUSADO: o Fastify passaria a usar o primeiro endereço do X-Forwarded-For, que é
 * escolhido pelo próprio cliente; qualquer um trocaria de "IP" a cada requisição.
 */
const trustProxySchema = z
  .string()
  .default('false')
  .transform((raw, ctx): false | number | string[] => {
    const value = raw.trim().toLowerCase();
    if (value === 'false' || value === '') return false;
    if (value === 'true') {
      ctx.addIssue({
        code: 'custom',
        message: '"true" confia em qualquer X-Forwarded-For; use o número de proxies ou IPs/CIDRs',
      });
      return z.NEVER;
    }
    if (/^\d+$/.test(value)) {
      const hops = Number(value);
      if (hops >= 1 && hops <= 10) return hops;
      ctx.addIssue({ code: 'custom', message: 'número de proxies deve estar entre 1 e 10' });
      return z.NEVER;
    }
    const entries = value
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean);
    if (entries.length > 0 && entries.every(isIpOrCidr)) return entries;
    ctx.addIssue({ code: 'custom', message: 'use false, um número de proxies ou IPs/CIDRs' });
    return z.NEVER;
  });

const WINDOW_UNIT_MS = { s: 1_000, m: 60_000, h: 3_600_000 } as const;

/**
 * Política de rate limit no formato "<máximo>/<janela>", ex.: "5/15m", "60/1m", "5/1h".
 * Janela entre 1 s e 24 h; máximo entre 1 e 100 000.
 */
const rateLimitSpec = (fallback: string) =>
  z
    .string()
    .default(fallback)
    .transform((raw, ctx) => {
      const match = /^(\d{1,6})\/(\d{1,5})(s|m|h)$/.exec(raw.trim());
      const max = Number(match?.[1]);
      const windowMs = Number(match?.[2]) * WINDOW_UNIT_MS[(match?.[3] ?? 's') as 's' | 'm' | 'h'];
      if (!match || max < 1 || max > 100_000 || windowMs < 1_000 || windowMs > 86_400_000) {
        ctx.addIssue({
          code: 'custom',
          message: 'use "<máximo>/<janela>" com janela em s, m ou h (ex.: 5/15m), até 24h',
        });
        return z.NEVER;
      }
      return { max, windowMs };
    });

/** Comando para gerar um segredo forte (citado nas mensagens de erro de configuração). */
const SECRET_HINT = `gere com: node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"`;

/** Segredo obrigatório de pelo menos 32 caracteres, com mensagem que diz como resolver. */
const secret = () =>
  z
    .string({ error: `obrigatória; ${SECRET_HINT}` })
    .min(32, `precisa ter pelo menos 32 caracteres; ${SECRET_HINT}`);

export const envSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    HOST: z.string().min(1).default('127.0.0.1'),
    PORT: z.coerce.number().int().min(1).max(65535).default(3000),
    LOG_LEVEL: z
      .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'])
      .default('info'),
    CORS_ORIGINS: csvList,
    /** Padrão: ligado fora de produção e DESLIGADO em produção (mapa da API para atacantes). */
    SWAGGER_ENABLED: z.stringbool().optional(),
    TRUST_PROXY: trustProxySchema,
    DATABASE_URL: z.url({
      protocol: /^postgres(ql)?$/,
      error: 'obrigatória: URL postgresql://usuario:senha@host:porta/banco (veja .env.example)',
    }),
    REDIS_URL: z.url({
      protocol: /^rediss?$/,
      error: 'obrigatória: URL redis://host:porta (veja .env.example)',
    }),
    // HS256 com chave curta é quebrável offline a partir de um único token capturado.
    // 32 caracteres é o piso; o .env.example gera 48 bytes aleatórios (64 em base64url).
    JWT_ACCESS_SECRET: secret(),
    JWT_ACCESS_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),
    /** Validade de cada refresh token; a rotação emite um novo, limitado pela sessão. */
    REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().min(1).max(90).default(7),
    /** Validade ABSOLUTA da sessão: a rotação nunca a estende. */
    SESSION_ABSOLUTE_TTL_DAYS: z.coerce.number().int().min(1).max(365).default(30),
    /** Janela em que reapresentar um refresh já rotacionado gera 409 em vez de revogar. */
    REFRESH_REUSE_GRACE_SECONDS: z.coerce.number().int().min(0).max(60).default(10),
    // --- Rate limiting (Etapa 6) ---
    /**
     * Chave do HMAC-SHA256 que pseudonimiza IPs, emails e ids nas chaves do Redis. Precisa ser
     * ESTÁVEL (trocar zera todos os contadores) e diferente do segredo do JWT.
     */
    RATE_LIMIT_HMAC_SECRET: secret(),
    /** Namespace das chaves no Redis. Os testes usam um prefixo próprio e aleatório. */
    RATE_LIMIT_KEY_PREFIX: z
      .string()
      .regex(/^[a-z0-9][a-z0-9:_-]{0,63}$/i, 'use letras, números, ":", "_" ou "-" (até 64)')
      .default('authapi:rl'),
    RATE_LIMIT_LOGIN_IP: rateLimitSpec('5/15m'),
    RATE_LIMIT_LOGIN_ACCOUNT: rateLimitSpec('10/1h'),
    RATE_LIMIT_REGISTER_IP: rateLimitSpec('5/1h'),
    RATE_LIMIT_REFRESH_IP: rateLimitSpec('20/15m'),
    RATE_LIMIT_LOGOUT_USER: rateLimitSpec('20/15m'),
    RATE_LIMIT_LOGOUT_ALL_USER: rateLimitSpec('5/15m'),
    RATE_LIMIT_UPDATE_PROFILE_USER: rateLimitSpec('10/15m'),
    RATE_LIMIT_ADMIN_USERS: rateLimitSpec('60/1m'),
    RATE_LIMIT_ADMIN_USER_BY_ID: rateLimitSpec('60/1m'),
    RATE_LIMIT_ADMIN_AUDIT_EVENTS: rateLimitSpec('30/1m'),
    RATE_LIMIT_FORGOT_PASSWORD_IP: rateLimitSpec('5/1h'),
    RATE_LIMIT_FORGOT_PASSWORD_ACCOUNT: rateLimitSpec('3/1h'),
    RATE_LIMIT_RESET_PASSWORD_IP: rateLimitSpec('10/15m'),
    // --- Recuperação de senha e email (Etapa 7) ---
    PASSWORD_RESET_TOKEN_TTL_MINUTES: z.coerce.number().int().min(5).max(60).default(15),
    /**
     * Página do front-end que recebe o token. O token vai no FRAGMENTO (#token=...), que o
     * navegador nunca envia a servidores nem coloca no Referer.
     */
    PASSWORD_RESET_URL: z
      .url({ protocol: /^https?$/ })
      .default('http://localhost:5173/reset-password'),
    /**
     * log: registra só metadados (nunca o token; o email não é entregue).
     * dev-mailbox: grava a mensagem completa em DEV_MAILBOX_DIR para testar o fluxo localmente.
     */
    MAIL_PROVIDER: z.enum(['log', 'dev-mailbox']).default('log'),
    MAIL_FROM: z.string().min(3).max(200).default('AuthAPI Pro <no-reply@authapi.localhost>'),
    DEV_MAILBOX_DIR: z.string().min(1).default('.dev-mailbox'),
    RATE_LIMIT_ADMIN_SECURITY_ALERTS: rateLimitSpec('60/1m'),
    RATE_LIMIT_ADMIN_SECURITY_ALERT_BY_ID: rateLimitSpec('60/1m'),
    RATE_LIMIT_ADMIN_SECURITY_ALERT_EXPLAIN: rateLimitSpec('10/1m'),
    RATE_LIMIT_ADMIN_SECURITY_ALERT_UPDATE: rateLimitSpec('30/1m'),
    // --- Motor de alertas (Etapa 9) ---
    /** Liga a avaliação periódica dentro da API. Também há o comando `npm run alerts:process`. */
    ALERTS_ENGINE_ENABLED: z.stringbool().default(true),
    ALERTS_ENGINE_INTERVAL_SECONDS: z.coerce.number().int().min(10).max(3600).default(60),
    /** Eventos mais novos que isto esperam a próxima rodada (dá tempo de os INSERTs confirmarem). */
    ALERTS_ENGINE_LAG_SECONDS: z.coerce.number().int().min(0).max(300).default(5),
    /** Na primeira execução (sem checkpoint), quanto da trilha avaliar para trás. */
    ALERTS_ENGINE_INITIAL_LOOKBACK_HOURS: z.coerce.number().int().min(1).max(720).default(24),
    /** Um incidente com a mesma regra e alvo vira um único alerta dentro desta janela. */
    ALERTS_DEDUP_WINDOW_HOURS: z.coerce.number().int().min(1).max(720).default(24),
    /**
     * Eventos que confirmam atrasados (created_at antes do checkpoint) são reavaliados até
     * este prazo após o seu created_at; mais velhos são só contados e logados.
     */
    ALERTS_ENGINE_MAX_LATENESS_HOURS: z.coerce.number().int().min(1).max(168).default(24),
    /** Duração máxima de um alerta; depois, a atividade abre um alerta novo ligado ao anterior. */
    ALERTS_MAX_INCIDENT_HOURS: z.coerce.number().int().min(2).max(2160).default(168),
    // Regras no formato "<limite>/<janela>": dispara quando a contagem na janela atinge o limite.
    ALERT_BRUTE_FORCE_ACCOUNT: rateLimitSpec('8/1h'),
    ALERT_CREDENTIAL_STUFFING: rateLimitSpec('5/1h'),
    ALERT_TOKEN_REUSE: rateLimitSpec('1/24h'),
    ALERT_RATE_LIMIT_ABUSE: rateLimitSpec('3/1h'),
    ALERT_ADMIN_ACCESS_PROBING: rateLimitSpec('5/1h'),
    ALERT_PASSWORD_RESET_ABUSE: rateLimitSpec('5/1h'),
    // --- IA local opcional (explica alertas; nunca detecta nem decide) ---
    ALERTS_AI_ENABLED: z.stringbool().default(false),
    /** Só endereços locais: as evidências nunca saem da máquina. */
    OLLAMA_URL: z
      .url({ protocol: /^https?$/ })
      .default('http://127.0.0.1:11434')
      .refine(
        (value) => ['localhost', '127.0.0.1', '[::1]'].includes(new URL(value).hostname),
        'precisa ser local (localhost, 127.0.0.1 ou ::1): evidências não podem sair da máquina',
      ),
    OLLAMA_MODEL: z
      .string()
      .regex(/^[a-z0-9][a-z0-9._:-]{0,63}$/i, 'nome de modelo inválido')
      .default('qwen2.5:7b'),
    OLLAMA_TIMEOUT_MS: z.coerce.number().int().min(1000).max(120_000).default(20_000),
  })
  .superRefine((env, ctx) => {
    if (env.NODE_ENV === 'production' && env.CORS_ORIGINS.includes('*')) {
      ctx.addIssue({
        code: 'custom',
        path: ['CORS_ORIGINS'],
        message: 'wildcard "*" não é permitido em produção',
      });
    }
    if (env.NODE_ENV === 'production' && env.MAIL_PROVIDER === 'dev-mailbox') {
      ctx.addIssue({
        code: 'custom',
        path: ['MAIL_PROVIDER'],
        message: 'dev-mailbox grava tokens em disco e não é permitido em produção',
      });
    }
    if (env.NODE_ENV === 'production' && !env.PASSWORD_RESET_URL.startsWith('https://')) {
      ctx.addIssue({
        code: 'custom',
        path: ['PASSWORD_RESET_URL'],
        message: 'precisa usar https em produção (o link carrega o token)',
      });
    }
    if (env.RATE_LIMIT_HMAC_SECRET === env.JWT_ACCESS_SECRET) {
      ctx.addIssue({
        code: 'custom',
        path: ['RATE_LIMIT_HMAC_SECRET'],
        message: 'precisa ser diferente de JWT_ACCESS_SECRET',
      });
    }
    // Garante períodos de fingerprint diferentes entre um alerta e o seu sucessor.
    if (env.ALERTS_MAX_INCIDENT_HOURS < 2 * env.ALERTS_DEDUP_WINDOW_HOURS) {
      ctx.addIssue({
        code: 'custom',
        path: ['ALERTS_MAX_INCIDENT_HOURS'],
        message: 'precisa ser pelo menos o dobro de ALERTS_DEDUP_WINDOW_HOURS',
      });
    }
    if (env.REFRESH_TOKEN_TTL_DAYS > env.SESSION_ABSOLUTE_TTL_DAYS) {
      ctx.addIssue({
        code: 'custom',
        path: ['REFRESH_TOKEN_TTL_DAYS'],
        message: 'não pode ser maior que SESSION_ABSOLUTE_TTL_DAYS',
      });
    }
  })
  .transform((env) => ({
    ...env,
    SWAGGER_ENABLED: env.SWAGGER_ENABLED ?? env.NODE_ENV !== 'production',
  }));

export type Env = z.infer<typeof envSchema>;

export class EnvValidationError extends Error {
  constructor(public readonly issues: string[]) {
    super(
      `Variáveis de ambiente inválidas:\n${issues.map((issue) => `  - ${issue}`).join('\n')}\n` +
        'Dica: copie .env.example para .env (Copy-Item .env.example .env) e ajuste os valores.',
    );
    this.name = 'EnvValidationError';
  }
}

/**
 * Valida as variáveis de ambiente e falha rápido na inicialização.
 * A mensagem de erro cita apenas o nome da variável e o problema, nunca o valor,
 * para não vazar segredos em logs de inicialização.
 */
export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const result = envSchema.safeParse(source);
  if (!result.success) {
    throw new EnvValidationError(
      result.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`),
    );
  }
  return result.data;
}
