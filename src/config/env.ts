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

export const envSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    HOST: z.string().min(1).default('127.0.0.1'),
    PORT: z.coerce.number().int().min(1).max(65535).default(3000),
    LOG_LEVEL: z
      .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'])
      .default('info'),
    CORS_ORIGINS: csvList,
    SWAGGER_ENABLED: z.stringbool().default(true),
    TRUST_PROXY: z.stringbool().default(false),
    DATABASE_URL: z.url({ protocol: /^postgres(ql)?$/ }),
    REDIS_URL: z.url({ protocol: /^rediss?$/ }),
    // HS256 com chave curta é quebrável offline a partir de um único token capturado.
    // 32 caracteres é o piso; o .env.example gera 48 bytes aleatórios (64 em base64url).
    JWT_ACCESS_SECRET: z.string().min(32, 'precisa ter pelo menos 32 caracteres'),
    JWT_ACCESS_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),
    /** Validade de cada refresh token; a rotação emite um novo, limitado pela sessão. */
    REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().min(1).max(90).default(7),
    /** Validade ABSOLUTA da sessão: a rotação nunca a estende. */
    SESSION_ABSOLUTE_TTL_DAYS: z.coerce.number().int().min(1).max(365).default(30),
    /** Janela em que reapresentar um refresh já rotacionado gera 409 em vez de revogar. */
    REFRESH_REUSE_GRACE_SECONDS: z.coerce.number().int().min(0).max(60).default(10),
  })
  .superRefine((env, ctx) => {
    if (env.NODE_ENV === 'production' && env.CORS_ORIGINS.includes('*')) {
      ctx.addIssue({
        code: 'custom',
        path: ['CORS_ORIGINS'],
        message: 'wildcard "*" não é permitido em produção',
      });
    }
    if (env.REFRESH_TOKEN_TTL_DAYS > env.SESSION_ABSOLUTE_TTL_DAYS) {
      ctx.addIssue({
        code: 'custom',
        path: ['REFRESH_TOKEN_TTL_DAYS'],
        message: 'não pode ser maior que SESSION_ABSOLUTE_TTL_DAYS',
      });
    }
  });

export type Env = z.infer<typeof envSchema>;

export class EnvValidationError extends Error {
  constructor(public readonly issues: string[]) {
    super(`Variáveis de ambiente inválidas:\n${issues.map((issue) => `  - ${issue}`).join('\n')}`);
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
