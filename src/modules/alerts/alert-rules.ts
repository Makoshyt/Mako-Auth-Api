import { createHash } from 'node:crypto';
import type { Env } from '../../config/env.js';
import type { AlertRule, AlertSeverity, AuditEventType } from '../../generated/prisma/enums.js';

/**
 * Coluna de `audit_events` que identifica o alvo do incidente. Lista fechada: o nome vai para
 * o SQL como identificador, então nunca vem de entrada externa.
 */
export type GroupBy = 'email_hash' | 'ip' | 'user_id';

/**
 * count: eventos do alvo na janela.
 * distinct_email: contas (email_hash) distintas do alvo na janela (ex.: um IP testando várias).
 */
export type Metric = 'count' | 'distinct_email';

export interface DetectionRule {
  rule: AlertRule;
  /** Único tipo de evento lido pela regra. O motor nunca lê alertas nem eventos que ele gere. */
  eventType: AuditEventType;
  groupBy: GroupBy;
  metric: Metric;
  threshold: number;
  windowMs: number;
  /** Severidade ao atingir o limite e ao atingir o dobro dele (nunca rebaixa). */
  severity: AlertSeverity;
  escalatedSeverity: AlertSeverity;
  /** Texto fixo, sem dados do alvo: o número e a janela vêm da configuração. */
  describe: (threshold: number, window: string) => string;
}

const formatWindow = (ms: number) =>
  ms % 3_600_000 === 0
    ? `${ms / 3_600_000} h`
    : ms % 60_000 === 0
      ? `${ms / 60_000} min`
      : `${ms / 1000} s`;

type RuleShape = Omit<DetectionRule, 'threshold' | 'windowMs'> & {
  envKey:
    | 'ALERT_BRUTE_FORCE_ACCOUNT'
    | 'ALERT_CREDENTIAL_STUFFING'
    | 'ALERT_TOKEN_REUSE'
    | 'ALERT_RATE_LIMIT_ABUSE'
    | 'ALERT_ADMIN_ACCESS_PROBING'
    | 'ALERT_PASSWORD_RESET_ABUSE';
};

const RULES: RuleShape[] = [
  {
    rule: 'BRUTE_FORCE_ACCOUNT',
    envKey: 'ALERT_BRUTE_FORCE_ACCOUNT',
    eventType: 'LOGIN_FAILURE',
    groupBy: 'email_hash',
    metric: 'count',
    severity: 'MEDIUM',
    escalatedSeverity: 'HIGH',
    describe: (n, w) => `${n} ou mais falhas de login para a mesma conta em ${w}`,
  },
  {
    rule: 'CREDENTIAL_STUFFING',
    envKey: 'ALERT_CREDENTIAL_STUFFING',
    eventType: 'LOGIN_FAILURE',
    groupBy: 'ip',
    metric: 'distinct_email',
    severity: 'HIGH',
    escalatedSeverity: 'HIGH',
    describe: (n, w) =>
      `Falhas de login em ${n} ou mais contas diferentes a partir do mesmo IP em ${w}`,
  },
  {
    rule: 'TOKEN_REUSE',
    envKey: 'ALERT_TOKEN_REUSE',
    eventType: 'TOKEN_REUSE_DETECTED',
    groupBy: 'user_id',
    metric: 'count',
    severity: 'HIGH',
    escalatedSeverity: 'HIGH',
    describe: (n, w) =>
      `Refresh token reutilizado fora da janela de tolerância (${n} ou mais vezes em ${w}); a sessão foi revogada`,
  },
  {
    rule: 'RATE_LIMIT_ABUSE',
    envKey: 'ALERT_RATE_LIMIT_ABUSE',
    eventType: 'RATE_LIMIT_EXCEEDED',
    groupBy: 'ip',
    metric: 'count',
    severity: 'LOW',
    escalatedSeverity: 'MEDIUM',
    describe: (n, w) => `O mesmo IP foi bloqueado pelo rate limit ${n} ou mais vezes em ${w}`,
  },
  {
    rule: 'ADMIN_ACCESS_PROBING',
    envKey: 'ALERT_ADMIN_ACCESS_PROBING',
    eventType: 'ACCESS_DENIED',
    groupBy: 'user_id',
    metric: 'count',
    severity: 'MEDIUM',
    escalatedSeverity: 'HIGH',
    describe: (n, w) =>
      `Um usuário sem permissão tentou rotas administrativas ${n} ou mais vezes em ${w}`,
  },
  {
    rule: 'PASSWORD_RESET_ABUSE',
    envKey: 'ALERT_PASSWORD_RESET_ABUSE',
    eventType: 'PASSWORD_RESET_REQUEST',
    groupBy: 'ip',
    metric: 'count',
    severity: 'LOW',
    escalatedSeverity: 'MEDIUM',
    describe: (n, w) => `${n} ou mais pedidos de recuperação de senha a partir do mesmo IP em ${w}`,
  },
];

export function buildDetectionRules(env: Env): DetectionRule[] {
  return RULES.map(({ envKey, ...rule }) => ({
    ...rule,
    threshold: env[envKey].max,
    windowMs: env[envKey].windowMs,
  }));
}

export function severityFor(rule: DetectionRule, peak: number): AlertSeverity {
  return peak >= rule.threshold * 2 ? rule.escalatedSeverity : rule.severity;
}

export function summaryFor(rule: DetectionRule): string {
  return rule.describe(rule.threshold, formatWindow(rule.windowMs));
}

/**
 * Regra + alvo, com o alvo só como hash (nunca IP nem email em texto). É o prefixo comum a
 * todos os alertas do mesmo alvo e regra, usado para continuar um incidente em andamento.
 */
export function subjectKeyFor(rule: AlertRule, key: string): string {
  return `${rule}:${createHash('sha256').update(`${rule}:${key}`).digest('hex').slice(0, 32)}`;
}

/**
 * Identidade de um alerta novo: regra + alvo + período em que o incidente começou. O período
 * só dá unicidade ao INSERT (índice único parcial); quem decide se a atividade continua um
 * alerta aberto é a janela deslizante em `upsertAlert`, então virar o período não parte o
 * incidente em dois.
 */
export function fingerprintFor(
  rule: AlertRule,
  key: string,
  at: Date,
  dedupWindowMs: number,
): string {
  return `${subjectKeyFor(rule, key)}:${Math.floor(at.getTime() / dedupWindowMs)}`;
}
