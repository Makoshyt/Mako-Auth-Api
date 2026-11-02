import { z } from 'zod';
import { AlertRule, AlertSeverity, AlertStatus } from '../../generated/prisma/enums.js';
import { MAX_PAGE, MAX_PAGE_SIZE, DEFAULT_PAGE_SIZE } from '../admin/admin.schemas.js';
import type { ExplainResult } from './alert-explainer.js';
import type { AlertView } from './alerts.repository.js';

/** strictObject: parâmetro desconhecido ou repetido gera 400. */
export const listAlertsQuerySchema = z.strictObject({
  page: z.coerce.number().int().min(1).max(MAX_PAGE).default(1),
  pageSize: z.coerce
    .number()
    .int()
    .min(1)
    .max(MAX_PAGE_SIZE, `pageSize pode ser no máximo ${MAX_PAGE_SIZE}`)
    .default(DEFAULT_PAGE_SIZE),
  rule: z.enum(AlertRule).optional(),
  severity: z.enum(AlertSeverity).optional(),
  status: z.enum(AlertStatus).optional(),
  order: z.enum(['asc', 'desc']).default('desc'),
});

export const alertIdParamsSchema = z.strictObject({ id: z.uuid('id precisa ser um UUID') });

/**
 * Única transição permitida por HTTP: OPEN -> RESOLVED. RESOLVED é terminal (atividade nova
 * abre outro alerta). Não há exclusão. A nota é texto puro: caracteres de controle viram
 * espaço, espaços repetidos são reduzidos, até 500 caracteres.
 */
export const updateAlertBodySchema = z.strictObject({
  status: z.literal('RESOLVED', 'a única transição permitida é para RESOLVED'),
  note: z
    .string()
    .max(2000)
    .transform((value) =>
      value
        .replace(/[\p{Cc}\p{Cf}]/gu, ' ')
        .replace(/\s+/g, ' ')
        .trim(),
    )
    .pipe(
      z.string().min(1, 'note não pode ficar vazia').max(500, 'note pode ter até 500 caracteres'),
    )
    .optional(),
});

export const securityAlertSchema = z
  .object({
    id: z.uuid(),
    rule: z.enum(AlertRule),
    severity: z.enum(AlertSeverity),
    status: z.enum(AlertStatus),
    summary: z.string(),
    details: z.record(z.string(), z.unknown()),
    userId: z.uuid().nullable(),
    eventCount: z.number().int(),
    firstSeenAt: z.iso.datetime(),
    lastSeenAt: z.iso.datetime(),
    resolvedAt: z.iso.datetime().nullable(),
    resolvedById: z.uuid().nullable(),
    resolutionNote: z.string().nullable(),
    createdAt: z.iso.datetime(),
    updatedAt: z.iso.datetime(),
  })
  .meta({ id: 'SecurityAlert' });

/**
 * Consulta individual: inclui quais `details.sampleEventIds` ainda existem na auditoria. Os ids
 * são referências opacas; a retenção da auditoria pode apagar os eventos, e isso nunca é erro.
 */
export const securityAlertDetailSchema = securityAlertSchema
  .extend({ retainedSampleEventIds: z.array(z.uuid()) })
  .meta({ id: 'SecurityAlertDetail' });

export const securityAlertListSchema = z
  .object({
    data: z.array(securityAlertSchema),
    pagination: z.object({
      page: z.number().int(),
      pageSize: z.number().int(),
      total: z.number().int(),
      totalPages: z.number().int(),
    }),
  })
  .meta({ id: 'SecurityAlertList' });

export const explanationResponseSchema = z
  .object({
    status: z.enum(['ok', 'disabled', 'unavailable']),
    /** Sempre true: texto gerado por IA, para apoio; não é decisão nem evidência. */
    advisory: z.literal(true),
    model: z.string().optional(),
    reason: z.enum(['TIMEOUT', 'UNREACHABLE', 'INVALID_RESPONSE']).optional(),
    explanation: z
      .object({
        summary: z.string(),
        likelyCauses: z.array(z.string()),
        suggestedChecks: z.array(z.string()),
      })
      .optional(),
  })
  .meta({ id: 'SecurityAlertExplanation' });

const asRecord = (value: unknown): Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};

/** Campo a campo, sem spread: o fingerprint e campos futuros não saem por acidente. */
export function toAlertDto(alert: AlertView) {
  return {
    id: alert.id,
    rule: alert.rule,
    severity: alert.severity,
    status: alert.status,
    summary: alert.summary,
    details: asRecord(alert.details),
    userId: alert.userId,
    eventCount: alert.eventCount,
    firstSeenAt: alert.firstSeenAt.toISOString(),
    lastSeenAt: alert.lastSeenAt.toISOString(),
    resolvedAt: alert.resolvedAt?.toISOString() ?? null,
    resolvedById: alert.resolvedById,
    resolutionNote: alert.resolutionNote,
    createdAt: alert.createdAt.toISOString(),
    updatedAt: alert.updatedAt.toISOString(),
  };
}

/** `details.sampleEventIds` como lista de strings, tolerando dados antigos ou malformados. */
export function sampleEventIdsOf(alert: AlertView): string[] {
  const ids = asRecord(alert.details).sampleEventIds;
  return Array.isArray(ids) ? ids.filter((id): id is string => typeof id === 'string') : [];
}

export function toAlertDetailDto(alert: AlertView, retainedSampleEventIds: readonly string[]) {
  const retained = new Set(retainedSampleEventIds);
  return {
    ...toAlertDto(alert),
    // Na ordem original dos ids, só os que ainda existem.
    retainedSampleEventIds: sampleEventIdsOf(alert).filter((id) => retained.has(id)),
  };
}

export function toExplanationDto(result: ExplainResult) {
  return {
    advisory: true as const,
    ...(result.status === 'ok'
      ? { status: 'ok' as const, model: result.model, explanation: result.explanation }
      : result.status === 'unavailable'
        ? { status: 'unavailable' as const, reason: result.reason }
        : { status: 'disabled' as const }),
  };
}
