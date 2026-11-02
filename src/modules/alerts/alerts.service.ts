import { notFound } from '../../shared/errors.js';
import type { AdminActor } from '../admin/admin.service.js';
import type { AuditRecorder } from '../audit/audit.recorder.js';
import type { AlertEvidence, AlertExplainer, ExplainResult } from './alert-explainer.js';
import type { AlertView, AlertsRepository, ListAlertsQuery } from './alerts.repository.js';

export interface AlertsServiceDeps {
  repository: AlertsRepository;
  explainer: AlertExplainer;
  audit: AuditRecorder;
}

export type AlertsService = ReturnType<typeof createAlertsService>;

const numberOr = (value: unknown, fallback: number) =>
  typeof value === 'number' && Number.isFinite(value) ? value : fallback;

/**
 * Minimização para a IA: só natureza e intensidade. O `subject` (IP ou id de usuário), os ids
 * de eventos e as datas absolutas ficam de fora.
 */
export function toEvidence(alert: AlertView): AlertEvidence {
  const details = (alert.details ?? {}) as Record<string, unknown>;
  const subject = (details.subject ?? {}) as { kind?: unknown };
  return {
    rule: alert.rule,
    severity: alert.severity,
    status: alert.status,
    summary: alert.summary,
    threshold: numberOr(details.threshold, 0),
    windowSeconds: numberOr(details.windowSeconds, 0),
    peak: numberOr(details.peak, 0),
    eventCount: alert.eventCount,
    durationSeconds: Math.round((alert.lastSeenAt.getTime() - alert.firstSeenAt.getTime()) / 1000),
    subjectKind: subject.kind === 'ip' || subject.kind === 'user' ? subject.kind : 'account',
  };
}

/**
 * Consultas administrativas de alertas (somente leitura). Não há exclusão, resolução
 * automática nem ação contra usuários. Cada consulta concluída gera UM evento de auditoria,
 * depois da leitura; o motor de regras não lê esse tipo de evento (sem alerta de alerta).
 */
export function createAlertsService({ repository, explainer, audit }: AlertsServiceDeps) {
  const record = (actor: AdminActor, metadata: Record<string, string | number | boolean>) =>
    audit.record({
      type: 'ADMIN_SECURITY_ALERTS_QUERIED',
      userId: actor.userId,
      ip: actor.ip,
      metadata,
    });

  async function getOrThrow(id: string): Promise<AlertView> {
    const alert = await repository.findById(id);
    if (!alert) throw notFound('Alerta não encontrado');
    return alert;
  }

  return {
    async list(query: ListAlertsQuery, actor: AdminActor) {
      const page = await repository.list(query);
      await record(actor, {
        action: 'LIST',
        page: query.page,
        pageSize: query.pageSize,
        ...(query.rule !== undefined && { rule: query.rule }),
        ...(query.severity !== undefined && { severity: query.severity }),
        ...(query.status !== undefined && { status: query.status }),
        resultCount: page.items.length,
      });
      return page;
    },

    async get(id: string, actor: AdminActor) {
      const alert = await repository.findById(id);
      await record(actor, { action: 'VIEW', alertId: id, found: alert !== null });
      if (!alert) throw notFound('Alerta não encontrado');
      return alert;
    },

    /** Explicação sob demanda. Não é gravada e não altera o alerta. */
    async explain(id: string, actor: AdminActor): Promise<ExplainResult> {
      const alert = await getOrThrow(id);
      const result = await explainer.explain(toEvidence(alert));
      await record(actor, { action: 'EXPLAIN', alertId: id, aiStatus: result.status });
      return result;
    },
  };
}
