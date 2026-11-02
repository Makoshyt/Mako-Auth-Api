import type { Env } from '../../config/env.js';
import type { PrismaClient } from '../../infra/prisma.js';
import {
  buildDetectionRules,
  fingerprintFor,
  severityFor,
  subjectKeyFor,
  summaryFor,
  type DetectionRule,
} from './alert-rules.js';
import {
  countLateEvents,
  databaseNow,
  findDetections,
  pruneFlaggedEvents,
  readCheckpoint,
  transactionHorizon,
  tryLockEngine,
  upsertAlert,
  writeCheckpoint,
  type DetectionScope,
} from './detection.repository.js';

export const CHECKPOINT_NAME = 'security-alerts';

export interface EngineConfig {
  rules: DetectionRule[];
  lagMs: number;
  initialLookbackMs: number;
  dedupWindowMs: number;
  /**
   * Até quanto tempo depois do seu created_at um evento que confirmou atrasado ainda é
   * reavaliado. Mais velhos que isso são contados em `skippedLateEvents` (e logados).
   * Padrão: 24 h.
   */
  maxLatenessMs?: number;
  /** Duração máxima de um alerta; depois disso a atividade abre um alerta novo. Padrão: 7 dias. */
  maxIncidentMs?: number;
  /** Maior intervalo avaliado por transação (as consultas ficam curtas mesmo após paradas longas). */
  maxRangeMs?: number;
  /** Teto de intervalos por rodada; o restante fica para a próxima. */
  maxIterations?: number;
}

export interface RunResult {
  /** false se outra instância estava processando (nada foi feito). */
  acquired: boolean;
  iterations: number;
  created: number;
  updated: number;
  processedUntil: Date | null;
  /** true se ainda há eventos antigos esperando (atingiu maxIterations). */
  behind: boolean;
  /** Eventos que confirmaram depois do checkpoint de created_at e foram reavaliados. */
  lateEvents: number;
  /** Eventos atrasados demais (além de maxLatenessMs): não reavaliados, só contados. */
  skippedLateEvents: number;
}

const HOUR_MS = 3_600_000;

/** Configuração do motor a partir do ambiente: a mesma na API e no `npm run alerts:process`. */
export function engineConfigFromEnv(env: Env): EngineConfig {
  return {
    rules: buildDetectionRules(env),
    lagMs: env.ALERTS_ENGINE_LAG_SECONDS * 1000,
    initialLookbackMs: env.ALERTS_ENGINE_INITIAL_LOOKBACK_HOURS * HOUR_MS,
    dedupWindowMs: env.ALERTS_DEDUP_WINDOW_HOURS * HOUR_MS,
    maxLatenessMs: env.ALERTS_ENGINE_MAX_LATENESS_HOURS * HOUR_MS,
    maxIncidentMs: env.ALERTS_MAX_INCIDENT_HOURS * HOUR_MS,
  };
}

/**
 * Uma rodada do motor. Cada iteração, numa única transação:
 *   1. trava a rodada (advisory lock): só uma instância processa por vez;
 *   2. lê o checkpoint: `from` (created_at já avaliado) e o horizonte de transações anterior;
 *      define (from, to], com to = now() do banco - lag, e o novo horizonte
 *      (pg_snapshot_xmin: toda transação com id menor já terminou);
 *   3. avalia as regras sobre o intervalo de tempo E sobre os eventos que confirmaram desde o
 *      horizonte anterior com created_at <= from (eventos atrasados);
 *   4. cada evento acima do limite entra no livro-razão uma única vez: só os novos somam;
 *   5. avança o checkpoint (created_at e horizonte) e poda o livro-razão.
 * Se algo falhar, nada é confirmado (alertas, livro-razão, checkpoint) e a próxima rodada
 * reprocessa: nenhum evento é perdido e nenhum é contado duas vezes.
 */
export async function runDetection(prisma: PrismaClient, config: EngineConfig): Promise<RunResult> {
  const maxRangeMs = config.maxRangeMs ?? 6 * HOUR_MS;
  const maxIterations = config.maxIterations ?? 24;
  const maxLatenessMs = config.maxLatenessMs ?? 24 * HOUR_MS;
  const maxIncidentMs = config.maxIncidentMs ?? 7 * 24 * HOUR_MS;
  const eventTypes = [...new Set(config.rules.map((rule) => rule.eventType))];
  const result: RunResult = {
    acquired: true,
    iterations: 0,
    created: 0,
    updated: 0,
    processedUntil: null,
    behind: false,
    lateEvents: 0,
    skippedLateEvents: 0,
  };

  while (result.iterations < maxIterations) {
    const step = await prisma.$transaction(
      async (tx) => {
        if (!(await tryLockEngine(tx))) return { locked: false as const };
        // Horizonte ANTES das leituras: tudo abaixo dele já está confirmado e visível a elas.
        const horizon = await transactionHorizon(tx);
        const now = await databaseNow(tx);
        const target = new Date(now.getTime() - config.lagMs);
        const checkpoint = await readCheckpoint(tx, CHECKPOINT_NAME);
        const from =
          checkpoint?.processedUntil ?? new Date(now.getTime() - config.initialLookbackMs);
        // Sem horizonte anterior (primeira rodada após a migração): nada é tratado como atrasado.
        const previousHorizon = checkpoint?.txHorizon ?? null;
        const to = new Date(
          Math.max(from.getTime(), Math.min(target.getTime(), from.getTime() + maxRangeMs)),
        );
        const scope: DetectionScope = {
          from,
          to,
          txFrom: previousHorizon !== null && previousHorizon < horizon ? previousHorizon : null,
          txTo: horizon,
          lateFloor: new Date(now.getTime() - maxLatenessMs),
        };

        const late = await countLateEvents(tx, eventTypes, scope);
        let created = 0;
        let updated = 0;
        for (const rule of config.rules) {
          for (const detection of await findDetections(tx, rule, scope)) {
            const outcome = await upsertAlert(tx, {
              rule: rule.rule,
              severity: severityFor(rule, detection.peak),
              fingerprint: fingerprintFor(
                rule.rule,
                detection.key,
                detection.firstSeen,
                config.dedupWindowMs,
              ),
              summary: summaryFor(rule),
              details: {
                threshold: rule.threshold,
                windowSeconds: rule.windowMs / 1000,
                peak: detection.peak,
                eventType: rule.eventType,
                // Alvo: id do usuário quando existe; IP só nas regras em que ele É o alvo.
                // Nunca email nem hash de email.
                subject:
                  rule.groupBy === 'ip'
                    ? { kind: 'ip', ip: detection.key }
                    : rule.groupBy === 'user_id'
                      ? { kind: 'user', userId: detection.key }
                      : { kind: 'account', userId: detection.userId },
                sampleEventIds: detection.sampleEventIds,
              },
              userId: rule.groupBy === 'ip' ? null : detection.userId,
              eventCount: detection.newEvents,
              firstSeen: detection.firstSeen,
              lastSeen: detection.lastSeen,
              // Incidente em andamento continua no mesmo alerta, mesmo virando o período,
              // até a duração máxima.
              continuation: {
                subjectKey: subjectKeyFor(rule.rule, detection.key),
                withinMs: config.dedupWindowMs,
                maxIncidentMs,
              },
            });
            if (outcome === 'created') created++;
            else updated++;
          }
        }
        await writeCheckpoint(tx, CHECKPOINT_NAME, {
          processedUntil: to,
          // O horizonte nunca recua (defesa extra; pg_snapshot_xmin já é monotônico).
          txHorizon:
            previousHorizon !== null && previousHorizon > horizon ? previousHorizon : horizon,
        });
        // Antes disto, nenhum evento volta a ser avaliado (nem pelo tempo, nem como atrasado).
        await pruneFlaggedEvents(
          tx,
          new Date(Math.min(from.getTime(), scope.lateFloor.getTime()) - HOUR_MS),
        );
        return {
          locked: true as const,
          done: to.getTime() >= target.getTime(),
          to,
          created,
          updated,
          late,
        };
      },
      { timeout: 60_000, maxWait: 10_000 },
    );

    if (!step.locked) {
      result.acquired = result.iterations > 0;
      return result;
    }
    result.iterations++;
    result.created += step.created;
    result.updated += step.updated;
    result.lateEvents += step.late.reevaluated;
    result.skippedLateEvents += step.late.skipped;
    result.processedUntil = step.to;
    if (step.done) return result;
  }
  result.behind = true;
  return result;
}

export interface EngineScheduler {
  start(): void;
  stop(): Promise<void>;
  /** Executa uma rodada agora (sem sobrepor uma em andamento). */
  runOnce(): Promise<RunResult | null>;
}

/**
 * Agenda rodadas periódicas dentro do processo. Nunca sobrepõe rodadas, não segura o event
 * loop (unref) e não derruba o processo: erros vão para `onError` e a próxima rodada tenta de
 * novo a partir do checkpoint persistido.
 */
export function createEngineScheduler(
  run: () => Promise<RunResult>,
  intervalMs: number,
  onResult: (result: RunResult) => void,
  onError: (error: unknown) => void,
): EngineScheduler {
  let timer: NodeJS.Timeout | null = null;
  let current: Promise<RunResult | null> | null = null;

  const runOnce = () => {
    current ??= run()
      .then((result) => {
        onResult(result);
        return result;
      })
      .catch((error: unknown) => {
        onError(error);
        return null;
      })
      .finally(() => {
        current = null;
      });
    return current;
  };

  return {
    start() {
      if (timer) return;
      timer = setInterval(() => void runOnce(), intervalMs);
      timer.unref();
      void runOnce();
    },
    async stop() {
      if (timer) clearInterval(timer);
      timer = null;
      await current;
    },
    runOnce,
  };
}
