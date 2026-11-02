import type { PrismaClient } from '../../infra/prisma.js';
import {
  fingerprintFor,
  severityFor,
  subjectKeyFor,
  summaryFor,
  type DetectionRule,
} from './alert-rules.js';
import {
  databaseNow,
  findDetections,
  readCheckpoint,
  tryLockEngine,
  upsertAlert,
  writeCheckpoint,
} from './detection.repository.js';

export const CHECKPOINT_NAME = 'security-alerts';

export interface EngineConfig {
  rules: DetectionRule[];
  lagMs: number;
  initialLookbackMs: number;
  dedupWindowMs: number;
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
}

/**
 * Uma rodada do motor. Cada iteração, numa única transação:
 *   1. trava a rodada (advisory lock): só uma instância processa um intervalo;
 *   2. lê o checkpoint e define (from, to], com to = now() do banco - lag;
 *   3. avalia todas as regras nesse intervalo e grava/soma os alertas;
 *   4. avança o checkpoint para `to`.
 * Se algo falhar, nada do intervalo é confirmado (nem alertas, nem checkpoint) e a próxima
 * rodada reprocessa o mesmo intervalo: nenhum evento é perdido e nenhum é contado duas vezes.
 */
export async function runDetection(prisma: PrismaClient, config: EngineConfig): Promise<RunResult> {
  const maxRangeMs = config.maxRangeMs ?? 6 * 3_600_000;
  const maxIterations = config.maxIterations ?? 24;
  const result: RunResult = {
    acquired: true,
    iterations: 0,
    created: 0,
    updated: 0,
    processedUntil: null,
    behind: false,
  };

  while (result.iterations < maxIterations) {
    const step = await prisma.$transaction(
      async (tx) => {
        if (!(await tryLockEngine(tx))) return { locked: false as const };
        const now = await databaseNow(tx);
        const target = new Date(now.getTime() - config.lagMs);
        const from =
          (await readCheckpoint(tx, CHECKPOINT_NAME)) ??
          new Date(now.getTime() - config.initialLookbackMs);
        if (target <= from)
          return { locked: true as const, done: true, to: from, created: 0, updated: 0 };

        const to = new Date(Math.min(target.getTime(), from.getTime() + maxRangeMs));
        let created = 0;
        let updated = 0;
        for (const rule of config.rules) {
          for (const detection of await findDetections(tx, rule, from, to)) {
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
              // Incidente em andamento continua no mesmo alerta, mesmo virando o período.
              continuation: {
                subjectKey: subjectKeyFor(rule.rule, detection.key),
                withinMs: config.dedupWindowMs,
              },
            });
            if (outcome === 'created') created++;
            else updated++;
          }
        }
        await writeCheckpoint(tx, CHECKPOINT_NAME, to);
        return {
          locked: true as const,
          done: to.getTime() >= target.getTime(),
          to,
          created,
          updated,
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
