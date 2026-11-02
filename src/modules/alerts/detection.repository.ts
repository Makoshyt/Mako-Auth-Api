import { Prisma } from '../../generated/prisma/client.js';
import type { AlertSeverity } from '../../generated/prisma/enums.js';
import type { PrismaClient } from '../../infra/prisma.js';
import type { DetectionRule, GroupBy } from './alert-rules.js';

/** Cliente dentro de uma transação interativa. */
export type Tx = Omit<
  PrismaClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$extends'
>;

/** Um alvo com eventos NOVOS acima do limite (ainda não somados a nenhum alerta). */
export interface Detection {
  key: string;
  /** Maior contagem observada numa janela da região avaliada (para a severidade). */
  peak: number;
  /** Eventos acima do limite que entraram agora no livro-razão (soma em `event_count`). */
  newEvents: number;
  firstSeen: Date;
  lastSeen: Date;
  /** Até 10 ids de eventos novos (os mais recentes): referência mínima às evidências. */
  sampleEventIds: string[];
  userId: string | null;
}

/**
 * O que uma iteração avalia:
 *  - intervalo de tempo (from, to]: eventos novos pela ordem de created_at;
 *  - eventos ATRASADOS: confirmados desde o último horizonte de transações
 *    (tx_id em [txFrom, txTo)) mas com created_at <= from, isto é, num intervalo que já foi
 *    avaliado. Só os mais novos que `lateFloor` são reavaliados (os demais são contados à parte).
 */
export interface DetectionScope {
  from: Date;
  to: Date;
  /** null na primeira rodada após a migração: ainda não há horizonte para comparar. */
  txFrom: bigint | null;
  txTo: bigint;
  lateFloor: Date;
}

/** Coluna do alvo, qualificada pelo alias `e` (lista fechada; nunca vem de entrada externa). */
const COLUMN: Record<GroupBy, Prisma.Sql> = {
  email_hash: Prisma.raw('e."email_hash"'),
  ip: Prisma.raw('e."ip"'),
  user_id: Prisma.raw('e."user_id"::text'),
};

interface DetectionRow {
  key: string;
  peak: number;
  new_events: number;
  first_seen: Date;
  last_seen: Date;
  sample_ids: string[];
  user_id: string | null;
}

const lateRange = (scope: DetectionScope) =>
  scope.txFrom === null
    ? Prisma.sql`FALSE`
    : Prisma.sql`e."tx_id" >= (${scope.txFrom}::text)::xid8 AND e."tx_id" < (${scope.txTo}::text)::xid8
        AND e."created_at" <= ${scope.from} AND e."created_at" > ${scope.lateFloor}`;

/**
 * Detecção idempotente, numa única instrução:
 *
 * 1. `cand`: alvos com eventos no intervalo de tempo OU eventos atrasados; para cada alvo, a
 *    região a reavaliar começa no evento candidato mais antigo (um evento atrasado em t pode
 *    elevar a contagem de eventos em [t, t + janela]).
 * 2. `windowed`: janela deslizante EXATA para cada evento da região, olhando `windowMs` para
 *    trás (inclusive antes de `from`). Processar em pedaços ou de uma vez dá o mesmo resultado.
 * 3. `flagged`: eventos da região que atingem o limite.
 * 4. `inserted`: entram no livro-razão `detection_flagged_events` (ON CONFLICT DO NOTHING).
 *    Só o que entrou AGORA soma no alerta: reprocessar a mesma região nunca conta duas vezes.
 */
export async function findDetections(
  tx: Tx,
  rule: DetectionRule,
  scope: DetectionScope,
): Promise<Detection[]> {
  const column = COLUMN[rule.groupBy];
  const windowSecs = rule.windowMs / 1000;
  const type = Prisma.sql`${rule.eventType}::"AuditEventType"`;

  const windowed =
    rule.metric === 'count'
      ? Prisma.sql`
          SELECT c.key, e."id", e."created_at", e."user_id", c.region_start,
            count(*) OVER (
              PARTITION BY c.key ORDER BY e."created_at"
              RANGE BETWEEN make_interval(secs => ${windowSecs}) PRECEDING AND CURRENT ROW
            ) AS cnt
          FROM cand c JOIN "audit_events" e ON ${column} = c.key
          WHERE e."type" = ${type} AND e."created_at" <= ${scope.to}
            AND e."created_at" >= c.region_start - make_interval(secs => ${windowSecs})`
      : // count(DISTINCT) não existe como função de janela: subconsulta correlacionada
        // (usa o índice (ip, created_at)). O rate limit por IP mantém o volume pequeno.
        Prisma.sql`
          SELECT c.key, e."id", e."created_at", e."user_id", c.region_start,
            (SELECT count(DISTINCT e2."email_hash") FROM "audit_events" e2
              WHERE e2."type" = e."type" AND e2."ip" = e."ip"
                AND e2."created_at" >= e."created_at" - make_interval(secs => ${windowSecs})
                AND e2."created_at" <= e."created_at") AS cnt
          FROM cand c JOIN "audit_events" e ON ${column} = c.key
          WHERE e."type" = ${type} AND e."created_at" <= ${scope.to}
            AND e."created_at" >= c.region_start`;

  const rows = await tx.$queryRaw<DetectionRow[]>`
    WITH cand_rows AS (
      SELECT ${column} AS key, e."created_at" FROM "audit_events" e
      WHERE e."type" = ${type} AND ${column} IS NOT NULL
        AND e."created_at" > ${scope.from} AND e."created_at" <= ${scope.to}
      UNION ALL
      SELECT ${column} AS key, e."created_at" FROM "audit_events" e
      WHERE e."type" = ${type} AND ${column} IS NOT NULL AND ${lateRange(scope)}
    ),
    cand AS (SELECT key, min("created_at") AS region_start FROM cand_rows GROUP BY key),
    windowed AS (${windowed}),
    flagged AS (
      SELECT * FROM windowed WHERE "created_at" >= region_start AND cnt >= ${rule.threshold}
    ),
    inserted AS (
      INSERT INTO "detection_flagged_events" ("rule", "event_id", "event_created_at")
      SELECT ${rule.rule}::"AlertRule", "id", "created_at" FROM flagged
      ON CONFLICT DO NOTHING
      RETURNING "event_id"
    )
    SELECT f.key,
      max(f.cnt)::int AS peak,
      count(i."event_id")::int AS new_events,
      min(f."created_at") FILTER (WHERE i."event_id" IS NOT NULL) AS first_seen,
      max(f."created_at") FILTER (WHERE i."event_id" IS NOT NULL) AS last_seen,
      (array_agg(f."id"::text ORDER BY f."created_at" DESC)
        FILTER (WHERE i."event_id" IS NOT NULL))[1:10] AS sample_ids,
      (array_agg(f."user_id"::text ORDER BY f."created_at" DESC)
        FILTER (WHERE f."user_id" IS NOT NULL))[1] AS user_id
    FROM flagged f LEFT JOIN inserted i ON i."event_id" = f."id"
    GROUP BY f.key
    HAVING count(i."event_id") > 0`;

  return rows.map((row) => ({
    key: row.key,
    peak: row.peak,
    newEvents: row.new_events,
    firstSeen: row.first_seen,
    lastSeen: row.last_seen,
    sampleEventIds: row.sample_ids,
    userId: row.user_id,
  }));
}

/**
 * Eventos atrasados vistos nesta iteração (confirmados desde o último horizonte, com
 * created_at <= from): `reevaluated` entram na detecção; `skipped` são mais velhos que
 * `lateFloor` e só são contados (e registrados no log), nunca descartados em silêncio.
 */
export async function countLateEvents(
  tx: Tx,
  types: readonly string[],
  scope: DetectionScope,
): Promise<{ reevaluated: number; skipped: number }> {
  if (scope.txFrom === null || types.length === 0) return { reevaluated: 0, skipped: 0 };
  const typeList = Prisma.join(types.map((t) => Prisma.sql`${t}::"AuditEventType"`));
  const [row] = await tx.$queryRaw<{ reevaluated: number; skipped: number }[]>`
    SELECT count(*) FILTER (WHERE e."created_at" > ${scope.lateFloor})::int AS reevaluated,
           count(*) FILTER (WHERE e."created_at" <= ${scope.lateFloor})::int AS skipped
    FROM "audit_events" e
    WHERE e."type" IN (${typeList})
      AND e."tx_id" >= (${scope.txFrom}::text)::xid8 AND e."tx_id" < (${scope.txTo}::text)::xid8
      AND e."created_at" <= ${scope.from}`;
  return { reevaluated: row?.reevaluated ?? 0, skipped: row?.skipped ?? 0 };
}

/**
 * Poda o livro-razão: entradas de eventos anteriores a `before` não podem mais ser
 * reavaliadas (nem pelo intervalo de tempo, nem como atrasadas). Lote limitado por iteração.
 */
export async function pruneFlaggedEvents(tx: Tx, before: Date, limit = 5_000): Promise<number> {
  return tx.$executeRaw`
    DELETE FROM "detection_flagged_events" WHERE ctid IN (
      SELECT ctid FROM "detection_flagged_events"
      WHERE "event_created_at" < ${before}
      LIMIT ${limit}
    )`;
}

/** Horizonte de transações: toda transação com id menor que este já terminou. */
export async function transactionHorizon(tx: Tx): Promise<bigint> {
  const [row] = await tx.$queryRaw<{ horizon: string }[]>`
    SELECT pg_snapshot_xmin(pg_current_snapshot())::text AS horizon`;
  return BigInt(row?.horizon ?? '0');
}

export interface AlertUpsert {
  rule: DetectionRule['rule'];
  severity: AlertSeverity;
  fingerprint: string;
  summary: string;
  details: Record<string, unknown>;
  userId: string | null;
  eventCount: number;
  firstSeen: Date;
  lastSeen: Date;
  /**
   * Deduplicação deslizante: se houver um alerta OPEN do mesmo alvo e regra (`subjectKey`)
   * cuja última atividade esteja a no máximo `withinMs` de `firstSeen`, a atividade é somada a
   * ele, mesmo que o período do fingerprint seja outro. Sem isto, só o fingerprint deduplica.
   *
   * `maxIncidentMs` limita a duração de um alerta: se somar a atividade faria o alerta passar
   * desse limite, abre-se um alerta novo que aponta para o anterior (`details.previousAlertId`).
   */
  continuation?: { subjectKey: string; withinMs: number; maxIncidentMs: number };
}

/**
 * Como uma detecção é somada a um alerta existente `a`, vinda de `n` (subconsulta ou EXCLUDED).
 * Um único texto para os dois caminhos de atualização: as regras nunca divergem.
 */
const mergeSet = (n: Prisma.Sql) => Prisma.sql`
  "event_count" = a."event_count" + ${n}."event_count",
  "first_seen_at" = LEAST(a."first_seen_at", ${n}."first_seen_at"),
  "last_seen_at" = GREATEST(a."last_seen_at", ${n}."last_seen_at"),
  "severity" = GREATEST(a."severity", ${n}."severity"),
  "user_id" = COALESCE(a."user_id", ${n}."user_id"),
  "details" = a."details" || ${n}."details" || jsonb_build_object(
    'peak', GREATEST(COALESCE((a."details"->>'peak')::int, 0), (${n}."details"->>'peak')::int)
  ),
  "updated_at" = now()`;

/**
 * Grava a detecção num alerta:
 *   1. continuação: soma ao alerta OPEN mais recente do mesmo alvo e regra, se a última
 *      atividade dele estiver dentro da janela de deduplicação (incidente em andamento);
 *   2. senão, INSERT com o fingerprint do período. O índice único parcial
 *      (fingerprint WHERE status = 'OPEN') + ON CONFLICT torna isso atômico: dois INSERTs
 *      simultâneos nunca criam dois alertas abertos com o mesmo fingerprint.
 * O motor já serializa as rodadas (advisory lock); o índice é a segunda barreira.
 * A severidade só sobe (GREATEST sobre o enum, ordenado LOW < MEDIUM < HIGH).
 */
export async function upsertAlert(tx: Tx, alert: AlertUpsert): Promise<'created' | 'updated'> {
  const incoming = Prisma.sql`
    SELECT ${alert.severity}::"AlertSeverity" AS "severity", ${alert.userId}::uuid AS "user_id",
      ${alert.eventCount}::int AS "event_count", ${alert.firstSeen}::timestamptz AS "first_seen_at",
      ${alert.lastSeen}::timestamptz AS "last_seen_at", ${JSON.stringify(alert.details)}::jsonb AS "details"`;

  let details = alert.details;
  if (alert.continuation) {
    const { subjectKey, withinMs, maxIncidentMs } = alert.continuation;
    const ongoing = Prisma.sql`
      "status" = 'OPEN' AND "rule" = ${alert.rule}::"AlertRule"
      AND starts_with("fingerprint", ${`${subjectKey}:`})
      AND "last_seen_at" >= ${new Date(alert.firstSeen.getTime() - withinMs)}`;
    const continued = await tx.$executeRaw`
      UPDATE "security_alerts" AS a SET ${mergeSet(Prisma.raw('n'))}
      FROM (${incoming}) AS n
      WHERE a."id" = (
        SELECT "id" FROM "security_alerts"
        WHERE ${ongoing}
          AND "first_seen_at" >= ${new Date(alert.lastSeen.getTime() - maxIncidentMs)}
        ORDER BY "last_seen_at" DESC
        LIMIT 1
        FOR UPDATE
      )`;
    if (continued > 0) return 'updated';

    // Incidente em andamento, mas o alerta atual chegou à duração máxima: o novo alerta
    // aponta para ele, preservando a rastreabilidade de incidentes longos.
    const [previous] = await tx.$queryRaw<{ id: string }[]>`
      SELECT "id"::text AS id FROM "security_alerts" WHERE ${ongoing}
      ORDER BY "last_seen_at" DESC LIMIT 1`;
    if (previous) details = { ...details, previousAlertId: previous.id };
  }

  const [row] = await tx.$queryRaw<{ inserted: boolean }[]>`
    INSERT INTO "security_alerts" AS a (
      "id", "rule", "severity", "status", "fingerprint", "summary", "details", "user_id",
      "event_count", "first_seen_at", "last_seen_at", "created_at", "updated_at"
    ) VALUES (
      gen_random_uuid(), ${alert.rule}::"AlertRule", ${alert.severity}::"AlertSeverity", 'OPEN',
      ${alert.fingerprint}, ${alert.summary}, ${JSON.stringify(details)}::jsonb,
      ${alert.userId}::uuid, ${alert.eventCount}, ${alert.firstSeen}, ${alert.lastSeen}, now(), now()
    )
    ON CONFLICT ("fingerprint") WHERE "status" = 'OPEN' DO UPDATE SET ${mergeSet(Prisma.raw('EXCLUDED'))}
    RETURNING (xmax = 0) AS inserted`;
  return row?.inserted ? 'created' : 'updated';
}

/** Trava exclusiva da rodada (só nesta transação). false = outra instância está processando. */
export async function tryLockEngine(tx: Tx): Promise<boolean> {
  const [row] = await tx.$queryRaw<{ locked: boolean }[]>`
    SELECT pg_try_advisory_xact_lock(hashtext('authapi:security-alerts-engine')) AS locked`;
  return row?.locked === true;
}

export async function databaseNow(tx: Tx): Promise<Date> {
  const [row] = await tx.$queryRaw<{ now: Date }[]>`SELECT now() AS now`;
  return row?.now ?? new Date();
}

export interface Checkpoint {
  processedUntil: Date;
  /** null em checkpoints anteriores ao horizonte de transações (Etapa 10). */
  txHorizon: bigint | null;
}

export async function readCheckpoint(tx: Tx, name: string): Promise<Checkpoint | null> {
  const row = await tx.detectionCheckpoint.findUnique({ where: { name } });
  return row ? { processedUntil: row.processedUntil, txHorizon: row.txHorizon } : null;
}

export async function writeCheckpoint(tx: Tx, name: string, checkpoint: Checkpoint): Promise<void> {
  await tx.detectionCheckpoint.upsert({
    where: { name },
    create: { name, ...checkpoint },
    update: checkpoint,
  });
}
