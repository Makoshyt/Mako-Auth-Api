import { Prisma } from '../../generated/prisma/client.js';
import type { AlertSeverity } from '../../generated/prisma/enums.js';
import type { PrismaClient } from '../../infra/prisma.js';
import type { DetectionRule, GroupBy } from './alert-rules.js';

/** Cliente dentro de uma transação interativa. */
export type Tx = Omit<
  PrismaClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$extends'
>;

/** Um alvo que atingiu o limite da regra dentro do intervalo avaliado. */
export interface Detection {
  key: string;
  /** Maior contagem observada numa janela (para a severidade). */
  peak: number;
  /** Eventos do intervalo que estavam acima do limite (soma em `event_count`). */
  newEvents: number;
  firstSeen: Date;
  lastSeen: Date;
  /** Até 10 ids de eventos (os mais recentes): referência mínima às evidências. */
  sampleEventIds: string[];
  userId: string | null;
}

const COLUMN: Record<GroupBy, Prisma.Sql> = {
  email_hash: Prisma.raw('"email_hash"'),
  ip: Prisma.raw('"ip"'),
  user_id: Prisma.raw('"user_id"::text'),
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

/**
 * Janela deslizante EXATA para cada evento do intervalo (from, to]: para cada evento, conta os
 * eventos do mesmo alvo nos `windowMs` anteriores, inclusive os que ficaram antes de `from`
 * (por isso a leitura começa em from - janela). Assim, processar o intervalo inteiro de uma vez
 * ou em pedaços dá o mesmo resultado, o que torna a retomada após reinício correta.
 */
export async function findDetections(
  tx: Tx,
  rule: DetectionRule,
  from: Date,
  to: Date,
): Promise<Detection[]> {
  const column = COLUMN[rule.groupBy];
  const windowSecs = rule.windowMs / 1000;
  const lookbackFrom = new Date(from.getTime() - rule.windowMs);

  const windowed =
    rule.metric === 'count'
      ? Prisma.sql`
          SELECT ${column} AS key, "id", "created_at", "user_id",
            count(*) OVER (
              PARTITION BY ${column} ORDER BY "created_at"
              RANGE BETWEEN make_interval(secs => ${windowSecs}) PRECEDING AND CURRENT ROW
            ) AS cnt
          FROM "audit_events"
          WHERE "type" = ${rule.eventType}::"AuditEventType" AND ${column} IS NOT NULL
            AND "created_at" > ${lookbackFrom} AND "created_at" <= ${to}`
      : // count(DISTINCT) não existe como função de janela: subconsulta correlacionada
        // (usa o índice (ip, created_at)). O rate limit por IP mantém o volume pequeno.
        Prisma.sql`
          SELECT ${column} AS key, e."id", e."created_at", e."user_id",
            (SELECT count(DISTINCT e2."email_hash") FROM "audit_events" e2
              -- Limite inferior inclusivo, como o RANGE … PRECEDING da métrica count.
              WHERE e2."type" = e."type" AND e2."ip" = e."ip"
                AND e2."created_at" >= e."created_at" - make_interval(secs => ${windowSecs})
                AND e2."created_at" <= e."created_at") AS cnt
          FROM "audit_events" e
          WHERE e."type" = ${rule.eventType}::"AuditEventType" AND e.${column} IS NOT NULL
            AND e."created_at" > ${from} AND e."created_at" <= ${to}`;

  const rows = await tx.$queryRaw<DetectionRow[]>`
    SELECT key,
      max(cnt)::int AS peak,
      count(*)::int AS new_events,
      min("created_at") AS first_seen,
      max("created_at") AS last_seen,
      (array_agg("id"::text ORDER BY "created_at" DESC))[1:10] AS sample_ids,
      (array_agg("user_id"::text ORDER BY "created_at" DESC) FILTER (WHERE "user_id" IS NOT NULL))[1] AS user_id
    FROM (${windowed}) w
    WHERE "created_at" > ${from} AND cnt >= ${rule.threshold}
    GROUP BY key`;

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
   */
  continuation?: { subjectKey: string; withinMs: number };
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
  "details" = ${n}."details" || jsonb_build_object(
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

  if (alert.continuation) {
    const { subjectKey, withinMs } = alert.continuation;
    const continued = await tx.$executeRaw`
      UPDATE "security_alerts" AS a SET ${mergeSet(Prisma.raw('n'))}
      FROM (${incoming}) AS n
      WHERE a."id" = (
        SELECT "id" FROM "security_alerts"
        WHERE "status" = 'OPEN' AND "rule" = ${alert.rule}::"AlertRule"
          AND starts_with("fingerprint", ${`${subjectKey}:`})
          AND "last_seen_at" >= ${new Date(alert.firstSeen.getTime() - withinMs)}
        ORDER BY "last_seen_at" DESC
        LIMIT 1
        FOR UPDATE
      )`;
    if (continued > 0) return 'updated';
  }

  const [row] = await tx.$queryRaw<{ inserted: boolean }[]>`
    INSERT INTO "security_alerts" AS a (
      "id", "rule", "severity", "status", "fingerprint", "summary", "details", "user_id",
      "event_count", "first_seen_at", "last_seen_at", "created_at", "updated_at"
    ) VALUES (
      gen_random_uuid(), ${alert.rule}::"AlertRule", ${alert.severity}::"AlertSeverity", 'OPEN',
      ${alert.fingerprint}, ${alert.summary}, ${JSON.stringify(alert.details)}::jsonb,
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

export async function readCheckpoint(tx: Tx, name: string): Promise<Date | null> {
  const row = await tx.detectionCheckpoint.findUnique({ where: { name } });
  return row?.processedUntil ?? null;
}

export async function writeCheckpoint(tx: Tx, name: string, processedUntil: Date): Promise<void> {
  await tx.detectionCheckpoint.upsert({
    where: { name },
    create: { name, processedUntil },
    update: { processedUntil },
  });
}
