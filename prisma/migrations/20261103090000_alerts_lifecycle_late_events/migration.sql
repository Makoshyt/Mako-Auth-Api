-- Etapa 10: eventos atrasados no motor de alertas, ciclo de vida dos alertas.
-- Somente acréscimos; nenhum dado existente é alterado (PostgreSQL 13+ para xid8).

-- AlterEnum
ALTER TYPE "AuditEventType" ADD VALUE 'ADMIN_SECURITY_ALERT_UPDATED';

-- AlterTable: transação que gravou cada evento.
-- Coluna adicionada SEM default e o default definido depois: sem reescrita da tabela, e os
-- eventos antigos ficam com NULL (nunca são tratados como "atrasados").
ALTER TABLE "audit_events" ADD COLUMN "tx_id" xid8;
ALTER TABLE "audit_events" ALTER COLUMN "tx_id" SET DEFAULT pg_current_xact_id();

-- AlterTable
ALTER TABLE "detection_checkpoints" ADD COLUMN "tx_horizon" BIGINT;

-- AlterTable
ALTER TABLE "security_alerts" ADD COLUMN "resolution_note" VARCHAR(500),
ADD COLUMN "resolved_by_id" UUID;

-- CreateTable
CREATE TABLE "detection_flagged_events" (
    "rule" "AlertRule" NOT NULL,
    "event_id" UUID NOT NULL,
    "event_created_at" TIMESTAMPTZ(3) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "detection_flagged_events_pkey" PRIMARY KEY ("rule","event_id")
);

-- CreateIndex
CREATE INDEX "detection_flagged_events_event_created_at_idx" ON "detection_flagged_events"("event_created_at");

-- CreateIndex
CREATE INDEX "audit_events_tx_id_idx" ON "audit_events"("tx_id");

-- AddForeignKey
ALTER TABLE "security_alerts" ADD CONSTRAINT "security_alerts_resolved_by_id_fkey" FOREIGN KEY ("resolved_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- Restrições manuais (o Prisma não expressa CHECK).
-- Quem resolveu e a nota só existem em alerta RESOLVED.
ALTER TABLE "security_alerts" ADD CONSTRAINT "security_alerts_resolution_fields_chk"
  CHECK ("status" = 'RESOLVED' OR ("resolved_by_id" IS NULL AND "resolution_note" IS NULL));

-- O guard append-only também precisa preservar tx_id na única exceção de UPDATE
-- (ON DELETE SET NULL do usuário).
CREATE OR REPLACE FUNCTION "audit_events_guard"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF OLD."user_id" IS NOT NULL AND NEW."user_id" IS NULL
       AND NEW."id" = OLD."id"
       AND NEW."type" = OLD."type"
       AND NEW."email_hash" IS NOT DISTINCT FROM OLD."email_hash"
       AND NEW."ip" IS NOT DISTINCT FROM OLD."ip"
       AND NEW."metadata" IS NOT DISTINCT FROM OLD."metadata"
       AND NEW."created_at" = OLD."created_at"
       AND NEW."tx_id" IS NOT DISTINCT FROM OLD."tx_id" THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'audit_events é append-only: UPDATE não permitido'
      USING ERRCODE = 'insufficient_privilege';
  END IF;

  IF current_setting('authapi.audit_purge', true) IS DISTINCT FROM 'on' THEN
    RAISE EXCEPTION 'audit_events: exclusão permitida apenas pela rotina de retenção'
      USING ERRCODE = 'insufficient_privilege';
  END IF;

  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NULL;
END;
$$;
