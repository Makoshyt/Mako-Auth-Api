-- CreateEnum
CREATE TYPE "Role" AS ENUM ('USER', 'ADMIN');

-- CreateEnum
CREATE TYPE "SessionRevokeReason" AS ENUM ('LOGOUT', 'LOGOUT_ALL', 'TOKEN_REUSE', 'PASSWORD_RESET');

-- CreateEnum
CREATE TYPE "AuditEventType" AS ENUM ('LOGIN_SUCCESS', 'LOGIN_FAILURE', 'LOGOUT', 'PASSWORD_RESET_REQUEST', 'PASSWORD_RESET_SUCCESS', 'TOKEN_REUSE_DETECTED', 'ACCESS_DENIED');

-- CreateEnum
CREATE TYPE "AlertRule" AS ENUM ('BRUTE_FORCE_ACCOUNT', 'CREDENTIAL_STUFFING', 'TOKEN_REUSE');

-- CreateEnum
CREATE TYPE "AlertSeverity" AS ENUM ('LOW', 'MEDIUM', 'HIGH');

-- CreateEnum
CREATE TYPE "AlertStatus" AS ENUM ('OPEN', 'RESOLVED');

-- CreateTable
CREATE TABLE "users" (
    "id" UUID NOT NULL,
    "email" VARCHAR(254) NOT NULL,
    "name" VARCHAR(100) NOT NULL,
    "password_hash" TEXT NOT NULL,
    "role" "Role" NOT NULL DEFAULT 'USER',
    "password_changed_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sessions" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "revoked_at" TIMESTAMPTZ(3),
    "revoked_reason" "SessionRevokeReason",
    "ip" VARCHAR(45),
    "user_agent" VARCHAR(255),
    "last_used_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "refresh_tokens" (
    "id" UUID NOT NULL,
    "session_id" UUID NOT NULL,
    "token_hash" CHAR(64) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "used_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "refresh_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "password_reset_tokens" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "token_hash" CHAR(64) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "used_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "password_reset_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_events" (
    "id" UUID NOT NULL,
    "type" "AuditEventType" NOT NULL,
    "user_id" UUID,
    "email_hash" CHAR(64),
    "ip" VARCHAR(45),
    "metadata" JSONB,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_alerts" (
    "id" UUID NOT NULL,
    "rule" "AlertRule" NOT NULL,
    "severity" "AlertSeverity" NOT NULL,
    "status" "AlertStatus" NOT NULL DEFAULT 'OPEN',
    "fingerprint" VARCHAR(128) NOT NULL,
    "summary" VARCHAR(500) NOT NULL,
    "details" JSONB NOT NULL,
    "user_id" UUID,
    "event_count" INTEGER NOT NULL DEFAULT 1,
    "first_seen_at" TIMESTAMPTZ(3) NOT NULL,
    "last_seen_at" TIMESTAMPTZ(3) NOT NULL,
    "resolved_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "security_alerts_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE INDEX "sessions_user_id_revoked_at_idx" ON "sessions"("user_id", "revoked_at");

-- CreateIndex
CREATE UNIQUE INDEX "refresh_tokens_token_hash_key" ON "refresh_tokens"("token_hash");

-- CreateIndex
CREATE INDEX "refresh_tokens_session_id_idx" ON "refresh_tokens"("session_id");

-- CreateIndex
CREATE UNIQUE INDEX "password_reset_tokens_token_hash_key" ON "password_reset_tokens"("token_hash");

-- CreateIndex
CREATE INDEX "password_reset_tokens_user_id_idx" ON "password_reset_tokens"("user_id");

-- CreateIndex
CREATE INDEX "audit_events_created_at_idx" ON "audit_events"("created_at");

-- CreateIndex
CREATE INDEX "audit_events_type_created_at_idx" ON "audit_events"("type", "created_at");

-- CreateIndex
CREATE INDEX "audit_events_user_id_created_at_idx" ON "audit_events"("user_id", "created_at");

-- CreateIndex
CREATE INDEX "audit_events_email_hash_created_at_idx" ON "audit_events"("email_hash", "created_at");

-- CreateIndex
CREATE INDEX "audit_events_ip_created_at_idx" ON "audit_events"("ip", "created_at");

-- CreateIndex
CREATE INDEX "security_alerts_status_created_at_idx" ON "security_alerts"("status", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "security_alerts_open_fingerprint_key" ON "security_alerts"("fingerprint") WHERE (status = 'OPEN');

-- AddForeignKey
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "password_reset_tokens" ADD CONSTRAINT "password_reset_tokens_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "security_alerts" ADD CONSTRAINT "security_alerts_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- ---------------------------------------------------------------------------
-- Restrições adicionadas manualmente (o Prisma não expressa CHECK constraints).
-- São a última linha de defesa: a aplicação já valida, o banco garante.
-- ---------------------------------------------------------------------------

-- Email sempre normalizado, para que o índice único não aceite "Ana@x.com" e "ana@x.com".
ALTER TABLE "users" ADD CONSTRAINT "users_email_normalized_chk"
  CHECK ("email" = lower(btrim("email")) AND "email" <> '');

-- Motivo de revogação existe se, e somente se, a sessão foi revogada.
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_revocation_consistent_chk"
  CHECK (("revoked_at" IS NULL) = ("revoked_reason" IS NULL));

ALTER TABLE "sessions" ADD CONSTRAINT "sessions_expiry_after_creation_chk"
  CHECK ("expires_at" > "created_at");

-- Hashes SHA-256 sempre em hexadecimal minúsculo de 64 caracteres.
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_token_hash_hex_chk"
  CHECK ("token_hash" ~ '^[0-9a-f]{64}$');

ALTER TABLE "password_reset_tokens" ADD CONSTRAINT "password_reset_tokens_token_hash_hex_chk"
  CHECK ("token_hash" ~ '^[0-9a-f]{64}$');

ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_email_hash_hex_chk"
  CHECK ("email_hash" IS NULL OR "email_hash" ~ '^[0-9a-f]{64}$');

ALTER TABLE "security_alerts" ADD CONSTRAINT "security_alerts_event_count_positive_chk"
  CHECK ("event_count" >= 1);

ALTER TABLE "security_alerts" ADD CONSTRAINT "security_alerts_seen_order_chk"
  CHECK ("last_seen_at" >= "first_seen_at");

-- Alerta resolvido sempre tem data de resolução, e alerta aberto nunca tem.
ALTER TABLE "security_alerts" ADD CONSTRAINT "security_alerts_resolution_consistent_chk"
  CHECK (("status" = 'RESOLVED') = ("resolved_at" IS NOT NULL));
