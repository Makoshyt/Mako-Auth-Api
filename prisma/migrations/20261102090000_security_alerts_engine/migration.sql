-- Etapa 9: motor de alertas de segurança.
-- Somente acréscimos: 3 regras, 1 tipo de evento (consulta admin aos alertas) e a tabela de
-- checkpoint do motor. Nenhum dado existente é alterado (requer PostgreSQL 12+, como o projeto).

-- AlterEnum


ALTER TYPE "AlertRule" ADD VALUE 'RATE_LIMIT_ABUSE';
ALTER TYPE "AlertRule" ADD VALUE 'ADMIN_ACCESS_PROBING';
ALTER TYPE "AlertRule" ADD VALUE 'PASSWORD_RESET_ABUSE';

-- AlterEnum
ALTER TYPE "AuditEventType" ADD VALUE 'ADMIN_SECURITY_ALERTS_QUERIED';

-- CreateTable
CREATE TABLE "detection_checkpoints" (
    "name" VARCHAR(64) NOT NULL,
    "processed_until" TIMESTAMPTZ(3) NOT NULL,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "detection_checkpoints_pkey" PRIMARY KEY ("name")
);

