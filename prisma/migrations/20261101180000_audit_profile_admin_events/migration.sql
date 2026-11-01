-- Etapa 8: auditoria de alterações de perfil e de leituras administrativas.
-- Apenas acrescenta valores ao enum; nenhum dado existente é alterado.
ALTER TYPE "AuditEventType" ADD VALUE 'PROFILE_UPDATED';
ALTER TYPE "AuditEventType" ADD VALUE 'PROFILE_UPDATE_DENIED';
ALTER TYPE "AuditEventType" ADD VALUE 'ADMIN_USERS_LISTED';
ALTER TYPE "AuditEventType" ADD VALUE 'ADMIN_USER_VIEWED';
ALTER TYPE "AuditEventType" ADD VALUE 'ADMIN_AUDIT_QUERIED';
