-- Etapa 6: bloqueios de rate limit entram na auditoria (no máximo um evento por chave e janela).
-- Apenas acrescenta um valor ao enum; nenhum dado existente é alterado.
ALTER TYPE "AuditEventType" ADD VALUE 'RATE_LIMIT_EXCEEDED';
