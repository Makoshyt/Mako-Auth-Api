-- Etapa 5: logout-all ganha um tipo de evento próprio, separado do logout de uma sessão.
-- Apenas acrescenta um valor ao enum; eventos antigos (LOGOUT com scope ALL) permanecem como estão.
ALTER TYPE "AuditEventType" ADD VALUE 'LOGOUT_ALL';
