-- Etapa 4: a troca de email revoga as demais sessões do usuário com um motivo próprio.
-- Apenas acrescenta um valor ao enum; nenhum dado existente é alterado.
ALTER TYPE "SessionRevokeReason" ADD VALUE 'EMAIL_CHANGE';
