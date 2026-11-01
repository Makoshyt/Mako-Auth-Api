-- Etapa 8: audit_events passa a ser append-only no próprio banco.
--
--  * UPDATE: proibido. Única exceção: o ON DELETE SET NULL da FK de usuário (excluir uma conta
--    preserva a trilha, sem o vínculo), reconhecido por mudar SOMENTE user_id para NULL.
--  * DELETE/TRUNCATE: só dentro de uma transação que declarou explicitamente a intenção com
--    SELECT set_config('authapi.audit_purge', 'on', true)  -- vale só até o fim da transação.
--    É o que faz a rotina de retenção; nenhum endpoint HTTP faz isso.
--
-- Limitação (documentada): o dono do banco ou um superusuário pode desabilitar o trigger.
-- A proteção impede alterações acidentais e por código da aplicação, não um DBA malicioso.

CREATE FUNCTION "audit_events_guard"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF OLD."user_id" IS NOT NULL AND NEW."user_id" IS NULL
       AND NEW."id" = OLD."id"
       AND NEW."type" = OLD."type"
       AND NEW."email_hash" IS NOT DISTINCT FROM OLD."email_hash"
       AND NEW."ip" IS NOT DISTINCT FROM OLD."ip"
       AND NEW."metadata" IS NOT DISTINCT FROM OLD."metadata"
       AND NEW."created_at" = OLD."created_at" THEN
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

CREATE TRIGGER "audit_events_guard_row"
  BEFORE UPDATE OR DELETE ON "audit_events"
  FOR EACH ROW EXECUTE FUNCTION "audit_events_guard"();

CREATE TRIGGER "audit_events_guard_truncate"
  BEFORE TRUNCATE ON "audit_events"
  FOR EACH STATEMENT EXECUTE FUNCTION "audit_events_guard"();
