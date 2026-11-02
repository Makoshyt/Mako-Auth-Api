# Prontidão para produção

Avaliação honesta do estado do AuthAPI Pro para um ambiente real. **Veredito: não está pronto
para produção.** O código da aplicação cobre bem segurança e resiliência, mas faltam peças de
operação (email real, gestão de segredos, backups, observabilidade e um caminho de deploy) que
são pré-requisitos, não detalhes.

Legenda: **Pronto** · **Parcial** · **Pendente**.

## Checklist

| Área                        | Estado   | Situação atual                                                                                                                                                     | O que falta                                                                                                  |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| Configuração segura         | Parcial  | Todas as variáveis validadas com Zod na inicialização; produção recusa CORS `*`, `dev-mailbox` e link de reset sem https; Swagger desligado por padrão em produção | Revisar os limites de rate limit com tráfego real; definir `TRUST_PROXY` conforme a topologia                |
| Gestão de segredos          | Parcial  | Segredos só por ambiente, nunca versionados, mínimo de 32 caracteres, JWT ≠ HMAC                                                                                   | Cofre de segredos (Vault, AWS/GCP/Azure Secrets); rotação de chave JWT sem derrubar sessões (`kid`/JWKS)     |
| Logs                        | Pronto   | JSON estruturado (pino), `requestId`, redação de headers/campos sensíveis, URL sem query string, testes que procuram segredos nos logs                             | Envio para um agregador (infra)                                                                              |
| Observabilidade             | Pendente | Só logs                                                                                                                                                            | Métricas (latência, 4xx/5xx, 429, rodadas do motor, `skippedLateEvents`) e tracing (OpenTelemetry)           |
| Health checks               | Pronto   | `/health` (liveness, sem dependências) e `/ready` (PostgreSQL + Redis, timeout de 2 s, só `up`/`down`)                                                             | —                                                                                                            |
| Encerramento gracioso       | Pronto   | SIGTERM/SIGINT: para de aceitar conexões, espera requisições, emails pendentes e a rodada do motor; prazo de 15 s com saída forçada                                | —                                                                                                            |
| Timeouts e limites          | Pronto   | `requestTimeout` (≥ 30 s), `bodyLimit` 16 KB, timeouts de conexão do PostgreSQL (5 s) e Redis (5 s), timeout do Ollama                                             | —                                                                                                            |
| Migrations                  | Parcial  | `prisma migrate deploy` (aditivo, nunca recria o banco); CI confere que schema e migrations batem                                                                  | Job de migração separado do deploy; plano de rollback (`ALTER TYPE … ADD VALUE` não é reversível)            |
| Backups                     | Pendente | Nenhum                                                                                                                                                             | Backup automatizado com PITR do PostgreSQL e testes periódicos de restauração                                |
| Recuperação de desastres    | Pendente | O motor de alertas se recupera de falhas e reinícios; o resto depende do banco                                                                                     | RPO/RTO definidos, réplica em outra zona, runbook de restauração                                             |
| Retenção de dados           | Parcial  | Auditoria e alertas com retenção configurável, simulação por padrão, lotes e confirmação explícita                                                                 | Agendamento (cron externo) e política aprovada por jurídico/privacidade                                      |
| Monitoramento de segurança  | Parcial  | 6 regras, alertas persistidos, ciclo de vida, auditoria de quem consulta e resolve                                                                                 | Notificação (email/Slack/PagerDuty) para alertas HIGH; painel                                                |
| Atualização de dependências | Parcial  | Versões fixadas, lockfile, `npm audit` no CI (bloqueia high/critical), `npm audit` local com 0 vulnerabilidades                                                    | Dependabot/Renovate; janela de atualização                                                                   |
| Segurança da infraestrutura | Pendente | Docker Compose é só para desenvolvimento (portas em 127.0.0.1, credenciais fictícias)                                                                              | Imagem da aplicação (usuário não-root, imagem mínima), TLS no proxy, rede privada para PostgreSQL/Redis, WAF |
| Dependências externas       | Pendente | Email: só `log` e `dev-mailbox`. **A recuperação de senha não funciona em produção sem um provedor real**                                                          | Provedor SMTP/API com fila e retentativas                                                                    |
| Disponibilidade PostgreSQL  | Parcial  | Falha do banco vira 500 genérico e `/ready` 503; pool com timeout                                                                                                  | PostgreSQL gerenciado com alta disponibilidade; pooler (PgBouncer) se houver muitas instâncias               |
| Disponibilidade Redis       | Parcial  | Sem fila offline; rotas sensíveis falham fechadas (503), leituras falham abertas; testes cobrem Redis fora do ar                                                   | Redis gerenciado com réplica; alerta quando o rate limit estiver indisponível                                |
| CI                          | Parcial  | Workflow com lint, tipos, formatação, build, testes unitários e de integração, auditoria; comandos validados localmente                                            | Executar no GitHub e exigir o status nos pull requests (branch protection)                                   |
| Deploy (CD)                 | Pendente | Nenhum                                                                                                                                                             | Pipeline com build da imagem, migração e implantação gradual                                                 |

## Bloqueadores para produção

1. **Provedor de email real**: sem ele, a recuperação de senha não entrega o link.
2. **Gestão de segredos** em um cofre, com processo de rotação.
3. **Backups e restauração testada** do PostgreSQL.
4. **Observabilidade mínima** (métricas e alertas operacionais).
5. **Imagem da aplicação e pipeline de deploy** com etapa de migração controlada.
6. **CI executado no GitHub** e exigido nos pull requests.

## Antes do primeiro deploy

- Gerar segredos novos no cofre (nunca reaproveitar os de desenvolvimento).
- `NODE_ENV=production`, `TRUST_PROXY` com o número exato de proxies, `CORS_ORIGINS` explícito.
- Conferir que `SWAGGER_ENABLED` está ausente ou `false`.
- Rodar `npm run db:migrate:deploy` como etapa separada, antes de subir a nova versão.
- Revisar os limites de rate limit e de alertas com dados reais.
- Definir quem recebe e trata alertas HIGH e como.
