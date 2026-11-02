# AuthAPI Pro

API REST de autenticação e gerenciamento de usuários construída com Node.js, TypeScript,
Fastify, PostgreSQL e Prisma.

> **Status:** Etapa 9 de 10 (motor de alertas de segurança com IA local opcional; auditoria, recuperação de senha, rate limiting, RBAC e JWT).
> O README completo, com arquitetura, modelo de ameaças e roteiro de demonstração, chega na
> Etapa 10. As decisões técnicas estão em [`docs/architecture.md`](docs/architecture.md).

## Requisitos

- Node.js 24 LTS
- Docker Desktop (aberto e rodando)

## Executar localmente (Windows PowerShell)

```powershell
npm install                      # instala dependências e gera o Prisma Client
Copy-Item .env.example .env      # só na primeira vez; depois preencha JWT_ACCESS_SECRET (abaixo)
npm run docker:up                # PostgreSQL (127.0.0.1:5433) e Redis (127.0.0.1:6379)
npm run db:migrate               # aplica as migrations no banco de desenvolvimento
npm run db:seed                  # usuários fictícios (opcional)
npm run dev
```

- Liveness: <http://127.0.0.1:3000/health>
- Readiness (PostgreSQL e Redis): <http://127.0.0.1:3000/ready>
- Swagger UI: <http://127.0.0.1:3000/docs>
- OpenAPI JSON: <http://127.0.0.1:3000/docs/json>

`JWT_ACCESS_SECRET` e `RATE_LIMIT_HMAC_SECRET` são obrigatórios (mínimo de 32 caracteres cada,
e diferentes entre si). Sem eles, a API não sobe. Gere um valor para cada um, rodando o comando
duas vezes, e cole no `.env`, que nunca é versionado:

```powershell
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

Se você já tinha um `.env` de etapas anteriores, rode também `npm run db:migrate:deploy`. As
migrations das Etapas 4 a 6 só acrescentam valores a enums.

`TRUST_PROXY=true` agora é **recusado** na inicialização (veja [Rate limiting](#rate-limiting)).
Use `false`, o número de proxies ou a lista de IPs/CIDRs dos proxies.

O PostgreSQL do Docker usa a porta **5433** para não conflitar com um PostgreSQL instalado
localmente na 5432. As portas são publicadas apenas em `127.0.0.1`.

## Endpoints disponíveis

| Método | Rota                                            | Acesso   | Descrição                                                                |
| ------ | ----------------------------------------------- | -------- | ------------------------------------------------------------------------ |
| GET    | `/health`                                       | público  | Liveness do processo                                                     |
| GET    | `/ready`                                        | público  | Readiness: PostgreSQL e Redis (200 ou 503)                               |
| POST   | `/api/v1/auth/register`                         | público  | Cadastro (papel USER), retorna 201                                       |
| POST   | `/api/v1/auth/login`                            | público  | Cria uma sessão e devolve access token + refresh token                   |
| POST   | `/api/v1/auth/refresh`                          | público* | Troca o refresh token por um par novo (rotação obrigatória)              |
| POST   | `/api/v1/auth/logout`                           | Bearer   | Encerra a sessão atual (204)                                             |
| POST   | `/api/v1/auth/logout-all`                       | Bearer   | Encerra todas as sessões do usuário (204)                                |
| GET    | `/api/v1/users/me`                              | Bearer   | Perfil do usuário autenticado                                            |
| PATCH  | `/api/v1/users/me`                              | Bearer   | Altera nome e/ou email (o email exige `currentPassword`)                 |
| GET    | `/api/v1/admin/users`                           | ADMIN    | Lista usuários: paginação, filtros e ordenação controlada                |
| GET    | `/api/v1/admin/users/:id`                       | ADMIN    | Consulta um usuário (404 se não existir)                                 |
| GET    | `/api/v1/admin/audit-events`                    | ADMIN    | Trilha de auditoria: filtros por tipo, usuário e período                 |
| GET    | `/api/v1/admin/security-alerts`                 | ADMIN    | Alertas de segurança: paginação e filtros por regra, severidade e estado |
| GET    | `/api/v1/admin/security-alerts/:id`             | ADMIN    | Consulta um alerta (404 se não existir)                                  |
| POST   | `/api/v1/admin/security-alerts/:id/explanation` | ADMIN    | Explicação por IA local (opcional; desligada por padrão)                 |
| POST   | `/api/v1/auth/forgot-password`                  | público  | Pede o link de recuperação (sempre 202, exista ou não a conta)           |
| POST   | `/api/v1/auth/reset-password`                   | público  | Redefine a senha com o token do link e encerra todas as sessões          |
| GET    | `/docs`                                         | público  | Swagger UI (desligável com `SWAGGER_ENABLED`)                            |

\* Não exige o access token: a credencial é o próprio refresh token, enviado no corpo.

Fora da área `/admin`, nenhuma rota recebe id de usuário: o perfil é sempre o do token.

### Controle de acesso (RBAC)

| Recurso                                       | Anônimo    | USER                       | ADMIN                       |
| --------------------------------------------- | ---------- | -------------------------- | --------------------------- |
| `register`, `login`, `refresh`                | ✔          | ✔                          | ✔                           |
| `logout`, `logout-all`                        | 401        | ✔ (só as próprias sessões) | ✔ (só as próprias sessões)  |
| `GET`/`PATCH /users/me`                       | 401        | ✔ (só o próprio perfil)    | ✔ (só o próprio perfil)     |
| `GET /admin/users`, `/admin/users/:id`        | 401        | **403**                    | ✔                           |
| `GET /admin/audit-events`                     | 401        | **403**                    | ✔                           |
| Excluir usuário, mudar papel, redefinir senha | não existe | não existe                 | não existe (fora do escopo) |

- O papel usado na decisão é o **atual do banco**, lido a cada requisição. A claim `role` do JWT
  não autoriza nada. Por isso, promover ou rebaixar alguém vale já na próxima requisição, com o
  mesmo token.
- `401` significa "não sei quem é você" (token ausente, inválido, expirado ou sessão encerrada).
  `403` significa "sei quem é, mas o papel não permite". Cada `403` é registrado como
  `ACCESS_DENIED` na auditoria.
- `role` enviado pelo cliente (no body, na query ou num header como `x-user-role`) é ignorado
  ou rejeitado.

### Rotas administrativas

Todas são **somente leitura** e exigem `Authorization: Bearer <token de um ADMIN>`.

| Parâmetro (`/admin/users`) | Valores                                      | Padrão      |
| -------------------------- | -------------------------------------------- | ----------- |
| `page`                     | 1 a 1000                                     | `1`         |
| `pageSize`                 | 1 a **100** (acima disso: 400)               | `20`        |
| `email`                    | trecho do email (curingas `%`/`_` são texto) | —           |
| `role`                     | `USER` ou `ADMIN`                            | —           |
| `sort`                     | `createdAt`, `email` ou `name`               | `createdAt` |
| `order`                    | `asc` ou `desc`                              | `desc`      |

| Parâmetro (`/admin/audit-events`) | Valores                                                                                            | Padrão |
| --------------------------------- | -------------------------------------------------------------------------------------------------- | ------ |
| `page`, `pageSize`                | como acima (máximo de 100)                                                                         | 1, 20  |
| `type`                            | `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGOUT`, `LOGOUT_ALL`, `TOKEN_REUSE_DETECTED`, `ACCESS_DENIED`… | —      |
| `userId`                          | UUID                                                                                               | —      |
| `from` / `to`                     | ISO 8601 (`from` inclusive, `to` exclusive)                                                        | —      |
| `order`                           | `asc` ou `desc` (por `createdAt` e `id`, ordem estável)                                            | `desc` |

Parâmetro desconhecido, repetido ou fora da lista gera `400 VALIDATION_ERROR`. A resposta da
listagem tem o formato `{ "data": [...], "pagination": { "page", "pageSize", "total", "totalPages" } }`.

```powershell
$h = @{ Authorization = "Bearer $($adminLogin.accessToken)" }
Invoke-RestMethod -Uri "$api/admin/users?role=USER&sort=name&order=asc&page=1&pageSize=2" -Headers $h
Invoke-RestMethod -Uri "$api/admin/users/01a19475-1655-72e9-9bf4-e6a743ff8e29" -Headers $h
Invoke-RestMethod -Uri "$api/admin/audit-events?type=ACCESS_DENIED&from=2026-11-01T00:00:00Z&pageSize=5" -Headers $h
```

Respostas reais do servidor compilado:

```jsonc
// GET /admin/users?email=demo%40admin-test.example.com&role=USER&sort=name&order=asc&pageSize=2 → 200
{ "data": [
    { "id": "01a19475-1655-72e9-9bf4-e6a743ff8e29", "name": "Bruno Demo", "email": "bruno.demo@admin-test.example.com",
      "role": "USER", "createdAt": "2026-11-01T00:14:23.829Z", "updatedAt": "2026-11-01T00:14:23.829Z" },
    { "id": "01a19475-1683-762f-a2cd-091f3d70b649", "name": "Carla Demo", "email": "carla.demo@admin-test.example.com",
      "role": "USER", "createdAt": "2026-11-01T00:14:23.875Z", "updatedAt": "2026-11-01T00:14:23.875Z" } ],
  "pagination": { "page": 1, "pageSize": 2, "total": 2, "totalPages": 1 } }

// GET /admin/audit-events?type=ACCESS_DENIED&userId=… → 200 (sem email, hash de email, tokens ou senhas)
{ "data": [ { "id": "01a19475-2171-7228-ac8e-4aec2d012fb6", "type": "ACCESS_DENIED",
              "userId": "01a19475-1655-72e9-9bf4-e6a743ff8e29", "ip": "127.0.0.1",
              "metadata": { "role": "USER", "route": "/api/v1/admin/users", "method": "GET", "requiredRoles": "ADMIN" },
              "createdAt": "2026-11-01T00:14:26.673Z" } ],
  "pagination": { "page": 1, "pageSize": 5, "total": 1, "totalPages": 1 } }

// GET /admin/users como USER → 403
{ "error": { "code": "FORBIDDEN", "message": "Seu papel não permite acessar este recurso", "requestId": "b01c5978-..." } }

// GET /admin/users?pageSize=101 → 400
{ "error": { "code": "VALIDATION_ERROR", "message": "Dados de entrada inválidos", "requestId": "d543bbed-...",
             "details": [{ "field": "querystring.pageSize", "message": "pageSize pode ser no máximo 100" }] } }

// GET /admin/users/0190a000-0000-7000-8000-0000000000ff → 404
{ "error": { "code": "NOT_FOUND", "message": "Usuário não encontrado", "requestId": "76956443-..." } }
```

### Como testar o papel ADMIN localmente

Não existe endpoint que promova usuários. Em desenvolvimento, use o comando local, que só
altera o papel (não cria nem lê senhas):

```powershell
npm run db:seed    # cria ada.admin@example.com, bruno.user@example.com e carla.user@example.com como USER
npm run admin:promote -- --email ada.admin@example.com --confirm ada.admin@example.com
```

```
Banco: authapi em 127.0.0.1
✔ ada.admin@example.com agora é ADMIN (id …).
  O papel vale na próxima requisição: não é preciso novo login.
```

Depois, faça login com `ada.admin@example.com` e a senha `SEED_USER_PASSWORD`, use o
**Authorize** do Swagger e experimente as rotas da tag **Admin**. Com `bruno.user@example.com`,
as mesmas rotas devolvem `403`.

Travas do comando:

- recusa `NODE_ENV=production` e qualquer ambiente que não seja `development` ou `test`;
- recusa bancos que não sejam locais;
- só aceita emails de domínios reservados para exemplos (`example.com`/`.org`/`.net`, `.test`,
  `.example`, `.invalid`, `.localhost`), então não alcança contas reais;
- exige repetir o email em `--confirm`;
- nunca é executado pelo seed.

### Autenticação em resumo

- **Access token:** JWT HS256 válido por 15 minutos, com as claims `sub`, `sid`, `role`, `iat`
  e `exp`. A cada requisição, a API confere a assinatura e também se a **sessão** continua ativa
  no PostgreSQL. Por isso, logout e revogação valem na hora, sem esperar o token expirar.
- **Refresh token:** valor opaco de 256 bits, de **uso único**. Cada refresh devolve um par
  novo. Reapresentar um token já trocado há menos de 10 s devolve `409` (corrida legítima entre
  abas). Depois disso, a sessão inteira é revogada.
- **Sessão:** dura no máximo 30 dias desde o login, e a rotação nunca estende esse prazo.
- O fluxo completo, as ameaças consideradas e as limitações estão em
  [`docs/architecture.md`](docs/architecture.md#etapa-4-autenticação-e-sessões).

### Rate limiting

Os contadores ficam no **Redis compartilhado**, então o limite vale para todas as instâncias da
API juntas. Cada contador é atualizado por um script Lua atômico (`INCR` + `PEXPIRE`) e expira
sozinho com a janela.

| Endpoint                     | Limite padrão | Janela | Por                   | Redis fora do ar |
| ---------------------------- | ------------- | ------ | --------------------- | ---------------- |
| `POST /auth/login`           | 5             | 15 min | IP                    | 503 (fechado)    |
| `POST /auth/login`           | 10            | 1 h    | conta (HMAC do email) | 503 (fechado)    |
| `POST /auth/register`        | 5             | 1 h    | IP                    | 503 (fechado)    |
| `POST /auth/refresh`         | 20            | 15 min | IP                    | 503 (fechado)    |
| `POST /auth/logout`          | 20            | 15 min | usuário               | libera (aberto)  |
| `POST /auth/logout-all`      | 5             | 15 min | usuário               | libera (aberto)  |
| `PATCH /users/me`            | 10            | 15 min | usuário               | 503 (fechado)    |
| `GET /admin/users`           | 60            | 1 min  | usuário (ADMIN)       | libera (aberto)  |
| `GET /admin/users/:id`       | 60            | 1 min  | usuário (ADMIN)       | libera (aberto)  |
| `GET /admin/audit-events`    | 30            | 1 min  | usuário (ADMIN)       | libera (aberto)  |
| `POST /auth/forgot-password` | 5             | 1 h    | IP                    | 503 (fechado)    |
| `POST /auth/forgot-password` | 3             | 1 h    | conta (HMAC do email) | 503 (fechado)    |
| `POST /auth/reset-password`  | 10            | 15 min | IP                    | 503 (fechado)    |

`/health`, `/ready`, `/docs` e `GET /users/me` não têm limite. Os valores são **defaults de
desenvolvimento**: ajuste-os por variável de ambiente (`RATE_LIMIT_LOGIN_IP=5/15m` etc., ver
`.env.example`) com base em métricas reais de uso.

- **IP e conta no login.** O limite por IP vem primeiro, antes de ler o corpo. O limite por conta
  (10/h, contando todos os IPs juntos) só é consumido se o de IP passou. Assim, quem distribui
  tentativas por muitos IPs esbarra na conta, e um único IP já bloqueado não consegue travar a
  conta de outra pessoa.
- **Usuário autenticado.** Nas rotas autenticadas, o limite roda **depois** da autenticação. Um
  anônimo sempre recebe `401`, nunca `429`. Nas rotas admin, o limite roda antes da checagem de
  papel, o que também contém um USER que insista em rotas admin.
- **Chaves no Redis:** `authapi:rl:<política>:<escopo>:<HMAC-SHA256>`. IPs, emails e ids nunca
  aparecem em texto (nem como SHA-256 simples, que seria reversível por dicionário). A chave do
  HMAC (`RATE_LIMIT_HMAC_SECRET`) é separada do JWT e precisa ser estável.
- **Redis fora do ar.** Login, cadastro, refresh e `PATCH /users/me` respondem
  `503 SERVICE_UNAVAILABLE`, com mensagem genérica: nunca `401`, para não parecer credencial
  inválida. Logout e consultas admin seguem funcionando, pois bloqueá-las não protege nada.
- **Auditoria.** Um evento `RATE_LIMIT_EXCEEDED` é gravado só no **primeiro** bloqueio de cada
  chave na janela. Um atacante recebendo milhões de `429` gera no máximo um registro por janela.

**TRUST_PROXY** decide de onde vem o IP:

| Valor                      | Quando usar                                      | X-Forwarded-For                                          |
| -------------------------- | ------------------------------------------------ | -------------------------------------------------------- |
| `false` (padrão)           | Desenvolvimento local, API exposta diretamente   | Ignorado: o IP é o da conexão TCP                        |
| `1`                        | Atrás de **um** proxy reverso (nginx, Caddy, LB) | Só o endereço que o proxy anexou é usado                 |
| `10.0.0.0/8,172.16.0.0/12` | Proxies com IPs conhecidos                       | Aceito apenas se a conexão vier desses IPs               |
| `true`                     | **Recusado na inicialização**                    | Usaria o primeiro valor do header, que o cliente escolhe |

Com o padrão `false`, mandar `X-Forwarded-For: 1.2.3.4` não muda nada: o limite continua
contando o IP real da conexão. Há teste para cada modo.

**Resposta 429** (real, do servidor compilado):

```http
HTTP/1.1 429 Too Many Requests
x-ratelimit-limit: 5
x-ratelimit-remaining: 0
x-ratelimit-reset: 900
retry-after: 900

{"error":{"code":"RATE_LIMITED","message":"Muitas requisições. Tente novamente em 900 s.","requestId":"c13d1bc1-...","details":{"retryAfterSeconds":900}}}
```

A mensagem é a mesma para os limites de IP, conta e usuário. A resposta não diz qual limite
estourou nem se a conta existe. O limite por conta não envia `X-RateLimit-*`: o "remaining" de
um email revelaria tentativas feitas por terceiros.

**Testar manualmente** (Git Bash ou WSL, com a API em `npm run dev`):

```bash
for i in 1 2 3 4 5 6; do
  curl -s -o /dev/null -w "tentativa $i: %{http_code}\n" -X POST http://127.0.0.1:3000/api/v1/auth/login \
    -H 'content-type: application/json' -H "x-forwarded-for: 10.0.0.$i" \
    -d '{"email":"teste@example.com","password":"senha errada porem longa"}'
done
# tentativa 1..5: 401 · tentativa 6: 429 (o X-Forwarded-For trocado não ajuda)
```

No Swagger, execute `POST /api/v1/auth/login` seis vezes: a sexta resposta é `429`, e os
cabeçalhos aparecem em _Response headers_. Para repetir o teste antes de a janela acabar, apague
**só** as chaves do ambiente local:
`docker compose exec redis redis-cli --scan --pattern 'authapi:rl:*' | xargs -r docker compose exec -T redis redis-cli del`.
Nunca use `FLUSHALL`.

### Auditoria

Toda ação sensível gera **um** evento em `audit_events`, gravado **depois** de a ação ser
confirmada. Só o ADMIN consulta a trilha, em `GET /api/v1/admin/audit-events`.

| Evento                   | Quando                                                     | Metadados (nunca senha, token ou email em texto)          |
| ------------------------ | ---------------------------------------------------------- | --------------------------------------------------------- |
| `LOGIN_SUCCESS`          | Login aceito                                               | `sessionId`                                               |
| `LOGIN_FAILURE`          | Senha errada ou email inexistente                          | `reason`                                                  |
| `LOGOUT` / `LOGOUT_ALL`  | Encerramento de uma sessão ou de todas                     | `sessionId` / `revokedSessions`                           |
| `TOKEN_REUSE_DETECTED`   | Refresh token reutilizado fora da janela (sessão revogada) | `sessionId`, `secondsSinceRotation`                       |
| `PROFILE_UPDATED`        | Nome e/ou email alterados                                  | `fields`, `emailChanged`, `otherSessionsRevoked`          |
| `PROFILE_UPDATE_DENIED`  | Troca de email recusada                                    | `reason` (`INVALID_CURRENT_PASSWORD`, `EMAIL_IN_USE`)     |
| `PASSWORD_RESET_REQUEST` | Pedido de recuperação (conta existente ou não)             | `outcome`                                                 |
| `PASSWORD_RESET_SUCCESS` | Senha redefinida                                           | `revokedSessions`                                         |
| `ACCESS_DENIED`          | 403 por papel insuficiente                                 | `method`, `route` (padrão), `requiredRoles`, `role`       |
| `RATE_LIMIT_EXCEEDED`    | Primeiro 429 de uma chave na janela                        | `policy`, `scope`, `limit`, `windowSeconds`               |
| `ADMIN_USERS_LISTED`     | ADMIN listou usuários                                      | paginação, `role`, `emailFilter` (sim/não), `resultCount` |
| `ADMIN_USER_VIEWED`      | ADMIN consultou um usuário (inclusive 404)                 | `targetUserId`, `found`                                   |
| `ADMIN_AUDIT_QUERIED`    | ADMIN consultou a auditoria                                | paginação, filtros usados, `resultCount`                  |

- **Privacidade:** o email entra só como SHA-256 (`emailHash`), que a API não devolve. O
  trecho pesquisado no filtro de email do ADMIN não é guardado. Os IPs são guardados para
  investigar abuso.
- **Append-only no banco:** um trigger recusa `UPDATE` e `DELETE` em `audit_events`. A única
  exceção é a rotina de retenção, e não existe endpoint de edição ou exclusão.
- **Retenção:** 180 dias para eventos comuns e 365 para sinais de ataque e responsabilização.
  A rotina é **manual** e só simula por padrão:

```powershell
npm run audit:retention                                         # simulação: só conta
$env:AUDIT_RETENTION_ENABLED='true'; npm run audit:retention -- --execute --confirm <nome-do-banco>
```

Fora de produção, a exclusão só roda em bancos `*_test`: o banco de desenvolvimento nunca é
apagado. Detalhes, limitações e riscos em
[`docs/architecture.md`](docs/architecture.md#etapa-8-auditoria-avançada).

### Alertas de segurança

Um **motor de regras determinísticas** lê a trilha de auditoria e gera alertas persistidos em
`security_alerts`. Ele roda **fora das requisições**: em rodadas periódicas (a cada 60 s) e a
partir de um checkpoint salvo no PostgreSQL, que permite retomar de onde parou após um
reinício. Não bloqueia contas nem age sobre usuários.

| Regra                  | Dispara quando (padrão)                                 | Evento lido              | Severidade             |
| ---------------------- | ------------------------------------------------------- | ------------------------ | ---------------------- |
| `BRUTE_FORCE_ACCOUNT`  | ≥ 8 falhas de login para a mesma conta em 1 h           | `LOGIN_FAILURE`          | MEDIUM (HIGH com ≥ 16) |
| `CREDENTIAL_STUFFING`  | Um IP falhando em ≥ 5 contas diferentes em 1 h          | `LOGIN_FAILURE`          | HIGH                   |
| `TOKEN_REUSE`          | Refresh token reutilizado fora da janela (≥ 1 em 24 h)  | `TOKEN_REUSE_DETECTED`   | HIGH                   |
| `RATE_LIMIT_ABUSE`     | O mesmo IP bloqueado pelo rate limit ≥ 3 vezes em 1 h   | `RATE_LIMIT_EXCEEDED`    | LOW (MEDIUM com ≥ 6)   |
| `ADMIN_ACCESS_PROBING` | Um usuário com ≥ 5 acessos negados a rotas admin em 1 h | `ACCESS_DENIED`          | MEDIUM (HIGH com ≥ 10) |
| `PASSWORD_RESET_ABUSE` | ≥ 5 pedidos de recuperação do mesmo IP em 1 h           | `PASSWORD_RESET_REQUEST` | LOW (MEDIUM com ≥ 10)  |

- **Limites e janelas** configuráveis por variável de ambiente (`ALERT_BRUTE_FORCE_ACCOUNT=8/1h`
  etc.). A severidade **sobe** ao atingir o dobro do limite e **nunca desce**.
- **Deduplicação deslizante:** enquanto a mesma regra e o mesmo alvo tiverem atividade com
  intervalos menores que `ALERTS_DEDUP_WINDOW_HOURS` (24 h), o incidente é **um** alerta
  aberto, mesmo atravessando a meia-noite. Novas ocorrências somam em `eventCount`. Depois de
  um intervalo maior que a janela, ou se o alerta estiver `RESOLVED`, abre-se um alerta novo.
  O advisory lock do motor e o índice único parcial do PostgreSQL impedem duplicatas mesmo com
  gravações simultâneas.
- **Evidências:** limite, janela, pico, tipo de evento, alvo e até 10 ids de eventos. O alvo é
  o `userId` quando existe, ou o IP nas regras em que o IP é o próprio alvo. **Nunca** email,
  hash de email, senha ou token.

```powershell
$h = @{ Authorization = "Bearer $($adminLogin.accessToken)" }
Invoke-RestMethod -Uri "$api/admin/security-alerts?status=OPEN&severity=HIGH&page=1&pageSize=20" -Headers $h
Invoke-RestMethod -Uri "$api/admin/security-alerts/<id>" -Headers $h
Invoke-RestMethod -Method Post -Uri "$api/admin/security-alerts/<id>/explanation" -Headers $h
npm run alerts:process   # rodada manual (seguro junto com a API)
```

```jsonc
// GET /admin/security-alerts?rule=BRUTE_FORCE_ACCOUNT → 200 (real, servidor compilado)
{ "data": [ { "id": "…", "rule": "BRUTE_FORCE_ACCOUNT", "severity": "MEDIUM", "status": "OPEN",
              "summary": "8 ou mais falhas de login para a mesma conta em 1 h", "eventCount": 1,
              "details": { "threshold": 8, "windowSeconds": 3600, "peak": 8, "eventType": "LOGIN_FAILURE",
                           "subject": { "kind": "account", "userId": "01a194f4-…" }, "sampleEventIds": ["…"] },
              "userId": "01a194f4-…", "firstSeenAt": "…", "lastSeenAt": "…", "resolvedAt": null, … } ],
  "pagination": { "page": 1, "pageSize": 20, "total": 1, "totalPages": 1 } }
```

**IA local opcional (explicação).** `POST /admin/security-alerts/:id/explanation` pede a um
modelo **local** (Ollama) uma explicação em texto. Ela é **desligada por padrão** (`"status": "disabled"`).
A IA não detecta, não decide, não grava e não altera nada: só explica, e a resposta vem marcada
com `"advisory": true`. Para habilitar:

```powershell
ollama pull qwen2.5:7b                       # feito por você; a API nunca baixa modelos
# no .env: ALERTS_AI_ENABLED=true  (OLLAMA_URL só aceita localhost/127.0.0.1/::1)
```

```jsonc
// POST /admin/security-alerts/:id/explanation → 200 (real, qwen2.5:7b local, ~2 s com o modelo carregado)
{ "status": "ok", "advisory": true, "model": "qwen2.5:7b",
  "explanation": { "summary": "Houve tentativas de login fracassadas para a mesma conta em um período de 1 hora.",
                   "likelyCauses": ["Ataque de força bruta", "Autenticação inválida"],
                   "suggestedChecks": ["Verificar atividade suspeita", "Ajustar configurações de autenticação"] } }

// Ollama fora do ar, lento demais ou resposta fora do formato → 200, alerta intacto
{ "status": "unavailable", "advisory": true, "reason": "TIMEOUT" }   // ou UNREACHABLE / INVALID_RESPONSE
```

A IA recebe só a regra, a severidade, os números e a duração do incidente: nunca IP, email, ids
ou datas absolutas. A primeira chamada pode demorar enquanto o modelo é carregado na memória.
Medido aqui: ultrapassou 90 s a frio e levou 2 s depois. Detalhes, limitações e falsos
positivos em [`docs/architecture.md`](docs/architecture.md#etapa-9-motor-de-alertas-de-segurança).

### Recuperação de senha

1. `POST /api/v1/auth/forgot-password` com `{"email": "..."}` responde **sempre `202`** com a
   mesma mensagem, exista ou não a conta. A busca da conta, a criação do token e o envio do
   email acontecem **depois** da resposta, então nem o tempo de resposta denuncia a conta
   (medido no servidor compilado: 14,65 ms com conta e 14,42 ms sem).
2. Se a conta existir, chega um email com o link
   `PASSWORD_RESET_URL#token=<token>`. O token vai no **fragmento** (`#`), que o navegador
   nunca envia a servidores nem coloca no cabeçalho `Referer`.
3. `POST /api/v1/auth/reset-password` com `{"token": "...", "newPassword": "..."}` troca a senha
   e **encerra todas as sessões** da conta, inclusive a de quem estiver usando a senha antiga.
   A rota não faz login: entre de novo com a nova senha.

| Regra           | Valor                                                                                                     |
| --------------- | --------------------------------------------------------------------------------------------------------- |
| Token           | 256 bits aleatórios (base64url). No banco fica só o **SHA-256**. Nunca aparece em resposta ou log         |
| Validade        | 15 minutos (`PASSWORD_RESET_TOKEN_TTL_MINUTES`)                                                           |
| Uso único       | Consumido de forma atômica. Com requisições simultâneas, só uma vence (testado com 5 em paralelo)         |
| Nova senha      | Mesma política do cadastro. Uma senha fraca **não** queima o link                                         |
| Depois do reset | Os outros links da conta deixam de valer e todas as sessões são revogadas (`PASSWORD_RESET`)              |
| Erro de token   | Sempre `400 INVALID_RESET_TOKEN` "Link de recuperação inválido ou expirado" (inválido, expirado ou usado) |

```powershell
Invoke-RestMethod -Method Post -Uri "$api/auth/forgot-password" -ContentType 'application/json' `
  -Body '{"email":"bruno.user@example.com"}'
Invoke-RestMethod -Method Post -Uri "$api/auth/reset-password" -ContentType 'application/json' `
  -Body '{"token":"<token do link>","newPassword":"girassol teimoso na janela azul"}'
```

```jsonc
// POST /auth/forgot-password → 202 (idêntico para conta existente e inexistente)
{ "message": "Se o email estiver cadastrado, você receberá as instruções para redefinir a senha." }

// POST /auth/reset-password → 200
{ "message": "Senha redefinida. Entre novamente com a nova senha." }

// POST /auth/reset-password com token inválido, expirado ou já usado → 400
{ "error": { "code": "INVALID_RESET_TOKEN", "message": "Link de recuperação inválido ou expirado", "requestId": "31a41ee6-..." } }

// POST /auth/reset-password com senha comum → 400 (o link continua valendo)
{ "error": { "code": "WEAK_PASSWORD", "message": "Esta senha é muito comum. Prefira uma frase com várias palavras",
             "requestId": "e9063c93-...", "details": { "reason": "COMMON_PASSWORD" } } }
```

**Testar localmente, sem serviço de email pago.** No `.env`, defina
`MAIL_PROVIDER=dev-mailbox` e reinicie o `npm run dev`. Cada email vira um arquivo `.txt` em
`.dev-mailbox/`, pasta que está no `.gitignore`:

```powershell
Invoke-RestMethod -Method Post -Uri "$api/auth/forgot-password" -ContentType 'application/json' `
  -Body '{"email":"bruno.user@example.com"}'
Get-ChildItem .dev-mailbox | Sort-Object LastWriteTime | Select-Object -Last 1 | Get-Content
# ... http://localhost:5173/reset-password#token=<TOKEN> → copie o valor depois de "#token="
```

- **Padrão (`MAIL_PROVIDER=log`):** registra só o tipo e a validade do email, nunca o token nem o
  destinatário, e **não entrega nada**. É o único provedor permitido em produção até existir uma
  integração real. A API avisa no log ao subir com ele em produção.
- **`dev-mailbox`:** é **recusado** com `NODE_ENV=production`, porque grava tokens em disco.
- **Provedor real:** basta implementar a interface `Mailer` (`src/modules/mail/mailer.ts`) e
  registrá-lo em `createMailer`. Os testes automatizados usam o `MemoryMailer`, injetado
  diretamente no app.

### Política de senhas

12 a 128 caracteres, qualquer caractere (passphrases são bem-vindas), **sem** regras de
composição. São rejeitadas senhas comuns, repetições, sequências e senhas que contêm o nome
ou o email. Detalhes em [`docs/architecture.md`](docs/architecture.md#política-de-senhas-nist-sp-800-63b).

### Demonstração pelo Swagger

1. Abra <http://127.0.0.1:3000/docs>.
2. **POST `/api/v1/auth/register`** → _Try it out_, informe `name`, `email` e `password` → _Execute_.
3. **POST `/api/v1/auth/login`** com o mesmo email e senha. Copie o `accessToken` e o `refreshToken`.
4. Clique em **Authorize** (cadeado no topo) e cole **apenas o access token**, sem o prefixo
   `Bearer`, que o Swagger acrescenta. Confirme.
5. **GET `/api/v1/users/me`** devolve o seu perfil. Sem o Authorize, a resposta é `401`.
6. **PATCH `/api/v1/users/me`** com `{"name": "Novo Nome"}`. Para trocar o email, envie também
   `currentPassword`.
7. **POST `/api/v1/auth/refresh`** com `{"refreshToken": "..."}` devolve um par novo. Executar
   de novo com o token **antigo** devolve `409`. Atualize o Authorize com o access token novo.
8. **POST `/api/v1/auth/logout`** devolve `204`. Repetir o `GET /users/me` agora dá `401`.
9. Com `MAIL_PROVIDER=dev-mailbox`, **POST `/api/v1/auth/forgot-password`** gera o email em
   `.dev-mailbox/`. Use o token do link em **POST `/api/v1/auth/reset-password`**.

### Exemplos (PowerShell)

Respostas reais do servidor compilado (tokens encurtados com `…`):

```powershell
$api = 'http://127.0.0.1:3000/api/v1'
$body = '{"name":"Diego Ramos","email":"  Diego.Ramos@Example.com ","password":"cavalo correto bateria grampo"}'
Invoke-RestMethod -Method Post -Uri "$api/auth/register" -ContentType 'application/json' -Body $body

$login = Invoke-RestMethod -Method Post -Uri "$api/auth/login" -ContentType 'application/json' `
  -Body '{"email":"diego.ramos@example.com","password":"cavalo correto bateria grampo"}'
$headers = @{ Authorization = "Bearer $($login.accessToken)" }

Invoke-RestMethod -Uri "$api/users/me" -Headers $headers
Invoke-RestMethod -Method Patch -Uri "$api/users/me" -Headers $headers -ContentType 'application/json' `
  -Body '{"email":"diego.novo@example.com","currentPassword":"cavalo correto bateria grampo"}'

$pair = Invoke-RestMethod -Method Post -Uri "$api/auth/refresh" -ContentType 'application/json' `
  -Body (@{ refreshToken = $login.refreshToken } | ConvertTo-Json)
Invoke-RestMethod -Method Post -Uri "$api/auth/logout" -Headers @{ Authorization = "Bearer $($pair.accessToken)" }
```

```jsonc
// POST /auth/register → 201 (email normalizado, papel USER, sem senha nem hash)
{ "id": "01a18fbd-841e-756f-8ade-d42aca744f97", "name": "Diego Ramos",
  "email": "diego.ramos@example.com", "role": "USER",
  "createdAt": "2026-10-31T02:15:24.447Z", "updatedAt": "2026-10-31T02:15:24.447Z" }

// POST /auth/login → 200
{ "accessToken": "eyJhbGciOiJI…", "tokenType": "Bearer", "expiresIn": 900,
  "refreshToken": "5UE-inkItReR…", "refreshTokenExpiresAt": "2026-11-07T23:51:46.810Z" }

// POST /auth/login → 401 (idêntico para senha errada e email inexistente)
{ "error": { "code": "INVALID_CREDENTIALS", "message": "Email ou senha inválidos", "requestId": "212ea92f-..." } }

// GET /users/me sem token → 401
{ "error": { "code": "UNAUTHORIZED", "message": "Autenticação necessária: envie Authorization: Bearer <token>", "requestId": "60f3b6e8-..." } }

// POST /auth/refresh com um token já trocado (há menos de 10 s) → 409, nenhum token emitido
{ "error": { "code": "REFRESH_TOKEN_ALREADY_ROTATED",
             "message": "Este refresh token acabou de ser trocado por outro. Use o par de tokens mais recente.", "requestId": "51f62992-..." } }

// PATCH /users/me com senha atual errada → 403
{ "error": { "code": "INVALID_CURRENT_PASSWORD", "message": "Senha atual incorreta", "requestId": "9fc54835-..." } }

// PATCH /users/me com {"role":"ADMIN"} → 400
{ "error": { "code": "VALIDATION_ERROR", "message": "Dados de entrada inválidos", "requestId": "5582959f-...",
             "details": [{ "field": "body", "message": "Unrecognized key: \"role\"" }] } }

// Qualquer rota protegida depois do logout (ou de sessão revogada) → 401
{ "error": { "code": "INVALID_SESSION", "message": "Sessão inválida ou encerrada", "requestId": "b7f7bd7f-..." } }
```

| Código de erro                  | Status | Quando                                                      |
| ------------------------------- | ------ | ----------------------------------------------------------- |
| `UNAUTHORIZED`                  | 401    | Header `Authorization: Bearer` ausente ou malformado        |
| `INVALID_TOKEN`                 | 401    | Assinatura, algoritmo, emissor ou formato inválido          |
| `TOKEN_EXPIRED`                 | 401    | Access token vencido: faça refresh                          |
| `INVALID_SESSION`               | 401    | Sessão encerrada (logout, revogação) ou expirada            |
| `INVALID_CREDENTIALS`           | 401    | Email ou senha inválidos                                    |
| `INVALID_REFRESH_TOKEN`         | 401    | Refresh token desconhecido, expirado ou de sessão encerrada |
| `REFRESH_TOKEN_REUSED`          | 401    | Token reutilizado fora da janela: a sessão foi revogada     |
| `REFRESH_TOKEN_ALREADY_ROTATED` | 409    | Token trocado há menos de 10 s: use o par mais recente      |
| `FORBIDDEN`                     | 403    | Papel sem permissão para o recurso                          |
| `INVALID_CURRENT_PASSWORD`      | 403    | Senha atual errada na troca de email                        |
| `INVALID_RESET_TOKEN`           | 400    | Link de recuperação inválido, expirado ou já usado          |
| `RATE_LIMITED`                  | 429    | Limite de requisições excedido: veja `Retry-After`          |
| `SERVICE_UNAVAILABLE`           | 503    | Proteção contra abuso indisponível (Redis fora do ar)       |

### Usuários fictícios do seed

| Email                    | Papel ao criar                     |
| ------------------------ | ---------------------------------- |
| `ada.admin@example.com`  | USER (promova com `admin:promote`) |
| `bruno.user@example.com` | USER                               |
| `carla.user@example.com` | USER                               |

A senha de todos é o valor de `SEED_USER_PASSWORD` no seu `.env`. O seed se recusa a rodar
com `NODE_ENV=production` ou contra um banco que não seja local. Desde a Etapa 5, o seed não
cria administradores e não altera o papel de contas que já existem. Se o seu banco local já
tinha `ada.admin@example.com` como ADMIN (seed da Etapa 2), ela continua ADMIN.

## Scripts

| Comando                                                    | O que faz                                                                        |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `npm run dev`                                              | Servidor com reload automático (tsx watch)                                       |
| `npm run build`                                            | Compila para `dist/`                                                             |
| `npm start`                                                | Executa o build compilado                                                        |
| `npm run lint`                                             | ESLint com regras type-checked                                                   |
| `npm run typecheck`                                        | Checagem de tipos sem emitir arquivos                                            |
| `npm run format` / `format:check`                          | Prettier                                                                         |
| `npm test`                                                 | Todos os testes (a integração exige `npm run docker:up`)                         |
| `npm run test:unit`                                        | Apenas testes unitários (sem Docker)                                             |
| `npm run test:integration`                                 | Apenas integração (banco `authapi_test` e Redis)                                 |
| `npm run test:coverage`                                    | Testes com relatório de cobertura                                                |
| `npm run docker:up`                                        | Sobe PostgreSQL e Redis e espera os healthchecks                                 |
| `npm run docker:stop`                                      | Para os containers (os dados nos volumes são mantidos)                           |
| `npm run db:migrate`                                       | Cria/aplica migrations em desenvolvimento (`prisma migrate dev`)                 |
| `npm run db:migrate:deploy`                                | Aplica migrations pendentes sem gerar novas (CI/produção)                        |
| `npm run db:seed`                                          | Popula o banco de desenvolvimento com dados fictícios                            |
| `npm run admin:promote -- --email <e> --confirm <e>`       | Promove um usuário fictício local a ADMIN (bloqueado em produção)                |
| `npm run audit:retention [-- --execute --confirm <banco>]` | Retenção da auditoria: simula por padrão; apagar exige habilitação e confirmação |
| `npm run alerts:process`                                   | Uma rodada do motor de alertas (cron/manual; seguro junto com a API)             |
| `npm run db:studio`                                        | Abre o Prisma Studio                                                             |
| `npm run db:generate`                                      | Regenera o Prisma Client após mudar o schema                                     |
