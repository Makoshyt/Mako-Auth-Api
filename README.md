# AuthAPI Pro

API REST de autenticação e gerenciamento de usuários construída com Node.js, TypeScript,
Fastify, PostgreSQL e Prisma.

> **Status:** Etapa 5 de 10 (RBAC USER/ADMIN, rotas administrativas somente leitura e trilha de auditoria).
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

`JWT_ACCESS_SECRET` é obrigatório (mínimo de 32 caracteres) e a API não sobe sem ele. Gere um
valor só seu e cole no `.env`, que nunca é versionado:

```powershell
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

Se você já tinha um `.env` da Etapa 3, rode também `npm run db:migrate:deploy`. A Etapa 4 traz
uma migration que só acrescenta dados (o valor `EMAIL_CHANGE` ao enum de motivos de revogação).

O PostgreSQL do Docker usa a porta **5433** para não conflitar com um PostgreSQL instalado
localmente na 5432. As portas são publicadas apenas em `127.0.0.1`.

## Endpoints disponíveis

| Método | Rota                         | Acesso   | Descrição                                                   |
| ------ | ---------------------------- | -------- | ----------------------------------------------------------- |
| GET    | `/health`                    | público  | Liveness do processo                                        |
| GET    | `/ready`                     | público  | Readiness: PostgreSQL e Redis (200 ou 503)                  |
| POST   | `/api/v1/auth/register`      | público  | Cadastro (papel USER), retorna 201                          |
| POST   | `/api/v1/auth/login`         | público  | Cria uma sessão e devolve access token + refresh token      |
| POST   | `/api/v1/auth/refresh`       | público* | Troca o refresh token por um par novo (rotação obrigatória) |
| POST   | `/api/v1/auth/logout`        | Bearer   | Encerra a sessão atual (204)                                |
| POST   | `/api/v1/auth/logout-all`    | Bearer   | Encerra todas as sessões do usuário (204)                   |
| GET    | `/api/v1/users/me`           | Bearer   | Perfil do usuário autenticado                               |
| PATCH  | `/api/v1/users/me`           | Bearer   | Altera nome e/ou email (o email exige `currentPassword`)    |
| GET    | `/api/v1/admin/users`        | ADMIN    | Lista usuários: paginação, filtros e ordenação controlada   |
| GET    | `/api/v1/admin/users/:id`    | ADMIN    | Consulta um usuário (404 se não existir)                    |
| GET    | `/api/v1/admin/audit-events` | ADMIN    | Trilha de auditoria: filtros por tipo, usuário e período    |
| GET    | `/docs`                      | público  | Swagger UI (desligável com `SWAGGER_ENABLED`)               |

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

> **Rate limiting** de login, cadastro e refresh chega na **Etapa 6**. Até lá, a defesa contra
> força bruta é o custo do Argon2id e a trilha de auditoria (`LOGIN_FAILURE`).

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

| Comando                                              | O que faz                                                         |
| ---------------------------------------------------- | ----------------------------------------------------------------- |
| `npm run dev`                                        | Servidor com reload automático (tsx watch)                        |
| `npm run build`                                      | Compila para `dist/`                                              |
| `npm start`                                          | Executa o build compilado                                         |
| `npm run lint`                                       | ESLint com regras type-checked                                    |
| `npm run typecheck`                                  | Checagem de tipos sem emitir arquivos                             |
| `npm run format` / `format:check`                    | Prettier                                                          |
| `npm test`                                           | Todos os testes (a integração exige `npm run docker:up`)          |
| `npm run test:unit`                                  | Apenas testes unitários (sem Docker)                              |
| `npm run test:integration`                           | Apenas integração (banco `authapi_test` e Redis)                  |
| `npm run test:coverage`                              | Testes com relatório de cobertura                                 |
| `npm run docker:up`                                  | Sobe PostgreSQL e Redis e espera os healthchecks                  |
| `npm run docker:stop`                                | Para os containers (os dados nos volumes são mantidos)            |
| `npm run db:migrate`                                 | Cria/aplica migrations em desenvolvimento (`prisma migrate dev`)  |
| `npm run db:migrate:deploy`                          | Aplica migrations pendentes sem gerar novas (CI/produção)         |
| `npm run db:seed`                                    | Popula o banco de desenvolvimento com dados fictícios             |
| `npm run admin:promote -- --email <e> --confirm <e>` | Promove um usuário fictício local a ADMIN (bloqueado em produção) |
| `npm run db:studio`                                  | Abre o Prisma Studio                                              |
| `npm run db:generate`                                | Regenera o Prisma Client após mudar o schema                      |
