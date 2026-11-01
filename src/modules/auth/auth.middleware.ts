import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { Role } from '../../generated/prisma/enums.js';
import { AppError, forbidden } from '../../shared/errors.js';
import type { AuditRecorder } from '../audit/audit.recorder.js';
import type { AuthService } from './auth.service.js';
import type { AuthContext, ClientInfo } from './auth.types.js';

export type AuthHook = (request: FastifyRequest, reply: FastifyReply) => Promise<void>;

declare module 'fastify' {
  interface FastifyRequest {
    /** Preenchido apenas pelo hook `authenticate`. Leia com `authOf(request)`. */
    auth: AuthContext | null;
  }
  interface FastifyInstance {
    /** Hook (use em onRequest) que exige um Bearer token válido de uma sessão ativa. */
    authenticate: AuthHook;
    /** Trilha de auditoria, usada pelo `requireRole` para registrar ACCESS_DENIED. */
    audit: AuditRecorder;
  }
}

// JWTs HS256 deste serviço têm poucas centenas de bytes; o teto evita trabalho com lixo.
const BEARER_PATTERN = /^Bearer +([A-Za-z0-9_.-]{1,2048}) *$/i;

const missingToken = () =>
  new AppError(401, 'UNAUTHORIZED', 'Autenticação necessária: envie Authorization: Bearer <token>');

/** Extrai o token SOMENTE do header Authorization. Body, query e cookies são ignorados. */
export function extractBearerToken(header: string | undefined): string {
  const match = header === undefined ? null : BEARER_PATTERN.exec(header);
  if (!match?.[1]) throw missingToken();
  return match[1];
}

/** Identidade autenticada. Se a rota esqueceu o `authenticate`, falha fechada com 401. */
export function authOf(request: FastifyRequest): AuthContext {
  if (!request.auth) throw missingToken();
  return request.auth;
}

/** IP (respeita TRUST_PROXY) e User-Agent, truncados ao tamanho das colunas. */
export function clientInfo(request: FastifyRequest): ClientInfo {
  const userAgent = request.headers['user-agent'];
  return {
    ip: request.ip ? request.ip.slice(0, 45) : null,
    userAgent: userAgent ? userAgent.slice(0, 255) : null,
  };
}

/**
 * Exige um dos papéis informados. Deve vir DEPOIS de `authenticate`.
 * Sem identidade: 401 (quem é você?). Papel insuficiente: 403 (sei quem é, mas não pode).
 * O papel avaliado é o de `request.auth`, que o `authenticate` leu do banco nesta requisição.
 *
 * Cada 403 vira um evento ACCESS_DENIED com o mínimo necessário: quem, de onde e qual rota
 * (o padrão, ex. /admin/users/:id, sem query string nem ids que possam conter dados pessoais).
 */
export function requireRole(...roles: [Role, ...Role[]]): AuthHook {
  return async (request) => {
    const auth = authOf(request);
    if (roles.includes(auth.role)) return;

    await request.server.audit.record({
      type: 'ACCESS_DENIED',
      userId: auth.userId,
      ip: clientInfo(request).ip,
      metadata: {
        method: request.method,
        route: request.routeOptions.url ?? 'desconhecida',
        requiredRoles: roles.join(','),
        role: auth.role,
      },
    });
    throw forbidden('Seu papel não permite acessar este recurso');
  };
}

/** Decora o app com `request.auth`, `app.authenticate` e `app.audit`. Chamado no composition root. */
export function registerAuthentication(
  app: FastifyInstance,
  authService: AuthService,
  audit: AuditRecorder,
): void {
  app.decorateRequest('auth', null);
  app.decorate('audit', audit);
  app.decorate('authenticate', async (request: FastifyRequest) => {
    const token = extractBearerToken(request.headers.authorization);
    request.auth = await authService.authenticate(token);
  });
}
