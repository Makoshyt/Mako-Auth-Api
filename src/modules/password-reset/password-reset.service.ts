import { AppError } from '../../shared/errors.js';
import type { BackgroundTasks } from '../../shared/background-tasks.js';
import type { AuditRecorder } from '../audit/audit.recorder.js';
import type { ClientInfo } from '../auth/auth.types.js';
import { generateOpaqueToken, hashOpaqueToken } from '../auth/tokens.js';
import type { Mailer } from '../mail/mailer.js';
import { checkPasswordPolicy, PASSWORD_VIOLATION_MESSAGES } from '../users/password-policy.js';
import type { PasswordResetRepository } from './password-reset.repository.js';

export interface PasswordResetServiceDeps {
  repository: PasswordResetRepository;
  hashPassword: (password: string) => Promise<string>;
  mailer: Mailer;
  audit: AuditRecorder;
  tasks: BackgroundTasks;
  tokenTtlMinutes: number;
  now?: () => Date;
}

export type PasswordResetService = ReturnType<typeof createPasswordResetService>;

/** Mesma resposta para inválido, expirado e já usado: não ajuda quem testa tokens. */
const invalidToken = () =>
  new AppError(400, 'INVALID_RESET_TOKEN', 'Link de recuperação inválido ou expirado');

export function createPasswordResetService({
  repository,
  hashPassword,
  mailer,
  audit,
  tasks,
  tokenTtlMinutes,
  now = () => new Date(),
}: PasswordResetServiceDeps) {
  /** Roda DEPOIS da resposta. Nada aqui altera o status, o corpo ou o tempo da resposta. */
  async function issueToken(email: string, client: ClientInfo): Promise<void> {
    const userId = await repository.findUserIdByEmail(email);
    if (!userId) {
      await audit.record({
        type: 'PASSWORD_RESET_REQUEST',
        email,
        ip: client.ip,
        metadata: { outcome: 'UNKNOWN_EMAIL' },
      });
      return;
    }

    const token = generateOpaqueToken();
    const expiresAt = new Date(now().getTime() + tokenTtlMinutes * 60_000);
    await repository.createToken({ userId, tokenHash: hashOpaqueToken(token), expiresAt });
    await audit.record({
      type: 'PASSWORD_RESET_REQUEST',
      userId,
      email,
      ip: client.ip,
      metadata: { outcome: 'TOKEN_ISSUED' },
    });
    // O token sai da aplicação só por aqui: nunca na resposta HTTP, nunca no log.
    await mailer.send({ type: 'PASSWORD_RESET', to: email, token, expiresAt });
  }

  return {
    /**
     * Agenda a emissão e retorna na hora. A busca da conta, o INSERT e o envio acontecem em
     * segundo plano: para quem chama, email cadastrado e inexistente são idênticos em status,
     * corpo e tempo de resposta.
     */
    requestReset(email: string, client: ClientInfo): void {
      tasks.run('password-reset-request', () => issueToken(email, client));
    },

    async resetPassword(token: string, newPassword: string, client: ClientInfo): Promise<void> {
      const at = now();
      const record = await repository.findToken(hashOpaqueToken(token));
      if (!record || record.usedAt !== null || record.expiresAt <= at) throw invalidToken();

      // Antes de consumir o token: uma senha fraca não queima o link.
      const violation = checkPasswordPolicy(newPassword, record.user);
      if (violation) {
        throw new AppError(400, 'WEAK_PASSWORD', PASSWORD_VIOLATION_MESSAGES[violation], {
          reason: violation,
        });
      }

      // Argon2id fora da transação: o custo da derivação não segura locks no banco.
      const passwordHash = await hashPassword(newPassword);
      const result = await repository.completeReset({
        tokenId: record.id,
        userId: record.userId,
        passwordHash,
        now: at,
      });
      // Outra requisição consumiu o mesmo token primeiro (ou ele expirou no meio do caminho).
      if (!result.completed) throw invalidToken();

      await audit.record({
        type: 'PASSWORD_RESET_SUCCESS',
        userId: record.userId,
        ip: client.ip,
        metadata: { revokedSessions: result.revokedSessions },
      });
    },
  };
}
