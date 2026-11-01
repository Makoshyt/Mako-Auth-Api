import { AppError, conflict, notFound } from '../../shared/errors.js';
import { checkPasswordPolicy, PASSWORD_VIOLATION_MESSAGES } from './password-policy.js';
import { EmailAlreadyInUseError } from './users.repository.js';
import type {
  HashPassword,
  ProfileChanges,
  PublicUser,
  RegisterInput,
  UpdateProfileInput,
  UsersRepository,
  VerifyPassword,
} from './users.types.js';

export interface UsersServiceDeps {
  usersRepository: UsersRepository;
  hashPassword: HashPassword;
  verifyPassword: VerifyPassword;
}

export type UsersService = ReturnType<typeof createUsersService>;

const EMAIL_CONFLICT_MESSAGE = 'Este email já está cadastrado';

export function createUsersService({
  usersRepository,
  hashPassword,
  verifyPassword,
}: UsersServiceDeps) {
  return {
    /**
     * Cadastro público. O papel é sempre USER: a entrada não tem campo role e o
     * repositório fixa o valor. Promoção a ADMIN é operação administrativa (Etapa 5).
     */
    async register(input: RegisterInput): Promise<PublicUser> {
      const violation = checkPasswordPolicy(input.password, {
        email: input.email,
        name: input.name,
      });
      if (violation) {
        throw new AppError(400, 'WEAK_PASSWORD', PASSWORD_VIOLATION_MESSAGES[violation], {
          reason: violation,
        });
      }

      const passwordHash = await hashPassword(input.password);
      try {
        return await usersRepository.create({
          name: input.name,
          email: input.email,
          passwordHash,
        });
      } catch (error) {
        if (error instanceof EmailAlreadyInUseError) throw conflict(EMAIL_CONFLICT_MESSAGE);
        throw error;
      }
    },

    /** `userId` deve vir sempre do token autenticado, nunca da requisição. */
    async getProfile(userId: string): Promise<PublicUser> {
      const user = await usersRepository.findById(userId);
      if (!user) throw notFound('Usuário não encontrado');
      return user;
    },

    /**
     * Só name e email. Senha tem fluxo próprio; role, só via rota administrativa.
     *
     * Trocar o email exige a senha atual: um access token roubado, sozinho, não consegue
     * apontar a conta para um email do atacante. Depois da troca, as DEMAIS sessões são
     * revogadas (a atual, `currentSessionId`, continua) na mesma transação do UPDATE.
     */
    async updateProfile(
      userId: string,
      input: UpdateProfileInput,
      { currentSessionId }: { currentSessionId?: string } = {},
    ): Promise<PublicUser> {
      const changes: ProfileChanges = {};
      if (input.name !== undefined) changes.name = input.name;
      if (input.email !== undefined) changes.email = input.email;
      if (Object.keys(changes).length === 0) {
        throw new AppError(400, 'BAD_REQUEST', 'Informe ao menos um campo: name ou email');
      }

      let emailChanged = false;
      if (changes.email !== undefined) {
        if (!input.currentPassword) {
          throw new AppError(
            400,
            'CURRENT_PASSWORD_REQUIRED',
            'Para trocar o email, informe a senha atual',
          );
        }
        const credentials = await usersRepository.findCredentials(userId);
        if (!credentials) throw notFound('Usuário não encontrado');
        if (!(await verifyPassword(credentials.passwordHash, input.currentPassword))) {
          throw new AppError(403, 'INVALID_CURRENT_PASSWORD', 'Senha atual incorreta');
        }
        emailChanged = credentials.email !== changes.email;
      }

      try {
        const user = await usersRepository.updateProfile(
          userId,
          changes,
          emailChanged ? { revokeOtherSessions: { keepSessionId: currentSessionId } } : {},
        );
        if (!user) throw notFound('Usuário não encontrado');
        return user;
      } catch (error) {
        if (error instanceof EmailAlreadyInUseError) throw conflict(EMAIL_CONFLICT_MESSAGE);
        throw error;
      }
    },
  };
}
