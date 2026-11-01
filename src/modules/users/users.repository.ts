import { Prisma } from '../../generated/prisma/client.js';
import type { PrismaClient } from '../../infra/prisma.js';
import type {
  ProfileChanges,
  PublicUser,
  UpdateProfileOptions,
  UsersRepository,
} from './users.types.js';

/** Projeção pública. Só `findCredentials` lê o passwordHash, para o service confirmar a senha. */
export const publicUserSelect = {
  id: true,
  name: true,
  email: true,
  role: true,
  createdAt: true,
  updatedAt: true,
} as const satisfies Prisma.UserSelect;

export class EmailAlreadyInUseError extends Error {
  constructor() {
    super('email já cadastrado');
    this.name = 'EmailAlreadyInUseError';
  }
}

const isUniqueViolation = (error: unknown) =>
  error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';

const isNotFound = (error: unknown) =>
  error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2025';

export function createUsersRepository(prisma: PrismaClient): UsersRepository {
  return {
    async create({ name, email, passwordHash }): Promise<PublicUser> {
      try {
        // O índice único do banco é a fonte da verdade: não há "SELECT antes do INSERT",
        // que teria condição de corrida entre dois cadastros simultâneos.
        return await prisma.user.create({
          data: { name, email, passwordHash, role: 'USER' },
          select: publicUserSelect,
        });
      } catch (error) {
        if (isUniqueViolation(error)) throw new EmailAlreadyInUseError();
        throw error;
      }
    },

    findById(id) {
      return prisma.user.findUnique({ where: { id }, select: publicUserSelect });
    },

    findCredentials(id) {
      return prisma.user.findUnique({ where: { id }, select: { email: true, passwordHash: true } });
    },

    async updateProfile(
      id,
      data: ProfileChanges,
      { revokeOtherSessions }: UpdateProfileOptions = {},
    ) {
      try {
        return await prisma.$transaction(async (tx) => {
          const user = await tx.user.update({
            where: { id },
            // Campo a campo: mesmo que `data` chegue com chaves extras, só estas são gravadas.
            data: { name: data.name, email: data.email },
            select: publicUserSelect,
          });
          if (revokeOtherSessions) {
            // Mesma transação: o email nunca muda sem que as outras sessões caiam junto.
            const { keepSessionId } = revokeOtherSessions;
            await tx.session.updateMany({
              where: {
                userId: id,
                revokedAt: null,
                ...(keepSessionId !== undefined && { id: { not: keepSessionId } }),
              },
              data: { revokedAt: new Date(), revokedReason: 'EMAIL_CHANGE' },
            });
          }
          return user;
        });
      } catch (error) {
        if (isUniqueViolation(error)) throw new EmailAlreadyInUseError();
        if (isNotFound(error)) return null;
        throw error;
      }
    },
  };
}
