import type { Role } from '../../generated/prisma/enums.js';

/** Dados de usuário que podem sair do módulo. Nunca contém passwordHash. */
export interface PublicUser {
  id: string;
  name: string;
  email: string;
  role: Role;
  createdAt: Date;
  updatedAt: Date;
}

/** Entrada do cadastro, já validada e normalizada pelo schema. Não existe campo role. */
export interface RegisterInput {
  name: string;
  email: string;
  password: string;
}

/** Campos que o próprio usuário pode alterar. Senha e papel ficam fora por desenho. */
export interface ProfileChanges {
  name?: string;
  email?: string;
}

/** Entrada do PATCH /users/me. Trocar o email exige a senha atual. */
export interface UpdateProfileInput extends ProfileChanges {
  currentPassword?: string;
}

export interface UpdateProfileOptions {
  /** Revoga as sessões ativas do usuário, exceto `keepSessionId`, na mesma transação. */
  revokeOtherSessions?: { keepSessionId?: string };
}

export interface UsersRepository {
  /** Sempre cria com role USER. Lança EmailAlreadyInUseError se o email existir. */
  create(data: { name: string; email: string; passwordHash: string }): Promise<PublicUser>;
  findById(id: string): Promise<PublicUser | null>;
  /** Uso interno (confirmação de senha). O hash nunca sai do service. */
  findCredentials(id: string): Promise<{ email: string; passwordHash: string } | null>;
  /** Retorna null se o usuário não existir. Lança EmailAlreadyInUseError em conflito. */
  updateProfile(
    id: string,
    data: ProfileChanges,
    options?: UpdateProfileOptions,
  ): Promise<PublicUser | null>;
}

export type HashPassword = (password: string) => Promise<string>;
export type VerifyPassword = (encoded: string, password: string) => Promise<boolean>;
