import { randomUUID } from 'node:crypto';
import { EmailAlreadyInUseError } from '../../src/modules/users/users.repository.js';
import type {
  ProfileChanges,
  PublicUser,
  UpdateProfileOptions,
  UsersRepository,
} from '../../src/modules/users/users.types.js';

interface StoredUser extends PublicUser {
  passwordHash: string;
}

/**
 * Repositório falso para testes unitários do service: mesma interface e mesmas regras
 * (email único, role sempre USER no create), sem banco. Expõe `stored` para inspeção.
 */
export class InMemoryUsersRepository implements UsersRepository {
  readonly stored = new Map<string, StoredUser>();
  /** Opções recebidas em cada updateProfile, para verificar a revogação de sessões. */
  readonly updateOptions: UpdateProfileOptions[] = [];

  private toPublic({ passwordHash: _hash, ...user }: StoredUser): PublicUser {
    return { ...user };
  }

  private emailTaken(email: string, exceptId?: string): boolean {
    return [...this.stored.values()].some((user) => user.email === email && user.id !== exceptId);
  }

  create(data: { name: string; email: string; passwordHash: string }): Promise<PublicUser> {
    if (this.emailTaken(data.email)) return Promise.reject(new EmailAlreadyInUseError());
    const now = new Date();
    const user: StoredUser = {
      id: randomUUID(),
      name: data.name,
      email: data.email,
      passwordHash: data.passwordHash,
      role: 'USER',
      createdAt: now,
      updatedAt: now,
    };
    this.stored.set(user.id, user);
    return Promise.resolve(this.toPublic(user));
  }

  findById(id: string): Promise<PublicUser | null> {
    const user = this.stored.get(id);
    return Promise.resolve(user ? this.toPublic(user) : null);
  }

  findCredentials(id: string): Promise<{ email: string; passwordHash: string } | null> {
    const user = this.stored.get(id);
    return Promise.resolve(user ? { email: user.email, passwordHash: user.passwordHash } : null);
  }

  updateProfile(
    id: string,
    data: ProfileChanges,
    options: UpdateProfileOptions = {},
  ): Promise<PublicUser | null> {
    this.updateOptions.push(options);
    const user = this.stored.get(id);
    if (!user) return Promise.resolve(null);
    if (data.email !== undefined && this.emailTaken(data.email, id)) {
      return Promise.reject(new EmailAlreadyInUseError());
    }
    const updated: StoredUser = {
      ...user,
      name: data.name ?? user.name,
      email: data.email ?? user.email,
      updatedAt: new Date(user.updatedAt.getTime() + 1),
    };
    this.stored.set(id, updated);
    return Promise.resolve(this.toPublic(updated));
  }
}
