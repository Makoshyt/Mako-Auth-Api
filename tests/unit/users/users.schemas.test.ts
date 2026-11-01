import { describe, expect, it } from 'vitest';
import {
  registerBodySchema,
  toPublicUserDto,
  updateProfileBodySchema,
} from '../../../src/modules/users/users.schemas.js';

const valid = {
  name: 'Ana Souza',
  email: 'ana.souza@example.com',
  password: 'cavalo correto bateria grampo',
};

/** Caminhos dos campos com erro, para asserções legíveis. */
function errorPaths(result: { success: boolean; error?: { issues: { path: PropertyKey[] }[] } }) {
  return result.error?.issues.map((issue) => issue.path.join('.')) ?? [];
}

describe('registerBodySchema', () => {
  it('aceita um cadastro válido', () => {
    expect(registerBodySchema.parse(valid)).toEqual(valid);
  });

  it('normaliza email com trim e minúsculas', () => {
    const parsed = registerBodySchema.parse({ ...valid, email: '  Ana.SOUZA@Example.COM  ' });

    expect(parsed.email).toBe('ana.souza@example.com');
  });

  it('normaliza o nome: trim e espaços internos colapsados', () => {
    const parsed = registerBodySchema.parse({ ...valid, name: '  Ana    Maria   Souza ' });

    expect(parsed.name).toBe('Ana Maria Souza');
  });

  it('não altera a senha (espaços nas pontas fazem parte dela)', () => {
    const parsed = registerBodySchema.parse({ ...valid, password: '  frase com espaços  ' });

    expect(parsed.password).toBe('  frase com espaços  ');
  });

  it.each([
    ['vazio', ''],
    ['só espaços', '     '],
    ['com 101 caracteres', 'a'.repeat(101)],
    ['com caractere de controle', 'Ana\u0000Souza'],
    ['com override de direção (bidi)', `Ana ${String.fromCodePoint(0x202e)}azuoS`],
    ['com caractere de largura zero', `Ana${String.fromCodePoint(0x200b)}Souza`],
  ])('rejeita nome %s', (_label, name) => {
    const result = registerBodySchema.safeParse({ ...valid, name });

    expect(errorPaths(result)).toEqual(['name']);
  });

  it.each(['sem-arroba', 'ana@', '@example.com', `${'a'.repeat(250)}@example.com`])(
    'rejeita email inválido: %s',
    (email) => {
      expect(errorPaths(registerBodySchema.safeParse({ ...valid, email }))).toEqual(['email']);
    },
  );

  it('rejeita senha com menos de 12 caracteres', () => {
    const result = registerBodySchema.safeParse({ ...valid, password: 'curta123' });

    expect(errorPaths(result)).toEqual(['password']);
  });

  it.each([
    ['role ADMIN', { role: 'ADMIN' }],
    ['id', { id: '00000000-0000-7000-8000-000000000000' }],
    ['passwordHash', { passwordHash: '$argon2id$...' }],
    ['campo qualquer', { isVerified: true }],
  ])('rejeita campo extra: %s', (_label, extra) => {
    const result = registerBodySchema.safeParse({ ...valid, ...extra });

    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.code).toBe('unrecognized_keys');
  });

  it('exige todos os campos', () => {
    expect(errorPaths(registerBodySchema.safeParse({})).sort()).toEqual([
      'email',
      'name',
      'password',
    ]);
  });
});

describe('updateProfileBodySchema', () => {
  it('aceita só name, só email ou ambos, normalizando o email', () => {
    expect(updateProfileBodySchema.parse({ name: 'Novo Nome' })).toEqual({ name: 'Novo Nome' });
    expect(
      updateProfileBodySchema.parse({
        email: ' NOVO@Example.com ',
        currentPassword: 'senha atual',
      }),
    ).toEqual({ email: 'novo@example.com', currentPassword: 'senha atual' });
  });

  it('exige currentPassword quando o email é informado', () => {
    const result = updateProfileBodySchema.safeParse({ email: 'novo@example.com' });

    expect(errorPaths(result)).toEqual(['currentPassword']);
  });

  it('rejeita corpo vazio', () => {
    expect(updateProfileBodySchema.safeParse({}).success).toBe(false);
  });

  it.each([
    ['role', { role: 'ADMIN' }],
    ['password', { password: 'nova senha bem longa' }],
    ['passwordHash', { passwordHash: 'x' }],
    ['id', { id: '00000000-0000-7000-8000-000000000000' }],
    ['createdAt', { createdAt: '2020-01-01T00:00:00.000Z' }],
  ])('rejeita campo não autorizado: %s', (_label, extra) => {
    const result = updateProfileBodySchema.safeParse({ name: 'Nome Válido', ...extra });

    expect(result.success).toBe(false);
  });
});

describe('toPublicUserDto', () => {
  it('copia somente campos públicos, mesmo que o objeto de entrada tenha mais', () => {
    const date = new Date('2026-01-02T03:04:05.000Z');
    const leaky = {
      id: '0190a000-0000-7000-8000-000000000001',
      name: 'Ana',
      email: 'ana@example.com',
      role: 'USER' as const,
      createdAt: date,
      updatedAt: date,
      passwordHash: '$argon2id$v=19$segredo',
    };

    const dto = toPublicUserDto(leaky);

    expect(dto).not.toHaveProperty('passwordHash');
    expect(dto.createdAt).toBe('2026-01-02T03:04:05.000Z');
  });
});
