import { describe, expect, it } from 'vitest';
import { checkPasswordPolicy } from '../../../src/modules/users/password-policy.js';

describe('política de senhas', () => {
  it.each([
    ['passphrase com espaços', 'cavalo correto bateria grampo'],
    ['frase longa sem símbolos', 'minha bicicleta azul tem doze marchas'],
    ['senha aleatória', 'k7#Qm2!vXp9@Lr4z'],
    ['acentos e emoji', 'café com pão às sete 🔐'],
    ['exatamente 12 caracteres', 'tr3s-gatos-v'],
  ])('aceita %s', (_label, password) => {
    expect(checkPasswordPolicy(password)).toBeNull();
  });

  it('não exige maiúsculas, dígitos ou símbolos (sem regras de composição)', () => {
    expect(checkPasswordPolicy('somente letras minusculas aqui')).toBeNull();
  });

  it.each([
    ['vazia', ''],
    ['11 caracteres', 'abcdefghij1'],
    ['11 code points mesmo com emoji', '🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐'],
  ])('rejeita senha curta: %s', (_label, password) => {
    expect(checkPasswordPolicy(password)).toBe('TOO_SHORT');
  });

  it('conta code points: 12 emojis são 12 caracteres (e não 24 unidades UTF-16)', () => {
    expect(checkPasswordPolicy('🔐🌵🎲🚲🧩🎈🪁🛶🎻🧭🪴🦉')).toBeNull();
  });

  it('rejeita senha acima de 128 caracteres', () => {
    expect(checkPasswordPolicy('a b c d '.repeat(17))).toBe('TOO_LONG');
  });

  it.each([
    'Password2024!',
    'password1234',
    'P@ssw0rd12345',
    'senha@123456',
    'Senha12345678',
    'iloveyou2024!',
    'Flamengo2026!!',
    'admin1234567',
    'senhasenhasenha',
    '!!!qwerty!!!123',
  ])('rejeita senha comum: %s', (password) => {
    expect(checkPasswordPolicy(password)).toBe('COMMON_PASSWORD');
  });

  it.each(['aaaaaaaaaaaa', '121212121212', 'abcabcabcabc', 'xyz!xyz!xyz!'])(
    'rejeita repetição: %s',
    (password) => {
      expect(checkPasswordPolicy(password)).toBe('REPETITIVE');
    },
  );

  it.each(['123456789012', '0987654321098', 'qwertyuiopas', 'abcdefghijklmn', '1qaz2wsx3edc'])(
    'rejeita sequência: %s',
    (password) => {
      expect(checkPasswordPolicy(password)).toBe('SEQUENTIAL');
    },
  );

  it('rejeita senha que contém o email ou o nome do usuário', () => {
    const context = { email: 'mariana.costa@example.com', name: 'Mariana Costa' };

    expect(checkPasswordPolicy('mariana.costa@example.com', context)).toBe(
      'CONTAINS_PERSONAL_DATA',
    );
    expect(checkPasswordPolicy('eu sou a Mariana 2026', context)).toBe('CONTAINS_PERSONAL_DATA');
    expect(checkPasswordPolicy('costa-forte-segura', context)).toBe('CONTAINS_PERSONAL_DATA');
  });

  it('ignora fragmentos curtos do nome para não barrar passphrases legítimas', () => {
    // "Ana" tem 3 letras: aparecer dentro de "banana" não é dado pessoal.
    expect(checkPasswordPolicy('banana com canela e mel', { name: 'Ana Li' })).toBeNull();
  });
});
