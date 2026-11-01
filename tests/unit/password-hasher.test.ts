import { argon2Sync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { hashPassword, verifyPassword } from '../../src/shared/password-hasher.js';

const PASSWORD = 'Senha-Ficticia-2026!';

describe('password hasher (Argon2id)', () => {
  it('gera hash no formato PHC com os parâmetros da OWASP', async () => {
    const hash = await hashPassword(PASSWORD);

    expect(hash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$[\w-]{22}\$[\w-]{43}$/);
    expect(hash).not.toContain(PASSWORD);
  });

  it('usa salt aleatório: a mesma senha gera hashes diferentes', async () => {
    const [first, second] = await Promise.all([hashPassword(PASSWORD), hashPassword(PASSWORD)]);

    expect(first).not.toBe(second);
  });

  it('verifica a senha correta e rejeita a incorreta', async () => {
    const hash = await hashPassword(PASSWORD);

    await expect(verifyPassword(hash, PASSWORD)).resolves.toBe(true);
    await expect(verifyPassword(hash, 'senha-errada')).resolves.toBe(false);
    await expect(verifyPassword(hash, `${PASSWORD} `)).resolves.toBe(false);
  });

  it('verifica hashes gerados com outros parâmetros (lidos do próprio hash)', async () => {
    const salt = Buffer.from('salt-ficticio-16');
    const raw = argon2Sync('argon2id', {
      message: PASSWORD,
      nonce: salt,
      memory: 8_192,
      passes: 3,
      parallelism: 1,
      tagLength: 32,
    });
    const legacy = `$argon2id$v=19$m=8192,t=3,p=1$${salt.toString('base64url')}$${raw.toString('base64url')}`;

    await expect(verifyPassword(legacy, PASSWORD)).resolves.toBe(true);
  });

  it('retorna false (sem lançar) para hashes malformados ou de outro algoritmo', async () => {
    for (const invalid of [
      '',
      'texto-qualquer',
      '$argon2i$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA',
      '$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234',
    ]) {
      await expect(verifyPassword(invalid, PASSWORD)).resolves.toBe(false);
    }
  });
});
