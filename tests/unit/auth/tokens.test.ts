import { generateKeyPair, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';
import {
  AccessTokenError,
  createAccessTokenSigner,
  generateRefreshToken,
  hashRefreshToken,
} from '../../../src/modules/auth/tokens.js';

const SECRET = 'segredo-ficticio-de-teste-com-32-caracteres-ou-mais';
const signer = createAccessTokenSigner(SECRET, 900);
const key = new TextEncoder().encode(SECRET);
const identity = {
  userId: '0190a000-0000-7000-8000-000000000001',
  sessionId: '0190a000-0000-7000-8000-000000000002',
  role: 'USER' as const,
};

const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');
const decodePart = (part: string | undefined) =>
  JSON.parse(Buffer.from(part ?? '', 'base64url').toString()) as Record<string, unknown>;

async function expectRejected(token: string, reason: 'EXPIRED' | 'INVALID', now?: Date) {
  const error = await signer.verify(token, now).catch((caught: unknown) => caught);
  expect(error).toBeInstanceOf(AccessTokenError);
  expect(error).toMatchObject({ reason });
}

/** Payload válido assinado por fora do signer, para testar variações de cabeçalho/claims. */
const validPayload = () => {
  const iat = Math.floor(Date.now() / 1000);
  return {
    sub: identity.userId,
    sid: identity.sessionId,
    role: 'USER',
    iat,
    exp: iat + 900,
    iss: 'authapi-pro',
    aud: 'authapi-pro:api',
  };
};

describe('access token (JWT HS256)', () => {
  it('emite e valida com as claims sub, sid, role, iat e exp (15 min)', async () => {
    const token = await signer.sign(identity);

    const claims = await signer.verify(token);

    expect(claims).toMatchObject({ sub: identity.userId, sid: identity.sessionId, role: 'USER' });
    expect(claims.exp - claims.iat).toBe(900);
    expect(decodePart(token.split('.')[0])).toEqual({ alg: 'HS256', typ: 'JWT' });
  });

  it('rejeita token expirado com o motivo EXPIRED', async () => {
    const issuedAt = new Date(Date.now() - 16 * 60 * 1000);
    const token = await signer.sign(identity, issuedAt);

    await expectRejected(token, 'EXPIRED');
  });

  it('aceita até o último segundo antes do exp', async () => {
    const issuedAt = new Date('2026-01-01T00:00:00.000Z');
    const token = await signer.sign(identity, issuedAt);

    await expect(signer.verify(token, new Date('2026-01-01T00:14:59.000Z'))).resolves.toBeTruthy();
    await expectRejected(token, 'EXPIRED', new Date('2026-01-01T00:15:00.000Z'));
  });

  it('rejeita payload adulterado (role trocado para ADMIN) com a assinatura original', async () => {
    const [header, payload, signature] = (await signer.sign(identity)).split('.');
    const forged = b64({ ...decodePart(payload), role: 'ADMIN' });

    await expectRejected(`${header ?? ''}.${forged}.${signature ?? ''}`, 'INVALID');
  });

  it('rejeita assinatura adulterada', async () => {
    const token = await signer.sign(identity);
    const tampered = token.slice(0, -2) + (token.endsWith('AA') ? 'BB' : 'AA');

    await expectRejected(tampered, 'INVALID');
  });

  it('rejeita alg "none" (token sem assinatura)', async () => {
    const token = `${b64({ alg: 'none', typ: 'JWT' })}.${b64(validPayload())}.`;

    await expectRejected(token, 'INVALID');
  });

  it('rejeita HS512 mesmo assinado com o segredo correto (só HS256 é aceito)', async () => {
    const token = await new SignJWT(validPayload())
      .setProtectedHeader({ alg: 'HS512', typ: 'JWT' })
      .sign(key);

    await expectRejected(token, 'INVALID');
  });

  it('rejeita RS256 (confusão de algoritmo com chave assimétrica)', async () => {
    const { privateKey } = await generateKeyPair('RS256');
    const token = await new SignJWT(validPayload())
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
      .sign(privateKey);

    await expectRejected(token, 'INVALID');
  });

  it('rejeita token assinado com outro segredo', async () => {
    const other = createAccessTokenSigner('outro-segredo-ficticio-tambem-com-32-chars', 900);

    await expectRejected(await other.sign(identity), 'INVALID');
  });

  it.each([
    ['sem sid', { sid: undefined }],
    ['sub que não é UUID', { sub: 'admin' }],
    ['role desconhecido', { role: 'SUPERUSER' }],
    ['issuer de outro serviço', { iss: 'outro-servico' }],
    ['audience de outro serviço', { aud: 'outra-api' }],
  ])('rejeita token bem assinado mas %s', async (_label, override) => {
    const token = await new SignJWT({ ...validPayload(), ...override })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .sign(key);

    await expectRejected(token, 'INVALID');
  });

  it.each(['', 'nao-e-um-jwt', 'a.b.c', 'a.b'])('rejeita lixo: "%s"', async (token) => {
    await expectRejected(token, 'INVALID');
  });
});

describe('refresh token opaco', () => {
  it('tem 256 bits aleatórios em base64url e nunca se repete', () => {
    const tokens = new Set(Array.from({ length: 1000 }, generateRefreshToken));

    expect(tokens.size).toBe(1000);
    for (const token of tokens) expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('o hash é SHA-256 em hex (64 caracteres) e não contém o token', () => {
    const token = generateRefreshToken();
    const hash = hashRefreshToken(token);

    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hash).toBe(hashRefreshToken(token));
    expect(hash).not.toContain(token);
  });
});
