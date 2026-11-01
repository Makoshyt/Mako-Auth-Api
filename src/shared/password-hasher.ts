import { argon2, randomBytes, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const argon2Async = promisify(argon2);

/**
 * Parâmetros mínimos recomendados pela OWASP para Argon2id:
 * 19 MiB de memória, 2 iterações, paralelismo 1.
 * https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
 */
export const ARGON2_PARAMS = { memoryKiB: 19_456, passes: 2, parallelism: 1 } as const;
const SALT_BYTES = 16;
const HASH_BYTES = 32;
const ARGON2_VERSION = 19; // 0x13, versão atual do algoritmo

interface ParsedHash {
  memoryKiB: number;
  passes: number;
  parallelism: number;
  salt: Buffer;
  hash: Buffer;
}

async function derive(
  password: string,
  salt: Buffer,
  params: { memoryKiB: number; passes: number; parallelism: number },
  tagLength: number,
): Promise<Buffer> {
  return argon2Async('argon2id', {
    // NFKC (recomendação do NIST): "é" digitado como 1 ou 2 code points gera o mesmo hash,
    // então a senha funciona igual em qualquer teclado ou sistema operacional.
    message: password.normalize('NFKC'),
    nonce: salt,
    memory: params.memoryKiB,
    passes: params.passes,
    parallelism: params.parallelism,
    tagLength,
  });
}

/**
 * Gera o hash no formato PHC, o mesmo de outras implementações de Argon2:
 * $argon2id$v=19$m=19456,t=2,p=1$<salt base64>$<hash base64>
 * O formato carrega os parâmetros, então hashes antigos continuam verificáveis
 * se os parâmetros forem endurecidos no futuro.
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(SALT_BYTES);
  const hash = await derive(password, salt, ARGON2_PARAMS, HASH_BYTES);
  const { memoryKiB, passes, parallelism } = ARGON2_PARAMS;
  return `$argon2id$v=${ARGON2_VERSION}$m=${memoryKiB},t=${passes},p=${parallelism}$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

const PHC_PATTERN =
  /^\$argon2id\$v=19\$m=(?<m>\d+),t=(?<t>\d+),p=(?<p>\d+)\$(?<salt>[\w+/-]+)\$(?<hash>[\w+/-]+)$/;

function parse(encoded: string): ParsedHash | null {
  const groups = PHC_PATTERN.exec(encoded)?.groups;
  if (!groups) return null;
  return {
    memoryKiB: Number(groups.m),
    passes: Number(groups.t),
    parallelism: Number(groups.p),
    // O decoder base64 do Node aceita as duas variantes (padrão e url-safe), sem padding,
    // então hashes PHC gerados por outras bibliotecas também são verificáveis.
    salt: Buffer.from(groups.salt ?? '', 'base64'),
    hash: Buffer.from(groups.hash ?? '', 'base64'),
  };
}

/** Compara em tempo constante. Hash malformado retorna false (nunca lança). */
export async function verifyPassword(encoded: string, password: string): Promise<boolean> {
  const parsed = parse(encoded);
  if (!parsed || parsed.hash.length === 0) return false;
  const candidate = await derive(password, parsed.salt, parsed, parsed.hash.length);
  return timingSafeEqual(candidate, parsed.hash);
}
