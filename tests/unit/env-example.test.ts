import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { envSchema } from '../../src/config/env.js';
import { alertRetentionConfigSchema } from '../../src/modules/alerts/alert-retention.js';
import { retentionConfigSchema } from '../../src/modules/audit/audit-retention.js';

/** Variáveis declaradas no .env.example (linhas NOME=valor). */
const exampleKeys = new Set(
  readFileSync('.env.example', 'utf8')
    .split(/\r?\n/)
    .filter((line) => /^[A-Z][A-Z0-9_]*=/.test(line))
    .map((line) => line.slice(0, line.indexOf('='))),
);

describe('.env.example (experiência de quem clona o projeto)', () => {
  it('documenta toda variável que a aplicação e as rotinas leem', () => {
    const schemaKeys = [
      ...Object.keys(envSchema.in.shape),
      ...Object.keys(retentionConfigSchema.shape),
      ...Object.keys(alertRetentionConfigSchema.shape),
    ];

    expect(schemaKeys.filter((key) => !exampleKeys.has(key))).toEqual([]);
  });

  it('não traz segredos preenchidos: JWT e HMAC ficam vazios para cada um gerar os seus', () => {
    const example = readFileSync('.env.example', 'utf8');

    expect(example).toMatch(/^JWT_ACCESS_SECRET=$/m);
    expect(example).toMatch(/^RATE_LIMIT_HMAC_SECRET=$/m);
  });
});
