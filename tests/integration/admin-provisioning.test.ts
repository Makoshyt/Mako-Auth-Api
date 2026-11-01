import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createPrismaClient, type PrismaClient } from '../../src/infra/prisma.js';
import { hashPassword } from '../../src/shared/password-hasher.js';
import { TEST_DATABASE_URL } from '../helpers/test-env.js';

/** Domínio reservado (.example.com): o único tipo de email que o comando aceita. */
const DOMAIN = '@provision-test.example.com';
const TARGET = `alvo${DOMAIN}`;
const tsxCli = createRequire(import.meta.url).resolve('tsx/cli');

let prisma: PrismaClient;

/** Executa o CLI real como processo, com ambiente controlado (o .env não sobrescreve). */
function promote(args: string[], env: Record<string, string> = {}) {
  const result = spawnSync(process.execPath, [tsxCli, 'scripts/promote-admin.ts', ...args], {
    env: { ...process.env, NODE_ENV: 'test', DATABASE_URL: TEST_DATABASE_URL, ...env },
    encoding: 'utf8',
    timeout: 60_000,
  });
  return { status: result.status, output: `${result.stdout}${result.stderr}` };
}

const roleOf = async (email: string) =>
  (await prisma.user.findUniqueOrThrow({ where: { email } })).role;

beforeAll(() => {
  prisma = createPrismaClient(TEST_DATABASE_URL);
});

beforeEach(async () => {
  await prisma.user.deleteMany({ where: { email: { endsWith: DOMAIN } } });
  await prisma.user.create({
    data: {
      email: TARGET,
      name: 'Alvo Fictício',
      passwordHash: await hashPassword('irrelevante 123 abc'),
    },
  });
});

afterAll(async () => {
  await prisma.user.deleteMany({ where: { email: { endsWith: DOMAIN } } });
  await prisma.$disconnect();
});

describe('npm run admin:promote', () => {
  it('NODE_ENV=production: recusa (exit 1) e não toca no banco', () => {
    const result = promote(['--email', TARGET, '--confirm', TARGET], { NODE_ENV: 'production' });

    expect(result.status).toBe(1);
    expect(result.output).toContain('NODE_ENV=production');
    return expect(roleOf(TARGET)).resolves.toBe('USER');
  });

  it('sem confirmação explícita: recusa', async () => {
    const result = promote(['--email', TARGET]);

    expect(result.status).toBe(1);
    expect(result.output).toContain('Confirmação');
    expect(await roleOf(TARGET)).toBe('USER');
  });

  it('banco não local: recusa antes de conectar', () => {
    const result = promote(['--email', TARGET, '--confirm', TARGET], {
      DATABASE_URL: 'postgresql://u:p@db.producao.example.net:5432/authapi',
    });

    expect(result.status).toBe(1);
    expect(result.output).toContain('não é local');
  });

  it('email real (fora dos domínios reservados): recusa', () => {
    const result = promote(['--email', 'pessoa@gmail.com', '--confirm', 'pessoa@gmail.com']);

    expect(result.status).toBe(1);
    expect(result.output).toContain('domínios fictícios');
  });

  it('com todas as travas satisfeitas: promove; repetir é idempotente', async () => {
    const first = promote(['--email', TARGET, '--confirm', TARGET]);

    expect(first.status).toBe(0);
    expect(first.output).toContain('agora é ADMIN');
    expect(first.output).toContain('authapi_test em 127.0.0.1');
    expect(await roleOf(TARGET)).toBe('ADMIN');

    const second = promote(['--email', TARGET, '--confirm', TARGET]);
    expect(second.status).toBe(0);
    expect(second.output).toContain('já é ADMIN');
  });

  it('usuário inexistente: exit 2, nada é criado', async () => {
    const ghost = `fantasma${DOMAIN}`;

    const result = promote(['--email', ghost, '--confirm', ghost]);

    expect(result.status).toBe(2);
    expect(await prisma.user.count({ where: { email: ghost } })).toBe(0);
  });

  it('argumento desconhecido (ex.: --role) é rejeitado pelo parser', () => {
    const result = promote(['--email', TARGET, '--confirm', TARGET, '--role', 'ADMIN']);

    expect(result.status).not.toBe(0);
  });
});
