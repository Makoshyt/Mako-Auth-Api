import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { TEST_DATABASE_URL } from '../helpers/test-env.js';

/**
 * Aplica as migrations pendentes no banco de testes com `prisma migrate deploy`,
 * que nunca apaga dados nem recria o banco (ao contrário de `migrate reset`).
 */
export default function setup(): void {
  const prismaCli = createRequire(import.meta.url).resolve('prisma/build/index.js');
  try {
    execFileSync(process.execPath, [prismaCli, 'migrate', 'deploy'], {
      env: { ...process.env, DATABASE_URL: TEST_DATABASE_URL },
      stdio: 'pipe',
    });
  } catch (error) {
    const output = (error as { stdout?: Buffer; stderr?: Buffer }).stderr?.toString() ?? '';
    throw new Error(
      'Não foi possível migrar o banco de testes. A infraestrutura está de pé? ' +
        'Rode: npm run docker:up\n' +
        output,
      { cause: error },
    );
  }
}
