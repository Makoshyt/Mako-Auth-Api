/**
 * Seed de DESENVOLVIMENTO com dados inteiramente fictícios (domínio reservado example.com).
 *
 * Proteções contra uso indevido:
 *  - recusa rodar com NODE_ENV=production;
 *  - recusa rodar contra um banco que não seja local (localhost/127.0.0.1/::1);
 *  - a senha não está no código: vem de SEED_USER_PASSWORD (só no .env local).
 * Assim, o admin fictício nunca é criado num ambiente real por acidente.
 *
 * Idempotente: pode ser executado várias vezes (upsert por email).
 *
 * O seed NÃO cria administradores: todos nascem USER. Para testar o papel ADMIN, promova a
 * conta fictícia com o comando explícito (Etapa 5):
 *   npm run admin:promote -- --email ada.admin@example.com --confirm ada.admin@example.com
 * Reexecutar o seed não mexe no papel de contas existentes, então a promoção não é desfeita.
 */
import { existsSync } from 'node:fs';
import { z } from 'zod';
import { createPrismaClient } from '../src/infra/prisma.js';
import { hashPassword } from '../src/shared/password-hasher.js';

if (existsSync('.env')) process.loadEnvFile('.env');

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

const seedEnv = z
  .object({
    NODE_ENV: z.string().default('development'),
    DATABASE_URL: z.url({ protocol: /^postgres(ql)?$/ }),
    SEED_USER_PASSWORD: z
      .string({ error: 'defina SEED_USER_PASSWORD no .env (veja .env.example)' })
      .min(12, 'SEED_USER_PASSWORD precisa de pelo menos 12 caracteres'),
  })
  .parse(process.env);

if (seedEnv.NODE_ENV === 'production') {
  throw new Error('Seed bloqueado: NODE_ENV=production. Ele cria contas de demonstração.');
}
const dbHost = new URL(seedEnv.DATABASE_URL).hostname;
if (!LOCAL_HOSTS.has(dbHost)) {
  throw new Error(`Seed bloqueado: banco "${dbHost}" não é local.`);
}

const users = [
  { email: 'ada.admin@example.com', name: 'Ada Admin (fictícia)' }, // candidata a promoção
  { email: 'bruno.user@example.com', name: 'Bruno Usuário (fictício)' },
  { email: 'carla.user@example.com', name: 'Carla Usuária (fictícia)' },
] as const;

const prisma = createPrismaClient(seedEnv.DATABASE_URL);

try {
  const passwordHash = await hashPassword(seedEnv.SEED_USER_PASSWORD);
  for (const user of users) {
    await prisma.user.upsert({
      where: { email: user.email },
      create: { ...user, role: 'USER', passwordHash },
      // Sem `role`: não rebaixa nem promove quem já existe.
      update: { name: user.name, passwordHash },
    });
  }
  // Somente emails e papéis: a senha nunca é impressa.
  const rows = await prisma.user.findMany({
    where: { email: { in: users.map((user) => user.email) } },
    select: { email: true, role: true },
    orderBy: { email: 'asc' },
  });
  console.table(rows);
  console.log(`Seed concluído: ${users.length} usuários fictícios.`);
  console.log(
    'Para testar o papel ADMIN: npm run admin:promote -- --email <email> --confirm <email>',
  );
} finally {
  await prisma.$disconnect();
}
