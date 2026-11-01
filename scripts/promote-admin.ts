/**
 * Atribui o papel ADMIN a um usuário FICTÍCIO do banco local de desenvolvimento.
 *
 *   npm run admin:promote -- --email ada.admin@example.com --confirm ada.admin@example.com
 *
 * Travas (ver admin-provisioning.ts): recusa NODE_ENV=production, bancos não locais e emails
 * fora dos domínios reservados para exemplos; exige repetir o email em --confirm.
 * Nunca é executado pelo seed. Não cria nem lê senhas.
 *
 * Códigos de saída: 0 = promovido ou já era ADMIN · 1 = bloqueado/inválido · 2 = não encontrado.
 */
import { existsSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { createPrismaClient } from '../src/infra/prisma.js';
import { checkPromotion, promoteToAdmin } from './admin-provisioning.js';

// Variáveis já definidas no ambiente têm precedência sobre o .env.
if (existsSync('.env')) process.loadEnvFile('.env');

const { values } = parseArgs({
  options: { email: { type: 'string' }, confirm: { type: 'string' } },
  strict: true,
});

const check = checkPromotion({
  nodeEnv: process.env.NODE_ENV,
  databaseUrl: process.env.DATABASE_URL,
  email: values.email,
  confirm: values.confirm,
});

if (!check.ok) {
  for (const error of check.errors) console.error(`✖ ${error}`);
  process.exit(1);
}

console.log(`Banco: ${check.database.name} em ${check.database.host}`);
const prisma = createPrismaClient(process.env.DATABASE_URL ?? '');
try {
  const result = await promoteToAdmin(prisma, check.email);
  if (result.status === 'NOT_FOUND') {
    console.error(`✖ Nenhum usuário com o email ${check.email}. Cadastre-o antes.`);
    process.exitCode = 2;
  } else if (result.status === 'ALREADY_ADMIN') {
    console.log(`= ${check.email} já é ADMIN (id ${result.userId}). Nada foi alterado.`);
  } else {
    console.log(`✔ ${check.email} agora é ADMIN (id ${result.userId}).`);
    console.log('  O papel vale na próxima requisição: não é preciso novo login.');
  }
} finally {
  await prisma.$disconnect();
}
