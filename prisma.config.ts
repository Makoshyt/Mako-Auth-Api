import { existsSync } from 'node:fs';
import { defineConfig, env } from 'prisma/config';

// O Prisma 7 não carrega .env sozinho. Variáveis já definidas no ambiente (CI) têm precedência.
if (existsSync('.env')) process.loadEnvFile('.env');

export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: {
    path: 'prisma/migrations',
    seed: 'tsx prisma/seed.ts',
  },
  datasource: {
    url: env('DATABASE_URL'),
  },
});
