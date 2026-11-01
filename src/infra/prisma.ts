import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '../generated/prisma/client.js';

export type { PrismaClient };

/**
 * Prisma 7 usa um driver adapter: as queries saem pelo driver `pg` (node-postgres),
 * sem engine binária de query. O adapter recebe a configuração do pool do `pg`.
 */
export function createPrismaClient(databaseUrl: string): PrismaClient {
  const adapter = new PrismaPg({
    connectionString: databaseUrl,
    max: 10,
    // Sem banco disponível, falha em 5 s em vez de pendurar requisições (e o /ready).
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 30_000,
  });
  return new PrismaClient({ adapter });
}
