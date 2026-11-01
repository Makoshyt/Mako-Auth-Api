/**
 * Regras do comando local `npm run admin:promote`. Separado do CLI para ser testado sem
 * abrir processo. O comando existe SÓ para desenvolvimento: não há endpoint que promova
 * usuários, e em produção a atribuição de ADMIN deve passar por um processo controlado.
 */
import type { PrismaClient } from '../src/infra/prisma.js';

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
const ALLOWED_ENVS = new Set(['development', 'test']);

/**
 * Domínios reservados para exemplos e testes (RFC 2606 e RFC 6761). Nenhum email real termina
 * assim, então o comando não consegue promover a conta de uma pessoa de verdade.
 */
const FICTITIOUS_DOMAIN =
  /@(?:[a-z0-9-]+\.)*(?:example\.(?:com|org|net)|[a-z0-9-]+\.(?:test|example|invalid|localhost))$/;

export interface PromotionInput {
  nodeEnv: string | undefined;
  databaseUrl: string | undefined;
  email: string | undefined;
  /** Precisa repetir o email: confirmação explícita de qual conta será promovida. */
  confirm: string | undefined;
}

export type PromotionCheck =
  | { ok: true; email: string; database: { host: string; name: string } }
  | { ok: false; errors: string[] };

export function checkPromotion(input: PromotionInput): PromotionCheck {
  const nodeEnv = input.nodeEnv ?? 'development';
  // Produção é verificada primeiro e sozinha: nada mais é avaliado nem conectado.
  if (nodeEnv === 'production') {
    return {
      ok: false,
      errors: ['Bloqueado: NODE_ENV=production. Este comando é só para desenvolvimento.'],
    };
  }

  const errors: string[] = [];
  if (!ALLOWED_ENVS.has(nodeEnv)) {
    errors.push(`Bloqueado: NODE_ENV="${nodeEnv}". Permitidos: development ou test.`);
  }

  let database: { host: string; name: string } | null = null;
  try {
    const url = new URL(input.databaseUrl ?? '');
    if (!/^postgres(ql)?:$/.test(url.protocol)) throw new Error('protocolo');
    database = { host: url.hostname, name: url.pathname.replace(/^\//, '') };
    if (!LOCAL_HOSTS.has(database.host)) {
      errors.push(`Bloqueado: o banco "${database.host}" não é local.`);
    }
  } catch {
    errors.push('DATABASE_URL ausente ou inválida.');
  }

  const email = input.email?.trim().toLowerCase() ?? '';
  if (!email) {
    errors.push('Informe o email: --email <email>.');
  } else if (!FICTITIOUS_DOMAIN.test(email)) {
    errors.push(
      'Bloqueado: só emails de domínios fictícios reservados (example.com/.org/.net, .test, .example, .invalid, .localhost).',
    );
  }

  if (email && input.confirm?.trim().toLowerCase() !== email) {
    errors.push('Confirmação ausente ou diferente: repita o mesmo email em --confirm <email>.');
  }

  if (errors.length > 0 || !database) return { ok: false, errors };
  return { ok: true, email, database };
}

export type PromotionResult =
  | { status: 'PROMOTED'; userId: string }
  | { status: 'ALREADY_ADMIN'; userId: string }
  | { status: 'NOT_FOUND' };

/** Só altera o papel. Nenhuma senha é criada, lida ou impressa. */
export async function promoteToAdmin(
  prisma: PrismaClient,
  email: string,
): Promise<PromotionResult> {
  const user = await prisma.user.findUnique({ where: { email }, select: { id: true, role: true } });
  if (!user) return { status: 'NOT_FOUND' };
  if (user.role === 'ADMIN') return { status: 'ALREADY_ADMIN', userId: user.id };

  await prisma.user.update({ where: { id: user.id }, data: { role: 'ADMIN' } });
  return { status: 'PROMOTED', userId: user.id };
}
