/**
 * Travas do comando `npm run audit:retention`. Separadas do CLI para serem testadas sem
 * processo. O padrão é SIMULAÇÃO (só conta); apagar exige configuração e flags explícitas.
 */
export interface RetentionRunInput {
  nodeEnv: string | undefined;
  databaseUrl: string | undefined;
  enabled: boolean;
  execute: boolean;
  /** Para executar, precisa repetir o NOME do banco de destino. */
  confirm: string | undefined;
}

export type RetentionRunCheck =
  | { ok: true; mode: 'dry-run' | 'execute'; database: { host: string; name: string } }
  | { ok: false; errors: string[] };

export function checkRetentionRun(input: RetentionRunInput): RetentionRunCheck {
  let database: { host: string; name: string };
  try {
    const url = new URL(input.databaseUrl ?? '');
    if (!/^postgres(ql)?:$/.test(url.protocol)) throw new Error('protocolo');
    database = { host: url.hostname, name: url.pathname.replace(/^\//, '') };
  } catch {
    return { ok: false, errors: ['DATABASE_URL ausente ou inválida.'] };
  }

  // Simulação é somente leitura: sempre permitida.
  if (!input.execute) return { ok: true, mode: 'dry-run', database };

  const errors: string[] = [];
  if (!input.enabled) {
    errors.push('Exclusão desligada: defina AUDIT_RETENTION_ENABLED=true para executar.');
  }
  if (input.confirm !== database.name) {
    errors.push(`Confirmação ausente ou diferente: use --confirm ${database.name}.`);
  }
  // Fora de produção, só bancos de teste: os dados de desenvolvimento são preservados.
  if ((input.nodeEnv ?? 'development') !== 'production' && !database.name.endsWith('_test')) {
    errors.push(
      `Bloqueado: fora de produção, a exclusão só roda em bancos *_test (destino: "${database.name}").`,
    );
  }
  return errors.length > 0 ? { ok: false, errors } : { ok: true, mode: 'execute', database };
}
