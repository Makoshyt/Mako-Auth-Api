import { Writable } from 'node:stream';
import { pino } from 'pino';
import { describe, expect, it } from 'vitest';
import { REDACTED_PATHS } from '../../src/infra/logger.js';

function captureLogger() {
  const lines: string[] = [];
  const stream = new Writable({
    write(chunk: Buffer, _encoding, callback) {
      lines.push(chunk.toString());
      callback();
    },
  });
  const logger = pino({ redact: { paths: REDACTED_PATHS, censor: '[REDACTED]' } }, stream);
  return { logger, output: () => lines.join('') };
}

describe('redação de dados sensíveis no logger', () => {
  it('remove Authorization e cookies dos headers da requisição', () => {
    const { logger, output } = captureLogger();

    logger.info({
      req: { headers: { authorization: 'Bearer token-ficticio-abc', cookie: 'sid=ficticio' } },
    });

    expect(output()).not.toContain('token-ficticio-abc');
    expect(output()).not.toContain('sid=ficticio');
    expect(output()).toContain('[REDACTED]');
  });

  it('remove senhas e tokens de objetos registrados', () => {
    const { logger, output } = captureLogger();

    logger.info({
      body: { email: 'ana@example.com', password: 'SenhaFicticia#2026' },
      result: { refreshToken: 'rt-ficticio', accessToken: 'at-ficticio' },
      reset: { token: 'reset-ficticio' },
    });

    const text = output();
    for (const secret of ['SenhaFicticia#2026', 'rt-ficticio', 'at-ficticio', 'reset-ficticio']) {
      expect(text).not.toContain(secret);
    }
    expect(text).toContain('ana@example.com');
  });
});
