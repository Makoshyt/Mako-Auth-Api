import type { FastifyRequest, FastifyServerOptions } from 'fastify';
import type { DestinationStream } from 'pino';
import type { Env } from '../config/env.js';

/**
 * Caminhos removidos de qualquer log, mesmo que algum código registre o objeto inteiro.
 * O serializer padrão do Fastify não registra headers nem body; a redação é a segunda barreira.
 */
export const REDACTED_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'res.headers["set-cookie"]',
  'headers.authorization',
  'headers.cookie',
  '*.password',
  '*.newPassword',
  '*.currentPassword',
  '*.token',
  '*.accessToken',
  '*.refreshToken',
  '*.resetToken',
  '*.secret',
];

/**
 * Mesmos campos do serializer padrão do Fastify, mas com a URL SEM a query string: filtros
 * administrativos (?email=ana@...) carregam dados pessoais que não devem ir para o log.
 * O caminho continua registrado (ex.: /api/v1/admin/users/<uuid>).
 */
export const serializers = {
  req: (request: FastifyRequest) => ({
    method: request.method,
    url: request.url.split('?', 1)[0],
    host: request.host,
    remoteAddress: request.ip,
    remotePort: request.socket.remotePort,
  }),
};

/**
 * `destination` permite capturar os logs (testes de vazamento de segredos). Quando informado,
 * os logs saem em JSON para ele, com a mesma redação de produção, inclusive em NODE_ENV=test.
 */
export function buildLoggerOptions(
  env: Env,
  destination?: DestinationStream,
): FastifyServerOptions['logger'] {
  if (destination) {
    return {
      level: env.LOG_LEVEL,
      redact: { paths: REDACTED_PATHS, censor: '[REDACTED]' },
      serializers,
      stream: destination,
    };
  }
  if (env.NODE_ENV === 'test') return false;

  return {
    level: env.LOG_LEVEL,
    redact: { paths: REDACTED_PATHS, censor: '[REDACTED]' },
    serializers,
    ...(env.NODE_ENV === 'development' && {
      transport: {
        target: 'pino-pretty',
        options: { translateTime: 'HH:MM:ss', ignore: 'pid,hostname' },
      },
    }),
  };
}
