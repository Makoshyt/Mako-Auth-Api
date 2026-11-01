import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { FastifyBaseLogger } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import {
  createDevMailboxMailer,
  createLogMailer,
  passwordResetLink,
  renderEmail,
  type PasswordResetEmail,
} from '../../../src/modules/mail/mailer.js';

const TOKEN = 'tokenFicticioDeTeste_0123456789abcdefABCDEF';
const email: PasswordResetEmail = {
  type: 'PASSWORD_RESET',
  to: 'ana.souza@example.com',
  token: TOKEN,
  expiresAt: new Date(Date.now() + 15 * 60_000),
};
const options = {
  from: 'AuthAPI <no-reply@example.com>',
  passwordResetUrl: 'https://app.example.com/reset',
};

/** Logger falso que guarda tudo o que receberia. */
function captureLogger() {
  const entries: unknown[] = [];
  const logger = {
    info: (...args: unknown[]) => entries.push(args),
  } as unknown as FastifyBaseLogger;
  return { logger, entries };
}

describe('link e renderização', () => {
  it('o token vai no fragmento (#), que não chega a servidores nem ao Referer', () => {
    const link = new URL(passwordResetLink('https://app.example.com/reset?lang=pt', TOKEN));

    expect(link.hash).toBe(`#token=${TOKEN}`);
    expect(link.search).toBe('?lang=pt');
    expect(link.pathname).toBe('/reset');
  });

  it('a mensagem traz o link, a validade e o aviso para quem não pediu', () => {
    const rendered = renderEmail(email, options);

    expect(rendered).toMatchObject({ from: options.from, to: email.to });
    expect(rendered.text).toContain(`https://app.example.com/reset#token=${TOKEN}`);
    expect(rendered.text).toContain('15 minutos');
    expect(rendered.text).toContain('Se não foi você');
  });
});

describe('provedor log (padrão)', () => {
  it('registra só tipo e validade: nunca o token nem o destinatário', async () => {
    const { logger, entries } = captureLogger();

    await createLogMailer(logger).send(email);

    const logged = JSON.stringify(entries);
    expect(logged).toContain('PASSWORD_RESET');
    expect(logged).not.toContain(TOKEN);
    expect(logged).not.toContain('ana.souza');
  });
});

describe('provedor dev-mailbox (só desenvolvimento)', () => {
  let dir = '';
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  it('grava a mensagem completa num arquivo local; o log leva só o nome do arquivo', async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'authapi-mailbox-'));
    const { logger, entries } = captureLogger();

    await createDevMailboxMailer(dir, options, logger).send(email);

    const files = await readdir(dir);
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/password_reset-[0-9a-f-]{36}\.txt$/);
    const content = await readFile(path.join(dir, files[0] ?? ''), 'utf8');
    expect(content).toContain(`#token=${TOKEN}`);
    expect(content).toContain('To: ana.souza@example.com');
    const logged = JSON.stringify(entries);
    expect(logged).not.toContain(TOKEN);
    expect(logged).not.toContain('ana.souza');
  });
});
