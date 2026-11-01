import { mkdir, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import type { FastifyBaseLogger } from 'fastify';
import type { Env } from '../../config/env.js';

/**
 * Mensagens que a aplicação sabe enviar. Tipadas (e não texto livre) para que os provedores
 * saibam o que é sensível: o token só existe aqui e no texto renderizado.
 */
export interface PasswordResetEmail {
  type: 'PASSWORD_RESET';
  to: string;
  token: string;
  expiresAt: Date;
}

export type OutgoingEmail = PasswordResetEmail;

/**
 * Porta de saída para email. A autenticação depende só desta interface; trocar o provedor
 * (SMTP, SES, Resend...) é implementar `send` e registrá-lo em `createMailer`.
 */
export interface Mailer {
  readonly name: string;
  send(email: OutgoingEmail): Promise<void>;
}

export interface RenderedEmail {
  from: string;
  to: string;
  subject: string;
  text: string;
}

export interface RenderOptions {
  from: string;
  passwordResetUrl: string;
}

/**
 * O token vai no FRAGMENTO da URL (#token=...): o navegador não envia o fragmento ao servidor
 * do front-end, a proxies, a ferramentas de analytics nem no cabeçalho Referer.
 */
export function passwordResetLink(baseUrl: string, token: string): string {
  const url = new URL(baseUrl);
  url.hash = `token=${encodeURIComponent(token)}`;
  return url.toString();
}

export function renderEmail(email: OutgoingEmail, options: RenderOptions): RenderedEmail {
  const minutes = Math.max(1, Math.round((email.expiresAt.getTime() - Date.now()) / 60_000));
  return {
    from: options.from,
    to: email.to,
    subject: 'Redefinição de senha — AuthAPI Pro',
    text: [
      'Recebemos um pedido para redefinir a senha da sua conta.',
      '',
      `Use o link abaixo em até ${minutes} minutos. Ele só funciona uma vez:`,
      passwordResetLink(options.passwordResetUrl, email.token),
      '',
      'Se não foi você, ignore esta mensagem: sua senha continua a mesma.',
    ].join('\n'),
  };
}

/**
 * Padrão (inclusive em produção, até existir um provedor real): registra só o tipo e a
 * validade. Nunca o token, nunca o destinatário. Nada é entregue.
 */
export function createLogMailer(log: FastifyBaseLogger): Mailer {
  return {
    name: 'log',
    async send(email) {
      log.info(
        { emailType: email.type, expiresAt: email.expiresAt.toISOString() },
        'email não entregue (MAIL_PROVIDER=log): configure um provedor real para enviar',
      );
    },
  };
}

/**
 * SOMENTE DESENVOLVIMENTO (recusado em produção pela validação do env). Grava a mensagem
 * completa, com o link, em DEV_MAILBOX_DIR (no .gitignore). O log registra só o nome do
 * arquivo, que não contém dados sensíveis.
 */
export function createDevMailboxMailer(
  directory: string,
  options: RenderOptions,
  log: FastifyBaseLogger,
): Mailer {
  return {
    name: 'dev-mailbox',
    async send(email) {
      const rendered = renderEmail(email, options);
      await mkdir(directory, { recursive: true });
      const file = `${new Date().toISOString().replace(/[:.]/g, '-')}-${email.type.toLowerCase()}-${randomUUID()}.txt`;
      const content = [
        `From: ${rendered.from}`,
        `To: ${rendered.to}`,
        `Subject: ${rendered.subject}`,
        '',
        rendered.text,
        '',
      ].join('\n');
      await writeFile(path.join(directory, file), content, { encoding: 'utf8', mode: 0o600 });
      log.info({ emailType: email.type, file }, 'email gravado na caixa local de desenvolvimento');
    },
  };
}

export function createMailer(env: Env, log: FastifyBaseLogger): Mailer {
  const options = { from: env.MAIL_FROM, passwordResetUrl: env.PASSWORD_RESET_URL };
  return env.MAIL_PROVIDER === 'dev-mailbox'
    ? createDevMailboxMailer(env.DEV_MAILBOX_DIR, options, log)
    : createLogMailer(log);
}
