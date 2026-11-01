import type { Mailer, OutgoingEmail } from './mailer.js';

/**
 * Provedor de TESTES: guarda as mensagens em memória para os testes lerem o token, como um
 * usuário leria o email. Não é selecionável por variável de ambiente; só por injeção em
 * `buildApp({ mailer })`.
 */
export class MemoryMailer implements Mailer {
  readonly name = 'memory';
  readonly sent: OutgoingEmail[] = [];
  /** Se definido, `send` espera esta promessa (simula provedor lento) ou falha com ela. */
  gate: Promise<void> | null = null;

  async send(email: OutgoingEmail): Promise<void> {
    if (this.gate) await this.gate;
    this.sent.push(email);
  }

  /** Mensagens enviadas para um destinatário. */
  to(address: string): OutgoingEmail[] {
    return this.sent.filter((email) => email.to === address);
  }

  /** Token da última mensagem de recuperação enviada para o endereço. */
  lastResetToken(address: string): string | undefined {
    return this.to(address).at(-1)?.token;
  }
}
