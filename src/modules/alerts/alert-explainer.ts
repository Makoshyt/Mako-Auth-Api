import { z } from 'zod';
import type { AlertRule, AlertSeverity, AlertStatus } from '../../generated/prisma/enums.js';

/**
 * O que a IA recebe: só a natureza e a intensidade do incidente. Nada de IP, email, hash, id
 * de usuário, ids de eventos ou datas absolutas. A detecção NÃO depende disto.
 */
export interface AlertEvidence {
  rule: AlertRule;
  severity: AlertSeverity;
  status: AlertStatus;
  summary: string;
  threshold: number;
  windowSeconds: number;
  peak: number;
  eventCount: number;
  /** Duração do incidente (último - primeiro evento), em segundos. */
  durationSeconds: number;
  subjectKind: 'ip' | 'user' | 'account';
}

export interface AlertExplanation {
  summary: string;
  likelyCauses: string[];
  suggestedChecks: string[];
}

export type ExplainResult =
  | { status: 'ok'; model: string; explanation: AlertExplanation }
  | { status: 'disabled' }
  | { status: 'unavailable'; reason: 'TIMEOUT' | 'UNREACHABLE' | 'INVALID_RESPONSE' };

/** Porta de saída: trocar o provedor local é implementar `explain`. */
export interface AlertExplainer {
  explain(evidence: AlertEvidence): Promise<ExplainResult>;
}

export const disabledExplainer: AlertExplainer = {
  explain: () => Promise.resolve({ status: 'disabled' }),
};

/** Remove caracteres de controle e espaços repetidos; a saída é texto puro, nunca HTML/comando. */
const cleanText = (max: number) =>
  z
    .string()
    .transform((value) =>
      value
        .replace(/[\p{Cc}\p{Cf}]/gu, ' ')
        .replace(/\s+/g, ' ')
        .trim(),
    )
    .pipe(z.string().min(1).max(max));

/** Limites rígidos: uma resposta fora disto é descartada como INVALID_RESPONSE. */
export const explanationSchema = z.object({
  summary: cleanText(600),
  likelyCauses: z.array(cleanText(240)).max(5),
  suggestedChecks: z.array(cleanText(240)).max(5),
});

const ollamaResponseSchema = z.object({ response: z.string().max(20_000) });

export function buildPrompt(evidence: AlertEvidence): string {
  return [
    'Você é um assistente que EXPLICA alertas de segurança de uma API de autenticação para um',
    'administrador. Você não toma decisões nem executa ações; apenas explica.',
    'Responda SOMENTE com um objeto JSON, em português, no formato:',
    '{"summary": "...", "likelyCauses": ["..."], "suggestedChecks": ["..."]}',
    'Use no máximo 3 itens por lista e frases curtas. Não invente dados que não estão abaixo.',
    '',
    'Evidências (minimizadas, sem dados pessoais):',
    JSON.stringify(evidence),
  ].join('\n');
}

export interface OllamaExplainerOptions {
  baseUrl: string;
  model: string;
  timeoutMs: number;
  /** Injetável para testes. */
  fetch?: typeof fetch;
}

/**
 * Explicação via Ollama local (/api/generate, sem streaming, saída JSON). Qualquer falha
 * (fora do ar, timeout, HTTP de erro, JSON inválido, schema violado) vira `unavailable`:
 * o alerta continua acessível normalmente, só sem a explicação.
 */
export function createOllamaExplainer({
  baseUrl,
  model,
  timeoutMs,
  fetch: fetchImpl = fetch,
}: OllamaExplainerOptions): AlertExplainer {
  const endpoint = new URL('/api/generate', baseUrl).toString();

  return {
    async explain(evidence) {
      let raw: unknown;
      try {
        const response = await fetchImpl(endpoint, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            model,
            prompt: buildPrompt(evidence),
            stream: false,
            format: 'json',
            options: { temperature: 0.2, num_predict: 400 },
          }),
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!response.ok) return { status: 'unavailable', reason: 'UNREACHABLE' };
        raw = await response.json();
      } catch (error) {
        const timedOut = error instanceof Error && error.name === 'TimeoutError';
        return { status: 'unavailable', reason: timedOut ? 'TIMEOUT' : 'UNREACHABLE' };
      }

      const envelope = ollamaResponseSchema.safeParse(raw);
      if (!envelope.success) return { status: 'unavailable', reason: 'INVALID_RESPONSE' };
      let parsed: unknown;
      try {
        parsed = JSON.parse(envelope.data.response);
      } catch {
        return { status: 'unavailable', reason: 'INVALID_RESPONSE' };
      }
      const explanation = explanationSchema.safeParse(parsed);
      if (!explanation.success) return { status: 'unavailable', reason: 'INVALID_RESPONSE' };
      return { status: 'ok', model, explanation: explanation.data };
    },
  };
}
