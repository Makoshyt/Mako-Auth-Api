import { describe, expect, it, vi } from 'vitest';
import {
  buildPrompt,
  createOllamaExplainer,
  disabledExplainer,
  type AlertEvidence,
} from '../../../src/modules/alerts/alert-explainer.js';

const evidence: AlertEvidence = {
  rule: 'BRUTE_FORCE_ACCOUNT',
  severity: 'MEDIUM',
  status: 'OPEN',
  summary: '8 ou mais falhas de login para a mesma conta em 1 h',
  threshold: 8,
  windowSeconds: 3600,
  peak: 9,
  eventCount: 9,
  durationSeconds: 540,
  subjectKind: 'account',
};

const valid = {
  summary: 'Várias tentativas de senha errada contra uma única conta.',
  likelyCauses: ['Ataque de força bruta', 'Usuário esqueceu a senha'],
  suggestedChecks: ['Verificar se houve login bem-sucedido depois das falhas'],
};

/** Ollama falso: devolve `body` como resposta de /api/generate. */
function ollama(body: unknown, init: { status?: number } = {}) {
  return vi.fn((_url: string | URL | Request, _options?: RequestInit) =>
    Promise.resolve(
      new Response(JSON.stringify(body), {
        status: init.status ?? 200,
        headers: { 'content-type': 'application/json' },
      }),
    ),
  );
}

const explainerWith = (fetchImpl: typeof fetch, timeoutMs = 2_000) =>
  createOllamaExplainer({
    baseUrl: 'http://127.0.0.1:11434',
    model: 'qwen2.5:7b',
    timeoutMs,
    fetch: fetchImpl,
  });

describe('IA desabilitada (padrão)', () => {
  it('não chama nada e responde "disabled"', async () => {
    await expect(disabledExplainer.explain(evidence)).resolves.toEqual({ status: 'disabled' });
  });
});

describe('Ollama local', () => {
  it('resposta válida: explicação validada, com o modelo usado', async () => {
    const fake = ollama({ response: JSON.stringify(valid) });

    await expect(explainerWith(fake).explain(evidence)).resolves.toEqual({
      status: 'ok',
      model: 'qwen2.5:7b',
      explanation: valid,
    });
  });

  it('chama só o endpoint local configurado, sem streaming e pedindo JSON', async () => {
    const fake = ollama({ response: JSON.stringify(valid) });

    await explainerWith(fake).explain(evidence);

    const [url, options] = fake.mock.calls[0] ?? [];
    expect(url).toBe('http://127.0.0.1:11434/api/generate');
    const body = JSON.parse(options?.body as string) as Record<string, unknown>;
    expect(body).toMatchObject({ model: 'qwen2.5:7b', stream: false, format: 'json' });
    expect(options?.signal).toBeInstanceOf(AbortSignal);
  });

  it('o prompt leva só as evidências minimizadas', () => {
    const prompt = buildPrompt(evidence);

    expect(prompt).toContain('"rule":"BRUTE_FORCE_ACCOUNT"');
    expect(prompt).not.toMatch(/@|\b\d{1,3}(\.\d{1,3}){3}\b|[0-9a-f]{8}-[0-9a-f]{4}-/i);
  });

  it('Ollama fora do ar: "unavailable" (UNREACHABLE), sem lançar', async () => {
    const down = vi.fn(() => Promise.reject(new TypeError('fetch failed')));

    await expect(explainerWith(down).explain(evidence)).resolves.toEqual({
      status: 'unavailable',
      reason: 'UNREACHABLE',
    });
  });

  it('HTTP de erro (ex.: modelo não baixado): UNREACHABLE', async () => {
    await expect(
      explainerWith(ollama({ error: 'model not found' }, { status: 404 })).explain(evidence),
    ).resolves.toEqual({ status: 'unavailable', reason: 'UNREACHABLE' });
  });

  it('timeout: aborta a chamada e responde TIMEOUT', async () => {
    // Nunca responde por conta própria: só termina quando o AbortSignal do timeout dispara.
    const hanging = vi.fn(
      (_url: string | URL | Request, options?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          options?.signal?.addEventListener('abort', () => {
            reject(options.signal?.reason as Error);
          });
        }),
    );

    const started = Date.now();
    const result = await explainerWith(hanging, 50).explain(evidence);

    expect(result).toEqual({ status: 'unavailable', reason: 'TIMEOUT' });
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it.each([
    ['envelope sem "response"', { message: 'oi' }],
    ['"response" que não é JSON', { response: 'Claro! Aqui está a explicação...' }],
    ['campos faltando', { response: JSON.stringify({ summary: 'só isso' }) }],
    ['resumo longo demais', { response: JSON.stringify({ ...valid, summary: 'x'.repeat(601) }) }],
    [
      'listas grandes demais',
      { response: JSON.stringify({ ...valid, likelyCauses: Array(6).fill('c') }) },
    ],
    ['tipos errados', { response: JSON.stringify({ ...valid, suggestedChecks: 'rodar comando' }) }],
    ['resumo vazio', { response: JSON.stringify({ ...valid, summary: '   ' }) }],
  ])('resposta inválida (%s): INVALID_RESPONSE', async (_label, body) => {
    await expect(explainerWith(ollama(body)).explain(evidence)).resolves.toEqual({
      status: 'unavailable',
      reason: 'INVALID_RESPONSE',
    });
  });

  it('remove caracteres de controle e espaços extras da saída (texto puro)', async () => {
    const dirty = { ...valid, summary: `Linha 1\u0000‮  com\n\n  sujeira\t` };

    const result = await explainerWith(ollama({ response: JSON.stringify(dirty) })).explain(
      evidence,
    );

    expect(result).toMatchObject({ status: 'ok', explanation: { summary: 'Linha 1 com sujeira' } });
  });
});
