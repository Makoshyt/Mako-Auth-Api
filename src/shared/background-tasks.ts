/**
 * Trabalho disparado DEPOIS da resposta HTTP (ex.: gerar o token e enviar o email de
 * recuperação). A resposta não espera, então o tempo dela não depende do que a tarefa faz.
 *
 * As tarefas ficam registradas: `idle()` espera todas terminarem (encerramento gracioso do
 * servidor e testes). Erros nunca vazam para o cliente; vão para `onError` (log).
 */
export interface BackgroundTasks {
  run(name: string, task: () => Promise<void>): void;
  idle(): Promise<void>;
}

export function createBackgroundTasks(
  onError: (name: string, error: unknown) => void,
): BackgroundTasks {
  const pending = new Set<Promise<void>>();

  return {
    run(name, task) {
      // setImmediate: a tarefa só começa depois que o ciclo atual (a resposta) terminar.
      const promise: Promise<void> = new Promise<void>((resolve) => setImmediate(resolve))
        .then(task)
        .catch((error: unknown) => {
          onError(name, error);
        })
        .finally(() => pending.delete(promise));
      pending.add(promise);
    },

    async idle() {
      while (pending.size > 0) await Promise.allSettled([...pending]);
    },
  };
}
