import { describe, expect, it, vi } from 'vitest';
import { createBackgroundTasks } from '../../../src/shared/background-tasks.js';

describe('BackgroundTasks', () => {
  it('a tarefa só começa depois do ciclo atual (a resposta sai antes)', async () => {
    const tasks = createBackgroundTasks(() => undefined);
    const order: string[] = [];

    tasks.run('t', async () => {
      order.push('tarefa');
    });
    order.push('resposta');
    await Promise.resolve();
    expect(order).toEqual(['resposta']);

    await tasks.idle();
    expect(order).toEqual(['resposta', 'tarefa']);
  });

  it('idle espera todas, inclusive as disparadas por outras tarefas', async () => {
    const tasks = createBackgroundTasks(() => undefined);
    let done = 0;

    tasks.run('pai', async () => {
      tasks.run('filha', async () => {
        await new Promise((resolve) => setTimeout(resolve, 10));
        done++;
      });
      done++;
    });

    await tasks.idle();
    expect(done).toBe(2);
  });

  it('erro numa tarefa vai para onError e não rejeita idle', async () => {
    const onError = vi.fn();
    const tasks = createBackgroundTasks(onError);
    const failure = new Error('smtp fora do ar');

    tasks.run('email', () => Promise.reject(failure));

    await expect(tasks.idle()).resolves.toBeUndefined();
    expect(onError).toHaveBeenCalledWith('email', failure);
  });
});
