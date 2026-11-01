import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    env: { NODE_ENV: 'test' },
    // A primeira montagem do app carrega os módulos do Swagger a frio; no Windows (antivírus
    // escaneando node_modules) isso chegou a ~10 s. Montagens seguintes levam ~100 ms.
    hookTimeout: 30_000,
    projects: [
      {
        extends: true,
        test: { name: 'unit', include: ['tests/unit/**/*.test.ts'] },
      },
      {
        extends: true,
        test: {
          name: 'integration',
          include: ['tests/integration/**/*.test.ts'],
          // Aplica as migrations no banco de testes (authapi_test) antes da suíte.
          globalSetup: ['tests/integration/global-setup.ts'],
          // Os arquivos compartilham o mesmo banco: execução sequencial evita interferência.
          fileParallelism: false,
        },
      },
    ],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/server.ts', 'src/generated/**'],
      reporter: ['text', 'html'],
    },
  },
});
