/**
 * Política de senhas baseada no NIST SP 800-63B:
 *  - mínimo de 12 e máximo de 128 caracteres (code points Unicode, então emoji e acentos contam 1);
 *  - qualquer caractere é aceito, inclusive espaços: passphrases são bem-vindas;
 *  - SEM regras de composição ("1 maiúscula, 1 símbolo..."), que geram senhas previsíveis;
 *  - rejeição de senhas comuns, padrões triviais e senhas derivadas dos dados do próprio usuário.
 *
 * A lista de senhas comuns é local e curada (ver COMMON_BASE_WORDS). Ela não substitui uma base
 * grande de senhas vazadas; essa limitação e a melhoria sugerida estão em docs/architecture.md.
 */

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

export type PasswordViolation =
  | 'TOO_SHORT'
  | 'TOO_LONG'
  | 'COMMON_PASSWORD'
  | 'REPETITIVE'
  | 'SEQUENTIAL'
  | 'CONTAINS_PERSONAL_DATA';

export const PASSWORD_VIOLATION_MESSAGES: Record<PasswordViolation, string> = {
  TOO_SHORT: `A senha precisa ter pelo menos ${PASSWORD_MIN_LENGTH} caracteres`,
  TOO_LONG: `A senha pode ter no máximo ${PASSWORD_MAX_LENGTH} caracteres`,
  COMMON_PASSWORD: 'Esta senha é muito comum. Prefira uma frase com várias palavras',
  REPETITIVE: 'A senha não pode ser um mesmo trecho repetido',
  SEQUENTIAL: 'A senha não pode ser uma sequência de teclado ou numérica',
  CONTAINS_PERSONAL_DATA: 'A senha não pode conter seu nome ou email',
};

/**
 * Palavras-base que aparecem com frequência em listas públicas de senhas vazadas.
 * Senhas formadas por uma delas mais dígitos/símbolos ("Password2024!", "senha@123456")
 * são rejeitadas, pois são as primeiras tentativas de qualquer ataque de dicionário.
 */
const COMMON_BASE_WORDS = new Set([
  'password',
  'passw0rd',
  'senha',
  'minhasenha',
  'mudar',
  'mudarsenha',
  'trocar',
  'secret',
  'qwerty',
  'asdf',
  'zxcv',
  'abc',
  'abcdef',
  'admin',
  'administrator',
  'administrador',
  'root',
  'user',
  'usuario',
  'login',
  'welcome',
  'bemvindo',
  'letmein',
  'iloveyou',
  'teamo',
  'monkey',
  'dragon',
  'master',
  'sunshine',
  'princess',
  'football',
  'baseball',
  'futebol',
  'flamengo',
  'corinthians',
  'palmeiras',
  'brasil',
  'brazil',
  'shadow',
  'superman',
  'batman',
  'starwars',
  'pokemon',
  'naruto',
  'whatever',
  'trustno',
  'freedom',
  'changeme',
  'default',
  'test',
  'teste',
  'testing',
  'guest',
  'internet',
  'computer',
  'jesus',
  'deus',
  'amor',
]);

/** Ciclos que "dão a volta": "...7890123..." e "...3210987...". */
const CYCLIC_SEQUENCES = [
  '0123456789',
  '9876543210',
  'abcdefghijklmnopqrstuvwxyz',
  'zyxwvutsrqponmlkjihgfedcba',
];

/** Sequências de teclado: a senha inteira ser um trecho contínuo delas é trivial. */
const KEYBOARD_SEQUENCES = [
  'qwertyuiopasdfghjklzxcvbnm',
  'qwertyuiop',
  'asdfghjkl',
  'zxcvbnm',
  '1qaz2wsx3edc4rfv5tgb',
  'qazwsxedcrfvtgbyhn',
];

export interface PasswordContext {
  email?: string;
  name?: string;
}

/**
 * Tamanho em code points, como recomenda o NIST: cada caractere Unicode conta 1
 * (um emoji composto pode contar mais, o que só favorece o usuário).
 */
export const codePointLength = (value: string): number => Array.from(value).length;

/** Verdadeiro se a senha é um único trecho curto repetido ("aaaa...", "abcabcabc..."). */
function isRepetitive(value: string): boolean {
  const chars = Array.from(value);
  for (let unit = 1; unit <= 4; unit++) {
    if (chars.length % unit !== 0) continue;
    const pattern = chars.slice(0, unit).join('');
    if (pattern.repeat(chars.length / unit) === value) return true;
  }
  return false;
}

function isSequential(lower: string): boolean {
  const inCycle = CYCLIC_SEQUENCES.some((cycle) =>
    // Repete o ciclo o suficiente para conter qualquer trecho do tamanho da senha.
    cycle.repeat(Math.ceil(lower.length / cycle.length) + 1).includes(lower),
  );
  return inCycle || KEYBOARD_SEQUENCES.some((sequence) => sequence.includes(lower));
}

/** Remove dígitos e símbolos das pontas: "P@ssword2024!" vira "p@ssword". */
function stripDecorations(lower: string): string {
  return lower.replace(/^[^\p{L}]+|[^\p{L}]+$/gu, '');
}

/** "senhasenhasenha" é repetição de "senha". */
function isRepetitionOf(value: string, word: string): boolean {
  return value.length % word.length === 0 && word.repeat(value.length / word.length) === value;
}

function isCommon(lower: string): boolean {
  const stripped = stripDecorations(lower);
  const variants = new Set([
    stripped,
    lower.replace(/[^\p{L}]/gu, ''), // só as letras: "p4ss-w0rd!" vira "psswrd"
    stripped.replace(/@/g, 'a').replace(/0/g, 'o').replace(/1/g, 'i').replace(/3/g, 'e'),
  ]);
  for (const variant of variants) {
    if (variant.length === 0) continue;
    for (const word of COMMON_BASE_WORDS) {
      if (isRepetitionOf(variant, word)) return true;
    }
  }
  return false;
}

function containsPersonalData(lower: string, context: PasswordContext): boolean {
  const fragments: string[] = [];
  if (context.email) {
    const [local = ''] = context.email.toLowerCase().split('@');
    fragments.push(context.email.toLowerCase(), local);
  }
  if (context.name) {
    fragments.push(...context.name.toLowerCase().split(/\s+/));
  }
  // Fragmentos curtos ("ana", "jo") gerariam falsos positivos em passphrases legítimas.
  return fragments.some((fragment) => fragment.length >= 4 && lower.includes(fragment));
}

/** Retorna a primeira violação encontrada, ou null se a senha atende à política. */
export function checkPasswordPolicy(
  password: string,
  context: PasswordContext = {},
): PasswordViolation | null {
  const length = codePointLength(password);
  if (length < PASSWORD_MIN_LENGTH) return 'TOO_SHORT';
  if (length > PASSWORD_MAX_LENGTH) return 'TOO_LONG';

  const lower = password.normalize('NFKC').toLowerCase();
  if (isRepetitive(lower)) return 'REPETITIVE';
  if (isSequential(lower)) return 'SEQUENTIAL';
  if (isCommon(lower)) return 'COMMON_PASSWORD';
  if (containsPersonalData(lower, context)) return 'CONTAINS_PERSONAL_DATA';
  return null;
}
