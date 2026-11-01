import { isIP } from 'node:net';

/** Expande um IPv6 para 8 grupos de 4 dígitos hex (aceita "::" e sufixo IPv4 pontuado). */
function expandIPv6(address: string): string[] {
  let value = address;
  const dotted = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  if (dotted) {
    const [a, b, c, d] = dotted.slice(1).map(Number) as [number, number, number, number];
    value = `${value.slice(0, dotted.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head = '', tail] = value.split('::');
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const groups =
    tail === undefined
      ? left
      : [...left, ...Array<string>(8 - left.length - right.length).fill('0'), ...right];
  return groups.map((group) => parseInt(group, 16).toString(16).padStart(4, '0'));
}

/**
 * Identificador de rate limit para um IP:
 *  - IPv4 (inclusive na forma IPv6 mapeada "::ffff:1.2.3.4") → o próprio endereço;
 *  - IPv6 → o prefixo /64. Um único cliente costuma controlar o /64 inteiro (2^64 endereços);
 *    contar por endereço deixaria trocar de IP a cada tentativa.
 * Zona ("fe80::1%eth0") e maiúsculas são normalizadas, então grafias diferentes do mesmo
 * endereço caem no mesmo contador.
 */
export function rateLimitIpKey(rawIp: string): string {
  const ip = (rawIp.split('%')[0] ?? '').trim().toLowerCase();
  if (isIP(ip) === 4) return `v4:${ip}`;
  if (isIP(ip) !== 6) return `raw:${ip}`;

  const groups = expandIPv6(ip);
  const isMappedV4 = groups.slice(0, 5).every((g) => g === '0000') && groups[5] === 'ffff';
  if (isMappedV4) {
    const high = parseInt(groups[6] ?? '0', 16);
    const low = parseInt(groups[7] ?? '0', 16);
    return `v4:${[high >> 8, high & 255, low >> 8, low & 255].join('.')}`;
  }
  return `v6/64:${groups.slice(0, 4).join(':')}`;
}
