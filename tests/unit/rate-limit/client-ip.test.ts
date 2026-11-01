import { describe, expect, it } from 'vitest';
import { rateLimitIpKey } from '../../../src/modules/rate-limit/client-ip.js';

describe('rateLimitIpKey (normalização do IP)', () => {
  it('IPv4 é usado como está', () => {
    expect(rateLimitIpKey('203.0.113.7')).toBe('v4:203.0.113.7');
  });

  it.each([
    '::ffff:203.0.113.7',
    '::FFFF:203.0.113.7',
    '::ffff:cb00:7107',
    '0:0:0:0:0:ffff:cb00:7107',
  ])('IPv4 mapeado em IPv6 (%s) cai no mesmo contador do IPv4', (ip) => {
    expect(rateLimitIpKey(ip)).toBe('v4:203.0.113.7');
  });

  it('IPv6 é agrupado por /64: trocar o fim do endereço não troca de contador', () => {
    const a = rateLimitIpKey('2001:db8:abcd:12::1');
    const b = rateLimitIpKey('2001:db8:abcd:12:ffff:ffff:ffff:fffe');
    const c = rateLimitIpKey('2001:0DB8:ABCD:0012:0000:0000:0000:0042');

    expect(a).toBe('v6/64:2001:0db8:abcd:0012');
    expect(b).toBe(a);
    expect(c).toBe(a);
  });

  it('outro /64 é outro contador', () => {
    expect(rateLimitIpKey('2001:db8:abcd:13::1')).not.toBe(rateLimitIpKey('2001:db8:abcd:12::1'));
  });

  it('remove o identificador de zona e trata "::"', () => {
    expect(rateLimitIpKey('fe80::1%eth0')).toBe(rateLimitIpKey('FE80::2'));
    expect(rateLimitIpKey('::1')).toBe('v6/64:0000:0000:0000:0000');
  });
});
