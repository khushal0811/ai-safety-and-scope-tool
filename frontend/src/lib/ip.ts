/**
 * IPv4 normalization utilities.
 *
 * Implements inet_aton-compatible parsing so obfuscated notations used to
 * evade naive regex scope checks are resolved BEFORE CIDR comparison:
 *   - hex parts      0x7f.0.0.1      -> 127.0.0.1
 *   - octal parts    0177.0.0.1      -> 127.0.0.1
 *   - short forms    127.1           -> 127.0.0.1
 *   - integer        2130706433      -> 127.0.0.1
 *   - IPv6-mapped    ::ffff:127.0.0.1 / ::ffff:7f00:1
 */

const MAX_U32 = 0xffffffff;

export interface ParsedIPv4 {
  value: number;
  normalized: string;
  /** true when the input was not already canonical dotted-quad notation. */
  obfuscated: boolean;
}

export interface ParsedCidr {
  network: number;
  prefix: number;
  normalized: string;
}

export function intToIPv4(n: number): string {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function parsePart(p: string): number | null {
  if (/^0x[0-9a-f]+$/i.test(p)) return parseInt(p, 16);
  if (/^0[0-7]+$/.test(p)) return parseInt(p, 8);
  if (/^(0|[1-9]\d*)$/.test(p)) return parseInt(p, 10);
  return null;
}

export function parseIPv4(raw: string): ParsedIPv4 | null {
  let s = raw.trim().replace(/^\[/, '').replace(/\]$/, '');
  let viaMapped = false;

  const mapped = /^(?:::|(?:0{1,4}:){5})ffff:(.+)$/i.exec(s);
  if (mapped) {
    viaMapped = true;
    s = mapped[1] ?? s;
    const hex = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(s);
    const high = hex?.[1];
    const low = hex?.[2];
    if (high && low) {
      const value = parseInt(high, 16) * 0x10000 + parseInt(low, 16);
      return { value, normalized: intToIPv4(value), obfuscated: true };
    }
  }

  const parts = s.split('.');
  if (parts.length < 1 || parts.length > 4) return null;
  const nums = parts.map(parsePart);
  if (nums.some((n) => n === null)) return null;
  const n = nums as number[];

  let value: number;
  switch (n.length) {
    case 1: {
      const a = n[0];
      if (a === undefined) return null;
      value = a;
      break;
    }
    case 2: {
      const a = n[0];
      const b = n[1];
      if (a === undefined || b === undefined || a > 255 || b > 0xffffff) return null;
      value = a * 2 ** 24 + b;
      break;
    }
    case 3: {
      const a = n[0];
      const b = n[1];
      const c = n[2];
      if (a === undefined || b === undefined || c === undefined) return null;
      if (a > 255 || b > 255 || c > 0xffff) return null;
      value = a * 2 ** 24 + b * 2 ** 16 + c;
      break;
    }
    default: {
      const a = n[0];
      const b = n[1];
      const c = n[2];
      const d = n[3];
      if (a === undefined || b === undefined || c === undefined || d === undefined) return null;
      if (n.some((x) => x > 255)) return null;
      value = a * 2 ** 24 + b * 2 ** 16 + c * 2 ** 8 + d;
    }
  }
  if (value > MAX_U32) return null;

  const normalized = intToIPv4(value);
  return { value, normalized, obfuscated: viaMapped || normalized !== s };
}

function maskFor(prefix: number): number {
  return prefix === 0 ? 0 : (MAX_U32 << (32 - prefix)) >>> 0;
}

/** Parses `a.b.c.d/nn` or a bare IP (treated as /32). */
export function parseCidr(raw: string): ParsedCidr | null {
  const pieces = raw.trim().split('/');
  if (pieces.length > 2) return null;
  const address = pieces[0];
  if (address === undefined) return null;
  const ip = parseIPv4(address);
  if (!ip) return null;
  const prefix = pieces.length === 1 ? 32 : Number(pieces[1]);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const network = (ip.value & maskFor(prefix)) >>> 0;
  return { network, prefix, normalized: `${intToIPv4(network)}/${prefix}` };
}

/**
 * True when a token is an IPv6 literal. The scope engine only understands IPv4,
 * so callers must treat a match as "unverifiable target" rather than "not a target".
 */
export function isIPv6Literal(raw: string): boolean {
  const s = raw.trim().replace(/^\[/, '').replace(/\]$/, '');
  if (!s.includes(':')) return false;
  if (!/^[0-9a-f:.]+$/i.test(s)) return false;
  return (s.match(/:/g)?.length ?? 0) >= 2;
}

export function cidrContainsIp(c: ParsedCidr, ip: number): boolean {
  return ((ip & maskFor(c.prefix)) >>> 0) === c.network;
}

export function cidrContainsCidr(outer: ParsedCidr, inner: ParsedCidr): boolean {
  return inner.prefix >= outer.prefix && cidrContainsIp(outer, inner.network);
}

export function cidrsOverlap(a: ParsedCidr, b: ParsedCidr): boolean {
  return cidrContainsIp(a, b.network) || cidrContainsIp(b, a.network);
}
