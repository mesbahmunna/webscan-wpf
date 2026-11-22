import dns from 'node:dns/promises';
import net from 'node:net';

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);
const ALLOWED_PORTS = new Set(['', '80', '443']);

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'metadata.google.internal',
  'metadata',
  'instance-data',
  '169.254.169.254',
  '0.0.0.0',
]);

const BLOCKED_HOSTNAME_SUFFIXES = [
  '.localhost',
  '.local',
  '.localdomain',
  '.internal',
  '.home.arpa',
  '.lan',
  '.corp',
  '.intranet',
];

export interface UrlValidationResult {
  valid: boolean;
  normalizedUrl?: string;
  parsedUrl?: URL;
  error?: string;
}

export function validateAndNormalizeUrl(rawInput: string): UrlValidationResult {
  if (typeof rawInput !== 'string') {
    return { valid: false, error: 'Please enter a valid HTTP or HTTPS website URL.' };
  }

  const trimmed = rawInput.trim();
  if (!trimmed) {
    return { valid: false, error: 'Please enter a website URL to scan.' };
  }

  if (trimmed.length > 2048) {
    return { valid: false, error: 'The URL exceeds the maximum supported length.' };
  }

  if (/[\s\r\n\t<>"{}|\\^`]/.test(trimmed)) {
    return { valid: false, error: 'Please enter a valid website URL without spaces or invalid characters.' };
  }

  let candidate = trimmed;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(candidate)) {
    // Reject obvious non-http schemes like javascript: or data: or mailto:
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(candidate)) {
      return { valid: false, error: 'Only HTTP and HTTPS websites are supported.' };
    }
    candidate = `https://${candidate}`;
  }

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return { valid: false, error: 'Please enter a valid website URL (for example, https://example.com).' };
  }

  if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
    return { valid: false, error: 'Only HTTP and HTTPS websites are supported.' };
  }

  if (parsed.username || parsed.password) {
    return { valid: false, error: 'URLs containing authentication credentials are not permitted.' };
  }

  if (!ALLOWED_PORTS.has(parsed.port)) {
    return { valid: false, error: 'Only standard HTTP (80) and HTTPS (443) ports are allowed.' };
  }

  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (!hostname) {
    return { valid: false, error: 'Please enter a valid domain name.' };
  }

  if (isBlockedHostname(hostname)) {
    return { valid: false, error: 'Scanning local, private, or internal network addresses is not permitted.' };
  }

  const ipVersion = net.isIP(hostname.replace(/^\[|\]$/g, ''));
  if (ipVersion !== 0) {
    const cleanIp = hostname.replace(/^\[|\]$/g, '');
    if (isPrivateOrReservedIp(cleanIp)) {
      return { valid: false, error: 'Scanning private, loopback, or reserved IP addresses is not permitted.' };
    }
  } else {
    // Must contain a valid TLD dot and valid DNS hostname characters
    if (!hostname.includes('.') || hostname.startsWith('.') || hostname.includes('..')) {
      return { valid: false, error: 'Please enter a valid public domain name (for example, https://example.com).' };
    }
    if (!/^[a-z0-9.-]+$/.test(hostname)) {
      return { valid: false, error: 'Please enter a valid domain name.' };
    }
  }

  // Strip fragment for server requests
  parsed.hash = '';

  return {
    valid: true,
    normalizedUrl: parsed.toString(),
    parsedUrl: parsed,
  };
}

export function isBlockedHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!normalized) return true;
  if (BLOCKED_HOSTNAMES.has(normalized)) return true;
  for (const suffix of BLOCKED_HOSTNAME_SUFFIXES) {
    if (normalized.endsWith(suffix)) return true;
  }
  return false;
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const n = Number(part);
    if (n < 0 || n > 255) return null;
    value = (value << 8) | n;
  }
  return value >>> 0;
}

function isPrivateOrReservedIpv4(ip: string): boolean {
  const num = ipv4ToInt(ip);
  if (num === null) return true;

  const ranges: Array<[number, number]> = [
    [0x00000000, 0x00ffffff], // 0.0.0.0/8 (this network)
    [0x0a000000, 0x0affffff], // 10.0.0.0/8 (private)
    [0x64400000, 0x647fffff], // 100.64.0.0/10 (CGNAT / shared)
    [0x7f000000, 0x7fffffff], // 127.0.0.0/8 (loopback)
    [0xa9fe0000, 0xa9feffff], // 169.254.0.0/16 (link-local & cloud metadata)
    [0xac100000, 0xac1fffff], // 172.16.0.0/12 (private)
    [0xc0000000, 0xc00000ff], // 192.0.0.0/24 (IETF protocol assignments)
    [0xc0000200, 0xc00002ff], // 192.0.2.0/24 (TEST-NET-1)
    [0xc0586300, 0xc05863ff], // 192.88.99.0/24 (6to4 relay anycast)
    [0xc0a80000, 0xc0a8ffff], // 192.168.0.0/16 (private)
    [0xc6120000, 0xc613ffff], // 198.18.0.0/15 (benchmarking)
    [0xc6336400, 0xc63364ff], // 198.51.100.0/24 (TEST-NET-2)
    [0xcb007100, 0xcb0071ff], // 203.0.113.0/24 (TEST-NET-3)
    [0xe0000000, 0xefffffff], // 224.0.0.0/4 (multicast)
    [0xf0000000, 0xffffffff], // 240.0.0.0/4 (reserved & broadcast)
  ];

  for (const [start, end] of ranges) {
    if (num >= start && num <= end) {
      return true;
    }
  }
  return false;
}

function expandIpv6(ip: string): string[] | null {
  let clean = ip.toLowerCase().trim();
  const zoneIdx = clean.indexOf('%');
  if (zoneIdx !== -1) {
    clean = clean.slice(0, zoneIdx);
  }

  // Handle embedded IPv4 (e.g. ::ffff:127.0.0.1)
  const lastColon = clean.lastIndexOf(':');
  if (lastColon !== -1 && clean.slice(lastColon + 1).includes('.')) {
    const ipv4Part = clean.slice(lastColon + 1);
    const v4Int = ipv4ToInt(ipv4Part);
    if (v4Int === null) return null;
    const high = ((v4Int >>> 16) & 0xffff).toString(16);
    const low = (v4Int & 0xffff).toString(16);
    clean = `${clean.slice(0, lastColon)}:${high}:${low}`;
  }

  const doubleColonParts = clean.split('::');
  if (doubleColonParts.length > 2) return null;

  let groups: string[];
  if (doubleColonParts.length === 2) {
    const left = doubleColonParts[0] ? doubleColonParts[0].split(':') : [];
    const right = doubleColonParts[1] ? doubleColonParts[1].split(':') : [];
    const missing = 8 - (left.length + right.length);
    if (missing < 0) return null;
    groups = [...left, ...Array(missing).fill('0'), ...right];
  } else {
    groups = clean.split(':');
  }

  if (groups.length !== 8) return null;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
  }
  return groups.map((g) => g.padStart(4, '0'));
}

function isPrivateOrReservedIpv6(ip: string): boolean {
  const groups = expandIpv6(ip);
  if (!groups) return true;

  const first = parseInt(groups[0], 16);
  const fullHex = groups.join('');

  // :: (unspecified) or ::1 (loopback)
  if (fullHex === '00000000000000000000000000000000') return true;
  if (fullHex === '00000000000000000000000000000001') return true;

  // ::ffff:0:0/96 (IPv4-mapped IPv6) or ::0:0/96 (IPv4-compatible)
  if (
    groups[0] === '0000' &&
    groups[1] === '0000' &&
    groups[2] === '0000' &&
    groups[3] === '0000' &&
    groups[4] === '0000' &&
    (groups[5] === 'ffff' || groups[5] === '0000')
  ) {
    const high = parseInt(groups[6], 16);
    const low = parseInt(groups[7], 16);
    const v4 = `${(high >>> 8) & 0xff}.${high & 0xff}.${(low >>> 8) & 0xff}.${low & 0xff}`;
    return isPrivateOrReservedIpv4(v4);
  }

  // 64:ff9b::/96 (NAT64 well-known prefix)
  if (
    groups[0] === '0064' &&
    groups[1] === 'ff9b' &&
    groups[2] === '0000' &&
    groups[3] === '0000' &&
    groups[4] === '0000' &&
    groups[5] === '0000'
  ) {
    const high = parseInt(groups[6], 16);
    const low = parseInt(groups[7], 16);
    const v4 = `${(high >>> 8) & 0xff}.${high & 0xff}.${(low >>> 8) & 0xff}.${low & 0xff}`;
    return isPrivateOrReservedIpv4(v4);
  }

  // fc00::/7 (Unique Local Address)
  if ((first & 0xfe00) === 0xfc00) return true;
  // fe80::/10 (Link-local)
  if ((first & 0xffc0) === 0xfe80) return true;
  // fec0::/10 (Deprecated site-local)
  if ((first & 0xffc0) === 0xfec0) return true;
  // ff00::/8 (Multicast)
  if ((first & 0xff00) === 0xff00) return true;
  // 2001:db8::/32 (Documentation)
  if (groups[0] === '2001' && groups[1] === '0db8') return true;
  // 100::/64 (Discard-only)
  if (groups[0] === '0100' && groups[1] === '0000' && groups[2] === '0000' && groups[3] === '0000') {
    return true;
  }

  return false;
}

export function isPrivateOrReservedIp(ip: string): boolean {
  const clean = ip.trim().replace(/^\[|\]$/g, '');
  const version = net.isIP(clean);
  if (version === 4) {
    return isPrivateOrReservedIpv4(clean);
  }
  if (version === 6) {
    return isPrivateOrReservedIpv6(clean);
  }
  return true;
}

export interface HostResolutionResult {
  allowed: boolean;
  addresses: Array<{ address: string; family: 4 | 6 }>;
  pinned?: { address: string; family: 4 | 6 };
  blockedReason?: string;
  dnsErrorCode?: string;
}

export async function resolveAndValidateHost(hostname: string): Promise<HostResolutionResult> {
  const cleanHost = hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (isBlockedHostname(cleanHost)) {
    return {
      allowed: false,
      addresses: [],
      blockedReason: 'Hostname is local or restricted.',
    };
  }

  const ipVer = net.isIP(cleanHost);
  if (ipVer === 4 || ipVer === 6) {
    if (isPrivateOrReservedIp(cleanHost)) {
      return {
        allowed: false,
        addresses: [],
        blockedReason: 'Destination IP address is private or reserved.',
      };
    }
    const entry = { address: cleanHost, family: ipVer as 4 | 6 };
    return {
      allowed: true,
      addresses: [entry],
      pinned: entry,
    };
  }

  try {
    const records = await dns.lookup(cleanHost, { all: true, verbatim: false });
    if (!records || records.length === 0) {
      return {
        allowed: false,
        addresses: [],
        dnsErrorCode: 'ENOTFOUND',
      };
    }

    const validated: Array<{ address: string; family: 4 | 6 }> = [];
    for (const rec of records) {
      if (isPrivateOrReservedIp(rec.address)) {
        return {
          allowed: false,
          addresses: [],
          blockedReason: 'Resolved IP address belongs to a private or reserved network.',
        };
      }
      validated.push({
        address: rec.address,
        family: rec.family === 6 ? 6 : 4,
      });
    }

    // Prefer IPv4 when available for widest TLS/HTTP reliability, else IPv6
    const pinned = validated.find((r) => r.family === 4) ?? validated[0];
    return {
      allowed: true,
      addresses: validated,
      pinned,
    };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code || 'DNS_LOOKUP_FAILED';
    return {
      allowed: false,
      addresses: [],
      dnsErrorCode: code,
    };
  }
}

export class RateLimiter {
  private readonly maxRequests: number;
  private readonly windowMs: number;
  private readonly maxConcurrent: number;
  private readonly hits = new Map<string, number[]>();
  private readonly active = new Map<string, number>();

  constructor(options?: { maxRequests?: number; windowMs?: number; maxConcurrent?: number }) {
    this.maxRequests = options?.maxRequests ?? 12;
    this.windowMs = options?.windowMs ?? 60_000;
    this.maxConcurrent = options?.maxConcurrent ?? 2;
  }

  acquire(key: string, now = Date.now()): { allowed: boolean; retryAfterSec?: number; reason?: string } {
    const currentActive = this.active.get(key) ?? 0;
    if (currentActive >= this.maxConcurrent) {
      return {
        allowed: false,
        retryAfterSec: 5,
        reason: 'Too many simultaneous scans from your address. Please wait for the current scan to finish.',
      };
    }

    const cutoff = now - this.windowMs;
    const timestamps = (this.hits.get(key) ?? []).filter((t) => t > cutoff);
    if (timestamps.length >= this.maxRequests) {
      const oldest = timestamps[0] ?? now;
      const retryAfterSec = Math.max(1, Math.ceil((oldest + this.windowMs - now) / 1000));
      this.hits.set(key, timestamps);
      return {
        allowed: false,
        retryAfterSec,
        reason: `Rate limit reached. Please try again in ${retryAfterSec} seconds.`,
      };
    }

    timestamps.push(now);
    this.hits.set(key, timestamps);
    this.active.set(key, currentActive + 1);
    return { allowed: true };
  }

  release(key: string): void {
    const current = this.active.get(key) ?? 0;
    if (current <= 1) {
      this.active.delete(key);
    } else {
      this.active.set(key, current - 1);
    }
  }
}
