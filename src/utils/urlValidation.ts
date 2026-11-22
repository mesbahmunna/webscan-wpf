const BLOCKED_CLIENT_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  '0.0.0.0',
  '127.0.0.1',
  '169.254.169.254',
  '::1',
]);

const BLOCKED_SUFFIXES = ['.localhost', '.local', '.localdomain', '.internal', '.lan'];

export interface ClientUrlValidation {
  valid: boolean;
  normalized?: string;
  error?: string;
}

export function validateClientUrl(rawInput: string): ClientUrlValidation {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    return { valid: false, error: 'Please enter a website URL to scan.' };
  }

  if (/\s/.test(trimmed)) {
    return { valid: false, error: 'URL cannot contain spaces.' };
  }

  let candidate = trimmed;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(candidate)) {
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

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, error: 'Only HTTP and HTTPS websites are supported.' };
  }

  if (parsed.username || parsed.password) {
    return { valid: false, error: 'URLs containing credentials are not allowed.' };
  }

  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    return { valid: false, error: 'Only standard HTTP (80) and HTTPS (443) ports are allowed.' };
  }

  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (
    !host ||
    BLOCKED_CLIENT_HOSTNAMES.has(host) ||
    BLOCKED_SUFFIXES.some((s) => host.endsWith(s)) ||
    /^127\./.test(host) ||
    /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^169\.254\./.test(host) ||
    /^172\.(?:1[6-9]|2\d|3[01])\./.test(host)
  ) {
    return { valid: false, error: 'Scanning local, private, or internal addresses is not permitted.' };
  }

  const isIpv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
  if (!isIpv4 && (!host.includes('.') || host.startsWith('.') || host.includes('..'))) {
    return { valid: false, error: 'Please enter a valid public domain name (for example, https://example.com).' };
  }

  parsed.hash = '';
  return { valid: true, normalized: parsed.toString() };
}
