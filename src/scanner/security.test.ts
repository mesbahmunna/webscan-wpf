import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isBlockedHostname,
  isPrivateOrReservedIp,
  RateLimiter,
  validateAndNormalizeUrl,
} from './security';

test('validateAndNormalizeUrl accepts valid http and https URLs', () => {
  const res1 = validateAndNormalizeUrl('https://wordpressfixer.com');
  assert.equal(res1.valid, true);
  assert.equal(res1.normalizedUrl, 'https://wordpressfixer.com/');

  const res2 = validateAndNormalizeUrl('example.com/blog?page=1#top');
  assert.equal(res2.valid, true);
  assert.equal(res2.normalizedUrl, 'https://example.com/blog?page=1');

  const res3 = validateAndNormalizeUrl('http://example.com:80/path');
  assert.equal(res3.valid, true);
});

test('validateAndNormalizeUrl rejects unsupported schemes, credentials, and non-standard ports', () => {
  assert.equal(validateAndNormalizeUrl('').valid, false);
  assert.equal(validateAndNormalizeUrl('ftp://example.com').valid, false);
  assert.equal(validateAndNormalizeUrl('javascript:alert(1)').valid, false);
  assert.equal(validateAndNormalizeUrl('file:///etc/passwd').valid, false);
  assert.equal(validateAndNormalizeUrl('https://user:pass@example.com').valid, false);
  assert.equal(validateAndNormalizeUrl('https://example.com:8080').valid, false);
  assert.equal(validateAndNormalizeUrl('http://example.com:6379').valid, false);
});

test('validateAndNormalizeUrl blocks localhost, internal hostnames, and private/metadata IPs', () => {
  assert.equal(validateAndNormalizeUrl('http://localhost').valid, false);
  assert.equal(validateAndNormalizeUrl('http://sub.localhost').valid, false);
  assert.equal(validateAndNormalizeUrl('http://metadata.google.internal').valid, false);
  assert.equal(validateAndNormalizeUrl('http://169.254.169.254/latest/meta-data/').valid, false);
  assert.equal(validateAndNormalizeUrl('http://127.0.0.1').valid, false);
  assert.equal(validateAndNormalizeUrl('http://10.0.0.5').valid, false);
  assert.equal(validateAndNormalizeUrl('http://192.168.1.1').valid, false);
  assert.equal(validateAndNormalizeUrl('http://172.16.0.1').valid, false);
  assert.equal(validateAndNormalizeUrl('http://[::1]').valid, false);
});

test('isPrivateOrReservedIp classifies private, loopback, link-local, and IPv4-mapped IPv6 accurately', () => {
  assert.equal(isPrivateOrReservedIp('127.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('10.20.30.40'), true);
  assert.equal(isPrivateOrReservedIp('172.20.0.1'), true);
  assert.equal(isPrivateOrReservedIp('192.168.100.1'), true);
  assert.equal(isPrivateOrReservedIp('169.254.169.254'), true);
  assert.equal(isPrivateOrReservedIp('100.64.0.1'), true);
  assert.equal(isPrivateOrReservedIp('0.0.0.0'), true);
  assert.equal(isPrivateOrReservedIp('::1'), true);
  assert.equal(isPrivateOrReservedIp('::ffff:127.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('::ffff:169.254.169.254'), true);
  assert.equal(isPrivateOrReservedIp('fe80::1'), true);
  assert.equal(isPrivateOrReservedIp('fc00::1'), true);

  assert.equal(isPrivateOrReservedIp('93.184.216.34'), false);
  assert.equal(isPrivateOrReservedIp('1.1.1.1'), false);
  assert.equal(isPrivateOrReservedIp('2606:2800:220:1:248:1893:25c8:1946'), false);
});

test('isBlockedHostname catches restricted hostnames and suffixes', () => {
  assert.equal(isBlockedHostname('localhost'), true);
  assert.equal(isBlockedHostname('db.internal'), true);
  assert.equal(isBlockedHostname('printer.local'), true);
  assert.equal(isBlockedHostname('wordpressfixer.com'), false);
});

test('RateLimiter enforces max concurrent and sliding window limits', () => {
  const limiter = new RateLimiter({ maxRequests: 2, windowMs: 10_000, maxConcurrent: 1 });
  const t0 = 1_000_000;

  assert.equal(limiter.acquire('1.2.3.4', t0).allowed, true);
  // Concurrent limit hit
  assert.equal(limiter.acquire('1.2.3.4', t0 + 100).allowed, false);
  limiter.release('1.2.3.4');

  // Second request within window succeeds
  assert.equal(limiter.acquire('1.2.3.4', t0 + 200).allowed, true);
  limiter.release('1.2.3.4');

  // Third request within window is rate-limited
  const third = limiter.acquire('1.2.3.4', t0 + 300);
  assert.equal(third.allowed, false);
  assert.ok((third.retryAfterSec ?? 0) > 0);

  // After window expires, allowed again
  assert.equal(limiter.acquire('1.2.3.4', t0 + 11_000).allowed, true);
  limiter.release('1.2.3.4');
});
