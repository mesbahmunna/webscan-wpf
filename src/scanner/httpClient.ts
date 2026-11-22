import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import zlib from 'node:zlib';
import type { LookupFunction } from 'node:net';
import { resolveAndValidateHost, validateAndNormalizeUrl } from './security.ts';
import type { HttpFetchResult, RedirectHop, SafeHttpClient } from './types.ts';

const SCANNER_USER_AGENT =
  'Mozilla/5.0 (compatible; WordPressFixerScanner/1.0; +https://wordpressfixer.com/)';

const DEFAULT_TIMEOUT_MS = 6500;
const DEFAULT_MAX_BYTES = 1_500_000; // 1.5 MB
const DEFAULT_MAX_REDIRECTS = 7;

interface SingleRequestResult {
  statusCode: number | null;
  statusMessage: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  bodyTruncated: boolean;
  byteLength: number;
  errorCode?: string;
  errorMessage?: string;
  tlsAuthorized?: boolean;
  tlsAuthError?: string;
}

function createPinnedLookup(pinnedAddress: string, family: 4 | 6): LookupFunction {
  return ((_hostname, options, callback) => {
    const cb = typeof options === 'function' ? options : callback;
    const opts = typeof options === 'object' && options !== null ? options : {};
    if ((opts as { all?: boolean }).all) {
      (cb as (err: NodeJS.ErrnoException | null, addresses: Array<{ address: string; family: number }>) => void)(
        null,
        [{ address: pinnedAddress, family }]
      );
    } else {
      (cb as (err: NodeJS.ErrnoException | null, address: string, family: number) => void)(
        null,
        pinnedAddress,
        family
      );
    }
  }) as LookupFunction;
}

function performSingleRequest(
  parsedUrl: URL,
  pinned: { address: string; family: 4 | 6 },
  options: {
    method: 'GET' | 'HEAD';
    timeoutMs: number;
    maxBytes: number;
    rejectUnauthorized: boolean;
  }
): Promise<SingleRequestResult> {
  return new Promise((resolve) => {
    const isHttps = parsedUrl.protocol === 'https:';
    const transport = isHttps ? https : http;
    const port = parsedUrl.port ? Number(parsedUrl.port) : isHttps ? 443 : 80;

    let settled = false;
    const finish = (result: SingleRequestResult) => {
      if (!settled) {
        settled = true;
        resolve(result);
      }
    };

    const reqOptions: https.RequestOptions = {
      protocol: parsedUrl.protocol,
      hostname: parsedUrl.hostname,
      port,
      path: `${parsedUrl.pathname || '/'}${parsedUrl.search || ''}`,
      method: options.method,
      lookup: createPinnedLookup(pinned.address, pinned.family),
      timeout: options.timeoutMs,
      headers: {
        'User-Agent': SCANNER_USER_AGENT,
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        Connection: 'close',
      },
      ...(isHttps
        ? {
            servername: parsedUrl.hostname,
            rejectUnauthorized: options.rejectUnauthorized,
          }
        : {}),
    };

    const req = transport.request(reqOptions, (res) => {
      const tlsSocket = res.socket as tls.TLSSocket;
      const tlsAuthorized = isHttps ? Boolean(tlsSocket?.authorized) : undefined;
      const tlsAuthError =
        isHttps && tlsSocket?.authorizationError
          ? String(tlsSocket.authorizationError)
          : undefined;

      if (options.method === 'HEAD') {
        res.resume();
        finish({
          statusCode: res.statusCode ?? null,
          statusMessage: res.statusMessage ?? '',
          headers: res.headers,
          body: '',
          bodyTruncated: false,
          byteLength: 0,
          tlsAuthorized,
          tlsAuthError,
        });
        return;
      }

      const encoding = String(res.headers['content-encoding'] ?? '').toLowerCase();
      let stream: NodeJS.ReadableStream = res;

      if (encoding === 'gzip') {
        const gunzip = zlib.createGunzip();
        res.pipe(gunzip);
        stream = gunzip;
      } else if (encoding === 'deflate') {
        const inflate = zlib.createInflate();
        res.pipe(inflate);
        stream = inflate;
      } else if (encoding === 'br') {
        const brotli = zlib.createBrotliDecompress();
        res.pipe(brotli);
        stream = brotli;
      }

      const chunks: Buffer[] = [];
      let totalBytes = 0;
      let truncated = false;

      stream.on('data', (chunk: Buffer | string) => {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        if (totalBytes + buf.length > options.maxBytes) {
          const remaining = options.maxBytes - totalBytes;
          if (remaining > 0) {
            chunks.push(buf.subarray(0, remaining));
            totalBytes += remaining;
          }
          truncated = true;
          req.destroy();
          finish({
            statusCode: res.statusCode ?? null,
            statusMessage: res.statusMessage ?? '',
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
            bodyTruncated: true,
            byteLength: totalBytes,
            tlsAuthorized,
            tlsAuthError,
          });
          return;
        }
        chunks.push(buf);
        totalBytes += buf.length;
      });

      stream.on('end', () => {
        finish({
          statusCode: res.statusCode ?? null,
          statusMessage: res.statusMessage ?? '',
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
          bodyTruncated: truncated,
          byteLength: totalBytes,
          tlsAuthorized,
          tlsAuthError,
        });
      });

      stream.on('error', (streamErr: NodeJS.ErrnoException) => {
        if (truncated) return;
        finish({
          statusCode: res.statusCode ?? null,
          statusMessage: res.statusMessage ?? '',
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
          bodyTruncated: truncated,
          byteLength: totalBytes,
          errorCode: streamErr.code || 'STREAM_ERROR',
          errorMessage: streamErr.message,
          tlsAuthorized,
          tlsAuthError,
        });
      });
    });

    req.on('timeout', () => {
      req.destroy(Object.assign(new Error('Request timed out'), { code: 'ETIMEDOUT' }));
    });

    req.on('error', (err: NodeJS.ErrnoException) => {
      finish({
        statusCode: null,
        statusMessage: '',
        headers: {},
        body: '',
        bodyTruncated: false,
        byteLength: 0,
        errorCode: err.code || 'REQUEST_ERROR',
        errorMessage: err.message,
      });
    });

    req.end();
  });
}

export function createSafeHttpClient(): SafeHttpClient {
  return {
    async fetch(targetUrl, opts = {}): Promise<HttpFetchResult> {
      const startTime = Date.now();
      const method = opts.method ?? 'GET';
      const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
      const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
      const maxRedirects = opts.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
      const followRedirects = opts.followRedirects ?? true;
      const rejectUnauthorized = opts.rejectUnauthorized ?? false;

      const visited = new Set<string>();
      const redirectChain: RedirectHop[] = [];
      let currentUrl = targetUrl;
      let lastResolvedIp: string | null = null;

      for (let hop = 0; hop <= maxRedirects; hop++) {
        const validation = validateAndNormalizeUrl(currentUrl);
        if (!validation.valid || !validation.parsedUrl || !validation.normalizedUrl) {
          return {
            ok: false,
            initialUrl: targetUrl,
            finalUrl: currentUrl,
            statusCode: null,
            statusMessage: '',
            headers: {},
            body: '',
            bodyTruncated: false,
            byteLength: 0,
            redirectChain,
            resolvedIp: lastResolvedIp,
            errorCode: 'BLOCKED_URL',
            errorMessage: validation.error || 'Blocked URL',
            redirectIssue: hop > 0 ? 'blocked-redirect' : undefined,
            durationMs: Date.now() - startTime,
          };
        }

        const parsed = validation.parsedUrl;
        const normalized = validation.normalizedUrl;

        if (visited.has(normalized)) {
          return {
            ok: false,
            initialUrl: targetUrl,
            finalUrl: normalized,
            statusCode: null,
            statusMessage: '',
            headers: {},
            body: '',
            bodyTruncated: false,
            byteLength: 0,
            redirectChain,
            resolvedIp: lastResolvedIp,
            errorCode: 'REDIRECT_LOOP',
            errorMessage: 'Redirect loop detected.',
            redirectIssue: 'redirect-loop',
            durationMs: Date.now() - startTime,
          };
        }
        visited.add(normalized);

        const resolved = await resolveAndValidateHost(parsed.hostname);
        if (!resolved.allowed || !resolved.pinned) {
          return {
            ok: false,
            initialUrl: targetUrl,
            finalUrl: normalized,
            statusCode: null,
            statusMessage: '',
            headers: {},
            body: '',
            bodyTruncated: false,
            byteLength: 0,
            redirectChain,
            resolvedIp: lastResolvedIp,
            errorCode: resolved.dnsErrorCode || 'BLOCKED_HOST',
            errorMessage: resolved.blockedReason || 'DNS lookup failed.',
            redirectIssue: hop > 0 && resolved.blockedReason ? 'blocked-redirect' : undefined,
            durationMs: Date.now() - startTime,
          };
        }

        lastResolvedIp = resolved.pinned.address;
        const response = await performSingleRequest(parsed, resolved.pinned, {
          method,
          timeoutMs,
          maxBytes,
          rejectUnauthorized,
        });

        const status = response.statusCode;
        const isRedirect =
          status !== null && [301, 302, 303, 307, 308].includes(status);

        if (isRedirect && followRedirects) {
          const rawLocation = response.headers.location;
          const location = Array.isArray(rawLocation) ? rawLocation[0] : rawLocation;

          if (!location || !location.trim()) {
            return {
              ok: false,
              initialUrl: targetUrl,
              finalUrl: normalized,
              statusCode: status,
              statusMessage: response.statusMessage,
              headers: response.headers,
              body: response.body,
              bodyTruncated: response.bodyTruncated,
              byteLength: response.byteLength,
              redirectChain,
              resolvedIp: lastResolvedIp,
              errorCode: 'INVALID_REDIRECT',
              errorMessage: 'Redirect response missing Location header.',
              redirectIssue: 'invalid-redirect',
              tlsAuthorized: response.tlsAuthorized,
              tlsAuthError: response.tlsAuthError,
              durationMs: Date.now() - startTime,
            };
          }

          let nextUrl: string;
          try {
            const resolvedNext = new URL(location.trim(), normalized);
            if (resolvedNext.protocol !== 'http:' && resolvedNext.protocol !== 'https:') {
              return {
                ok: false,
                initialUrl: targetUrl,
                finalUrl: normalized,
                statusCode: status,
                statusMessage: response.statusMessage,
                headers: response.headers,
                body: response.body,
                bodyTruncated: response.bodyTruncated,
                byteLength: response.byteLength,
                redirectChain,
                resolvedIp: lastResolvedIp,
                errorCode: 'INVALID_REDIRECT',
                errorMessage: 'Redirect points to an unsupported scheme.',
                redirectIssue: 'invalid-redirect',
                durationMs: Date.now() - startTime,
              };
            }
            nextUrl = resolvedNext.toString();
          } catch {
            return {
              ok: false,
              initialUrl: targetUrl,
              finalUrl: normalized,
              statusCode: status,
              statusMessage: response.statusMessage,
              headers: response.headers,
              body: response.body,
              bodyTruncated: response.bodyTruncated,
              byteLength: response.byteLength,
              redirectChain,
              resolvedIp: lastResolvedIp,
              errorCode: 'INVALID_REDIRECT',
              errorMessage: 'Malformed redirect Location URL.',
              redirectIssue: 'invalid-redirect',
              durationMs: Date.now() - startTime,
            };
          }

          redirectChain.push({
            fromUrl: normalized,
            toUrl: nextUrl,
            statusCode: status,
            locationHeader: location.trim(),
          });

          if (hop === maxRedirects) {
            return {
              ok: false,
              initialUrl: targetUrl,
              finalUrl: nextUrl,
              statusCode: status,
              statusMessage: response.statusMessage,
              headers: response.headers,
              body: response.body,
              bodyTruncated: response.bodyTruncated,
              byteLength: response.byteLength,
              redirectChain,
              resolvedIp: lastResolvedIp,
              errorCode: 'TOO_MANY_REDIRECTS',
              errorMessage: 'Exceeded maximum redirect hops.',
              redirectIssue: 'too-many-redirects',
              durationMs: Date.now() - startTime,
            };
          }

          currentUrl = nextUrl;
          continue;
        }

        const isBrokenAfterRedirect =
          redirectChain.length > 0 &&
          (status === null || status >= 400);

        return {
          ok: status !== null && status >= 200 && status < 400 && !response.errorCode,
          initialUrl: targetUrl,
          finalUrl: normalized,
          statusCode: status,
          statusMessage: response.statusMessage,
          headers: response.headers,
          body: response.body,
          bodyTruncated: response.bodyTruncated,
          byteLength: response.byteLength,
          redirectChain,
          resolvedIp: lastResolvedIp,
          errorCode: response.errorCode,
          errorMessage: response.errorMessage,
          redirectIssue: isBrokenAfterRedirect ? 'broken-redirect' : undefined,
          tlsAuthorized: response.tlsAuthorized,
          tlsAuthError: response.tlsAuthError,
          durationMs: Date.now() - startTime,
        };
      }

      return {
        ok: false,
        initialUrl: targetUrl,
        finalUrl: currentUrl,
        statusCode: null,
        statusMessage: '',
        headers: {},
        body: '',
        bodyTruncated: false,
        byteLength: 0,
        redirectChain,
        resolvedIp: lastResolvedIp,
        errorCode: 'TOO_MANY_REDIRECTS',
        errorMessage: 'Exceeded maximum redirect hops.',
        redirectIssue: 'too-many-redirects',
        durationMs: Date.now() - startTime,
      };
    },
  };
}
