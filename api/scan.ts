import type { IncomingMessage, ServerResponse } from 'node:http';
import { scanWebsite } from '../src/scanner/engine.ts';
import { RateLimiter, validateAndNormalizeUrl } from '../src/scanner/security.ts';
import type { ScanPublicResponse } from '../src/scanner/types.ts';

interface VercelRequestLike extends IncomingMessage {
  body?: unknown;
}

const scanRateLimiter = new RateLimiter({
  maxRequests: 300,
  windowMs: 60_000,
  maxConcurrent: 6,
});

const MAX_BODY_BYTES = 16 * 1024;

function sendJson(res: ServerResponse, statusCode: number, payload: unknown): void {
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(payload));
}

function getClientKey(req: IncomingMessage): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }
  if (Array.isArray(forwarded) && forwarded[0]) {
    return forwarded[0].split(',')[0].trim();
  }
  return req.socket?.remoteAddress || 'unknown';
}

async function readJsonBody(req: VercelRequestLike): Promise<Record<string, unknown>> {
  if (req.body && typeof req.body === 'object') {
    return req.body as Record<string, unknown>;
  }
  if (typeof req.body === 'string') {
    try {
      const parsed = JSON.parse(req.body);
      return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : {};
    } catch {
      return {};
    }
  }

  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;

    req.on('data', (chunk: Buffer | string) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += buf.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error('Request payload too large.'));
        req.destroy();
        return;
      }
      chunks.push(buf);
    });

    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8').trim();
        if (!raw) {
          resolve({});
          return;
        }
        const parsed = JSON.parse(raw);
        resolve(parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : {});
      } catch {
        resolve({});
      }
    });

    req.on('error', () => resolve({}));
  });
}

export default async function handler(req: VercelRequestLike, res: ServerResponse): Promise<void> {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    sendJson(res, 405, { error: 'Method not allowed. Use POST.' });
    return;
  }

  let body: Record<string, unknown>;
  try {
    body = await readJsonBody(req);
  } catch (err) {
    sendJson(res, 413, {
      error: err instanceof Error ? err.message : 'Request payload too large.',
    });
    return;
  }

  const rawUrl = typeof body.url === 'string' ? body.url : '';
  const validation = validateAndNormalizeUrl(rawUrl);
  if (!validation.valid || !validation.normalizedUrl) {
    sendJson(res, 400, {
      error: validation.error || 'Please enter a valid HTTP or HTTPS website URL.',
    });
    return;
  }

  const clientKey = getClientKey(req);
  const rateCheck = scanRateLimiter.acquire(clientKey);
  if (!rateCheck.allowed) {
    if (rateCheck.retryAfterSec) {
      res.setHeader('Retry-After', String(rateCheck.retryAfterSec));
    }
    sendJson(res, 429, {
      error: rateCheck.reason || 'Too many scan requests. Please wait a moment and try again.',
    });
    return;
  }

  try {
    const report = await scanWebsite(validation.normalizedUrl);
    const publicResponse: ScanPublicResponse = {
      scannedUrl: report.scannedUrl,
      errors: report.errors,
    };
    sendJson(res, 200, publicResponse);
  } catch (err) {
    const message =
      err instanceof Error && err.message
        ? err.message
        : 'Unable to complete the website scan. Please check the URL and try again.';
    sendJson(res, 400, { error: message });
  } finally {
    scanRateLimiter.release(clientKey);
  }
}
