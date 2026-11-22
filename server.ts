import dotenv from 'dotenv';
import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanWebsite } from './src/scanner/engine.ts';
import { RateLimiter, validateAndNormalizeUrl } from './src/scanner/security.ts';
import type { ScanPublicResponse } from './src/scanner/types.ts';

dotenv.config({ path: '.env.local' });
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';

const scanRateLimiter = new RateLimiter({
  maxRequests: 300,
  windowMs: 60_000,
  maxConcurrent: 6,
});

function getClientKey(req: express.Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

async function startServer() {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '16kb' }));

  // Basic security headers on API responses
  app.use('/api', (_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true });
  });

  app.post('/api/scan', async (req, res) => {
    const rawUrl = typeof req.body?.url === 'string' ? req.body.url : '';
    const validation = validateAndNormalizeUrl(rawUrl);

    if (!validation.valid || !validation.normalizedUrl) {
      res.status(400).json({
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
      res.status(429).json({
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
      res.status(200).json(publicResponse);
    } catch (err) {
      const message =
        err instanceof Error && err.message
          ? err.message
          : 'Unable to complete the website scan. Please check the URL and try again.';
      res.status(400).json({ error: message });
    } finally {
      scanRateLimiter.release(clientKey);
    }
  });

  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`WordPressFixer Scanner running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
