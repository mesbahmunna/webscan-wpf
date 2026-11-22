import type { IncomingMessage, ServerResponse } from 'node:http';
import { verifyGoogleThreatApiStatus } from '../src/scanner/checks/webRiskCheck.ts';

export default async function handler(
  req: IncomingMessage,
  res: ServerResponse
): Promise<void> {
  if (req.method !== 'GET' && req.method !== 'POST') {
    res.statusCode = 405;
    res.setHeader('Allow', 'GET, POST');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: 'Method not allowed.' }));
    return;
  }

  const status = await verifyGoogleThreatApiStatus();
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(status));
}
