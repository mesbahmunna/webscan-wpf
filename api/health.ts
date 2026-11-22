import type { IncomingMessage, ServerResponse } from 'node:http';
import { isWebRiskConfigured } from '../src/scanner/checks/webRiskCheck.ts';

export default function handler(_req: IncomingMessage, res: ServerResponse): void {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify({ ok: true, webRiskConfigured: isWebRiskConfigured() }));
}
