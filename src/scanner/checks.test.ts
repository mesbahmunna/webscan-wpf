import test from 'node:test';
import assert from 'node:assert/strict';
import * as cheerio from 'cheerio';
import { deduplicateErrorNames, evaluateScanContext } from './engine';
import { detectWordPressFootprint } from './checks/wordpressCheck';
import type { HttpFetchResult, SafeHttpClient, ScanContext } from './types';

function makeMockClient(
  routes: Record<string, Partial<HttpFetchResult>> = {}
): SafeHttpClient {
  return {
    async fetch(targetUrl): Promise<HttpFetchResult> {
      const match = routes[targetUrl];
      return {
        ok: match?.ok ?? true,
        initialUrl: targetUrl,
        finalUrl: match?.finalUrl ?? targetUrl,
        statusCode: match?.statusCode !== undefined ? match.statusCode : 200,
        statusMessage: match?.statusMessage ?? 'OK',
        headers: match?.headers ?? { 'content-type': 'text/plain' },
        body: match?.body ?? '',
        bodyTruncated: false,
        byteLength: (match?.body ?? '').length,
        redirectChain: match?.redirectChain ?? [],
        resolvedIp: '93.184.216.34',
        errorCode: match?.errorCode,
        errorMessage: match?.errorMessage,
        durationMs: 10,
      };
    },
  };
}

function makeCleanContext(overrides: Partial<ScanContext> = {}): ScanContext {
  const cleanHtml = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>Clean Example Site</title>
  </head>
  <body>
    <h1>Welcome to Clean Example</h1>
    <p>Everything is configured properly.</p>
  </body>
</html>`;

  const parsed = new URL('https://clean-example.com/');
  const http: HttpFetchResult = {
    ok: true,
    initialUrl: 'https://clean-example.com/',
    finalUrl: 'https://clean-example.com/',
    statusCode: 200,
    statusMessage: 'OK',
    headers: {
      'content-type': 'text/html; charset=utf-8',
    },
    body: cleanHtml,
    bodyTruncated: false,
    byteLength: cleanHtml.length,
    redirectChain: [],
    resolvedIp: '93.184.216.34',
    tlsAuthorized: true,
    durationMs: 25,
    ...overrides.http,
  };

  const isHtml = overrides.isHtml ?? true;
  const $ = isHtml ? cheerio.load(http.body) : null;
  const wpSignals = overrides.wpSignals ?? detectWordPressFootprint(http, $);

  return {
    inputUrl: 'https://clean-example.com',
    normalizedUrl: 'https://clean-example.com/',
    parsedInitialUrl: parsed,
    parsedFinalUrl: parsed,
    hostname: 'clean-example.com',
    deadlineMs: Date.now() + 15_000,
    tls: {
      attempted: true,
      connected: true,
      authorized: true,
      isExpired: false,
      isSelfSigned: false,
      hostnameMismatch: false,
      chainError: false,
      ...overrides.tls,
    },
    http,
    httpToHttpsCheck: {
      attempted: true,
      enforcesHttps: true,
      redirectedToHttps: true,
      httpAccessibleWithoutRedirect: false,
      statusCode: 301,
    },
    $,
    isHtml,
    isWordPress: overrides.isWordPress ?? wpSignals.length > 0,
    wpSignals,
    client: overrides.client ?? makeMockClient(),
    ...overrides,
  };
}

test('clean website produces zero errors', async () => {
  const ctx = makeCleanContext();
  const report = await evaluateScanContext(ctx);
  assert.deepEqual(report.errors, []);
});

test('returns 1 highest-priority error per website while ignoring removed categories', async () => {
  const brokenHtml = `<!doctype html>
<html>
  <head>
    <meta name="generator" content="WordPress 6.5.2" />
    <link rel="stylesheet" href="http://insecure.example.com/style.css" />
    <script>function broken( { return 1; }</script>
  </head>
  <body>
    <p>There has been a critical error on this website.</p>
    <b>Fatal error</b>: Call to undefined function my_missing_fn() in <b>/var/www/html/wp-content/themes/app/functions.php</b> on line <b>42</b>
    <img src="https://clean-example.com/missing.jpg" />
  </body>
</html>`;

  const client = makeMockClient({
    'https://clean-example.com/wp-json/': { statusCode: 500, body: 'Server Error' },
    'https://clean-example.com/missing.jpg': { statusCode: 404, body: '' },
    'http://insecure.example.com/style.css': { statusCode: 404, body: '' },
  });

  const ctx = makeCleanContext({
    http: {
      ok: false,
      initialUrl: 'https://clean-example.com/',
      finalUrl: 'https://clean-example.com/',
      statusCode: 500,
      statusMessage: 'Internal Server Error',
      headers: {
        'content-type': 'text/html',
        server: 'nginx/1.24.0',
      },
      body: brokenHtml,
      bodyTruncated: false,
      byteLength: brokenHtml.length,
      redirectChain: [],
      resolvedIp: '93.184.216.34',
      durationMs: 30,
    },
    tls: {
      attempted: true,
      connected: true,
      authorized: false,
      authorizationError: 'CERT_HAS_EXPIRED',
      isExpired: true,
      validTo: 'Jan 01 2024 GMT',
    },
    client,
  });

  const report = await evaluateScanContext(ctx);
  assert.deepEqual(report.errors, ['WordPress Critical Error (Publicly Exposed)']);
});

test('returns only 1 primary SSL error when hostname mismatch, verification failed, and HTTPS redirect errors all occur', async () => {
  const ctx = makeCleanContext({
    tls: {
      attempted: true,
      connected: true,
      authorized: false,
      authorizationError: 'ERR_TLS_CERT_ALTNAME_INVALID',
      hostnameMismatch: true,
    },
    httpToHttpsCheck: {
      attempted: true,
      enforcesHttps: false,
      redirectedToHttps: false,
      httpAccessibleWithoutRedirect: true,
      statusCode: 200,
    },
  });

  const report = await evaluateScanContext(ctx);
  assert.deepEqual(report.errors, ['SSL Certificate Hostname Mismatch']);
});

test('detects passive malware indicators as 1 error while ignoring removed server/directory listing checks', async () => {
  const suspiciousHtml = `<!doctype html>
<html>
  <head>
    <title>Index of /</title>
    <script>eval(atob("YWxlcnQoMSk="));</script>
  </head>
  <body>
    <h1>Index of /</h1>
    <iframe src="https://evil-tracker.xyz/frame.html" width="0" height="0"></iframe>
    <a href="db-backup.sql">db-backup.sql</a>
    <a href=".env">.env</a>
  </body>
</html>`;

  const ctx = makeCleanContext({
    http: {
      ok: true,
      initialUrl: 'https://clean-example.com/',
      finalUrl: 'https://clean-example.com/',
      statusCode: 200,
      statusMessage: 'OK',
      headers: {
        'content-type': 'text/html',
        'access-control-allow-origin': '*',
        'access-control-allow-credentials': 'true',
      },
      body: suspiciousHtml,
      bodyTruncated: false,
      byteLength: suspiciousHtml.length,
      redirectChain: [],
      resolvedIp: '93.184.216.34',
      durationMs: 20,
    },
  });

  const report = await evaluateScanContext(ctx);
  assert.deepEqual(report.errors, ['Suspicious JavaScript Detected']);

  // Verify a clean page with only removed-category signals produces 0 errors
  const removedOnlyHtml = `<!doctype html><html><head><title>Index of /</title><meta name="generator" content="WordPress 6.5.2" /><link rel="stylesheet" href="http://insecure.example.com/style.css" /></head><body><h1>Index of /</h1><a href=".env">.env</a></body></html>`;
  const removedOnlyCtx = makeCleanContext({
    http: {
      ok: true,
      initialUrl: 'https://clean-example.com/',
      finalUrl: 'https://clean-example.com/',
      statusCode: 200,
      statusMessage: 'OK',
      headers: { 'content-type': 'text/html', server: 'nginx/1.24.0' },
      body: removedOnlyHtml,
      bodyTruncated: false,
      byteLength: removedOnlyHtml.length,
      redirectChain: [],
      resolvedIp: '93.184.216.34',
      durationMs: 20,
    },
  });
  const removedOnlyReport = await evaluateScanContext(removedOnlyCtx);
  assert.deepEqual(removedOnlyReport.errors, []);
});

test('deduplicateErrorNames removes duplicate error names across active categories', () => {
  const unique = deduplicateErrorNames([
    { errorName: 'Website Compromise Indicator', detected: true, evidence: 'a', detectionMethod: 'm1', category: 'malware' },
    { errorName: 'Website Compromise Indicator', detected: true, evidence: 'b', detectionMethod: 'm2', category: 'malware' },
    { errorName: 'HTTP 404 – Not Found', detected: true, evidence: 'c', detectionMethod: 'm3', category: 'http' },
    { errorName: 'Ignored Undetected', detected: false, evidence: 'd', detectionMethod: 'm4', category: 'http' },
  ]);

  assert.deepEqual(unique, ['HTTP 404 – Not Found', 'Website Compromise Indicator']);
});

test('shows ONLY the actual public WordPress error message and ignores all other errors', async () => {
  const wpDieHtml = `<!doctype html>
<html>
  <body id="error-page">
    <div class="wp-die-message">
      <p>Your server is running PHP version 5.6.40 but WordPress 6.6 requires at least 7.2.24.</p>
    </div>
    <b>Fatal error</b>: Call to undefined function broken_fn() in <b>/var/www/html/index.php</b> on line <b>10</b>
  </body>
</html>`;

  const wpDieCtx = makeCleanContext({
    http: {
      ok: false,
      initialUrl: 'https://clean-example.com/',
      finalUrl: 'https://clean-example.com/',
      statusCode: 500,
      statusMessage: 'Internal Server Error',
      headers: { 'content-type': 'text/html' },
      body: wpDieHtml,
      bodyTruncated: false,
      byteLength: wpDieHtml.length,
      redirectChain: [],
      resolvedIp: '93.184.216.34',
      durationMs: 20,
    },
    tls: {
      attempted: true,
      connected: true,
      authorized: false,
      authorizationError: 'CERT_HAS_EXPIRED',
      isExpired: true,
    },
  });

  const wpDieReport = await evaluateScanContext(wpDieCtx);
  assert.deepEqual(wpDieReport.errors, [
    'Your server is running PHP version 5.6.40 but WordPress 6.6 requires at least 7.2.24.',
  ]);

  const dbErrHtml = `<!doctype html><html><body id="error-page"><h1>Error establishing a database connection</h1></body></html>`;
  const dbErrCtx = makeCleanContext({
    http: {
      ok: false,
      initialUrl: 'https://clean-example.com/',
      finalUrl: 'https://clean-example.com/',
      statusCode: 500,
      statusMessage: 'Internal Server Error',
      headers: { 'content-type': 'text/html' },
      body: dbErrHtml,
      bodyTruncated: false,
      byteLength: dbErrHtml.length,
      redirectChain: [],
      resolvedIp: '93.184.216.34',
      durationMs: 20,
    },
  });

  const dbErrReport = await evaluateScanContext(dbErrCtx);
  assert.deepEqual(dbErrReport.errors, ['Error establishing a database connection']);
});

test('detects White Screen / Blank Page for 0-byte, whitespace-only, and empty HTML responses without false positives on SPAs', async () => {
  // 1. 0-byte HTTP 200 (like pdas.org.au)
  const zeroByteCtx = makeCleanContext({
    isHtml: false,
    http: {
      ok: true,
      initialUrl: 'https://pdas.org.au/',
      finalUrl: 'https://pdas.org.au/',
      statusCode: 200,
      statusMessage: 'OK',
      headers: { 'content-type': 'application/json', 'content-length': '0' },
      body: '',
      bodyTruncated: false,
      byteLength: 0,
      redirectChain: [],
      resolvedIp: '93.184.216.34',
      durationMs: 20,
    },
  });
  const zeroByteReport = await evaluateScanContext(zeroByteCtx);
  assert.deepEqual(zeroByteReport.errors, ['White Screen / Blank Page']);

  // 2. Whitespace/comment-only HTTP 200
  const whitespaceBody = '  \n <!-- cached --> \t ';
  const whitespaceCtx = makeCleanContext({
    http: {
      ok: true,
      initialUrl: 'https://clean-example.com/',
      finalUrl: 'https://clean-example.com/',
      statusCode: 200,
      statusMessage: 'OK',
      headers: { 'content-type': 'text/html' },
      body: whitespaceBody,
      bodyTruncated: false,
      byteLength: whitespaceBody.length,
      redirectChain: [],
      resolvedIp: '93.184.216.34',
      durationMs: 20,
    },
  });
  const whitespaceReport = await evaluateScanContext(whitespaceCtx);
  assert.deepEqual(whitespaceReport.errors, ['White Screen / Blank Page']);

  // 3. Empty HTML shell with no visible text, media, or scripts
  const emptyHtml = '<!doctype html><html><head><title>Blank</title></head><body><div></div></body></html>';
  const emptyHtmlCtx = makeCleanContext({
    http: {
      ok: true,
      initialUrl: 'https://clean-example.com/',
      finalUrl: 'https://clean-example.com/',
      statusCode: 200,
      statusMessage: 'OK',
      headers: { 'content-type': 'text/html' },
      body: emptyHtml,
      bodyTruncated: false,
      byteLength: emptyHtml.length,
      redirectChain: [],
      resolvedIp: '93.184.216.34',
      durationMs: 20,
    },
  });
  const emptyHtmlReport = await evaluateScanContext(emptyHtmlCtx);
  assert.deepEqual(emptyHtmlReport.errors, ['White Screen / Blank Page']);

  // 4. Client-rendered SPA with <script> tag must NOT false-positive
  const spaHtml = '<!doctype html><html><head><title>App</title></head><body><div id="root"></div><script type="module" src="/assets/index.js"></script></body></html>';
  const spaCtx = makeCleanContext({
    http: {
      ok: true,
      initialUrl: 'https://clean-example.com/',
      finalUrl: 'https://clean-example.com/',
      statusCode: 200,
      statusMessage: 'OK',
      headers: { 'content-type': 'text/html' },
      body: spaHtml,
      bodyTruncated: false,
      byteLength: spaHtml.length,
      redirectChain: [],
      resolvedIp: '93.184.216.34',
      durationMs: 20,
    },
  });
  const spaReport = await evaluateScanContext(spaCtx);
  assert.deepEqual(spaReport.errors, []);
});

test('prioritizes browser-blocking SSL certificate errors over White Screen / Blank Page on 0-byte HTTP 200', async () => {
  const ctx = makeCleanContext({
    isHtml: false,
    http: {
      ok: true,
      initialUrl: 'https://australiahomecare.com.au/',
      finalUrl: 'https://australiahomecare.com.au/',
      statusCode: 200,
      statusMessage: 'OK',
      headers: { 'content-type': 'text/html', 'content-length': '0' },
      body: '',
      bodyTruncated: false,
      byteLength: 0,
      redirectChain: [],
      resolvedIp: '35.189.53.189',
      tlsAuthorized: false,
      tlsAuthError: 'ERR_TLS_CERT_ALTNAME_INVALID',
      durationMs: 20,
    },
    tls: {
      attempted: true,
      connected: true,
      authorized: false,
      authorizationError: 'ERR_TLS_CERT_ALTNAME_INVALID',
      hostnameMismatch: true,
    },
  });

  const report = await evaluateScanContext(ctx);
  assert.deepEqual(report.errors, ['SSL Certificate Hostname Mismatch']);
});
