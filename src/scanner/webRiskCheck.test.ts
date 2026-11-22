import test from 'node:test';
import assert from 'node:assert/strict';
import * as cheerio from 'cheerio';
import {
  runWebRiskCheck,
  WEB_RISK_API_ENDPOINT,
  WEB_RISK_THREAT_TYPES,
} from './checks/webRiskCheck.ts';
import { evaluateScanContext } from './engine.ts';
import type { HttpFetchResult, SafeHttpClient, ScanContext } from './types.ts';

function makeMinimalContext(overrides: Partial<ScanContext> = {}): ScanContext {
  const html = '<!doctype html><html><head><title>Test</title></head><body>OK</body></html>';
  const parsed = new URL('https://example.com/');
  const http: HttpFetchResult = {
    ok: true,
    initialUrl: 'https://example.com/',
    finalUrl: 'https://example.com/',
    statusCode: 200,
    statusMessage: 'OK',
    headers: { 'content-type': 'text/html' },
    body: html,
    bodyTruncated: false,
    byteLength: html.length,
    redirectChain: [],
    resolvedIp: '93.184.216.34',
    tlsAuthorized: true,
    durationMs: 10,
    ...overrides.http,
  };

  const client: SafeHttpClient = {
    async fetch(url) {
      return { ...http, initialUrl: url, finalUrl: url };
    },
  };

  return {
    inputUrl: 'https://example.com',
    normalizedUrl: 'https://example.com/',
    parsedInitialUrl: parsed,
    parsedFinalUrl: parsed,
    hostname: 'example.com',
    deadlineMs: Date.now() + 10_000,
    tls: { attempted: true, connected: true, authorized: true },
    http,
    httpToHttpsCheck: {
      attempted: true,
      enforcesHttps: true,
      redirectedToHttps: true,
      httpAccessibleWithoutRedirect: false,
      statusCode: 301,
    },
    $: cheerio.load(html),
    isHtml: true,
    isWordPress: false,
    wpSignals: [],
    client,
    ...overrides,
  };
}

test('runWebRiskCheck queries Google Web Risk v1 with all 3 threat types and backend X-Goog-Api-Key header', async () => {
  let capturedUrl = '';
  let capturedHeaders: HeadersInit | undefined;

  const mockFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    capturedUrl = String(input);
    capturedHeaders = init?.headers;
    return new Response(
      JSON.stringify({
        threat: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'MALWARE', 'UNWANTED_SOFTWARE', 'UNKNOWN_TYPE'],
          expireTime: '2026-12-01T00:00:00Z',
        },
      }),
      { status: 200, headers: { 'content-type': 'application/json' } }
    );
  }) as typeof fetch;

  const findings = await runWebRiskCheck('https://testsafebrowsing.appspot.com/s/malware.html', {
    apiKey: 'test-backend-secret-key',
    fetchFn: mockFetch,
  });

  const parsedRequest = new URL(capturedUrl);
  assert.equal(`${parsedRequest.origin}${parsedRequest.pathname}`, WEB_RISK_API_ENDPOINT);
  assert.deepEqual(parsedRequest.searchParams.getAll('threatTypes'), [...WEB_RISK_THREAT_TYPES]);
  assert.equal(
    parsedRequest.searchParams.get('uri'),
    'https://testsafebrowsing.appspot.com/s/malware.html'
  );
  // Key must never appear in query string
  assert.equal(parsedRequest.searchParams.get('key'), null);
  assert.equal(
    (capturedHeaders as Record<string, string>)['X-Goog-Api-Key'],
    'test-backend-secret-key'
  );

  // Deduplicated and mapped strictly to clean threat names
  assert.deepEqual(
    findings.map((f) => f.errorName),
    ['Malware Detected', 'Social Engineering Detected', 'Unwanted Software Detected']
  );
});

test('runWebRiskCheck returns empty array when URL is clean ({})', async () => {
  const mockFetch = (async () =>
    new Response(JSON.stringify({}), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })) as typeof fetch;

  const findings = await runWebRiskCheck('https://example.com/', {
    apiKey: 'test-key',
    fetchFn: mockFetch,
  });

  assert.deepEqual(findings, []);
});

test('runWebRiskCheck skips gracefully when API key is missing or placeholder', async () => {
  let called = false;
  const mockFetch = (async () => {
    called = true;
    return new Response('{}', { status: 200 });
  }) as typeof fetch;

  const missingKeyResult = await runWebRiskCheck('https://example.com/', {
    apiKey: '',
    fetchFn: mockFetch,
  });
  const placeholderKeyResult = await runWebRiskCheck('https://example.com/', {
    apiKey: 'MY_GOOGLE_WEB_RISK_API_KEY',
    fetchFn: mockFetch,
  });

  assert.equal(called, false);
  assert.deepEqual(missingKeyResult, []);
  assert.deepEqual(placeholderKeyResult, []);
});

test('runWebRiskCheck handles HTTP errors, network failures, invalid JSON, and timeouts gracefully', async () => {
  const httpErr = await runWebRiskCheck('https://example.com/', {
    apiKey: 'test-key',
    fetchFn: (async () => new Response('Forbidden', { status: 403 })) as typeof fetch,
  });
  assert.deepEqual(httpErr, []);

  const networkErr = await runWebRiskCheck('https://example.com/', {
    apiKey: 'test-key',
    fetchFn: (async () => {
      throw new Error('ECONNREFUSED');
    }) as typeof fetch,
  });
  assert.deepEqual(networkErr, []);

  const badJson = await runWebRiskCheck('https://example.com/', {
    apiKey: 'test-key',
    fetchFn: (async () => new Response('not-json', { status: 200 })) as typeof fetch,
  });
  assert.deepEqual(badJson, []);

  const timedOut = await runWebRiskCheck('https://example.com/', {
    apiKey: 'test-key',
    timeoutMs: 25,
    fetchFn: (async (_input: RequestInfo | URL, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          reject(new DOMException('Aborted', 'AbortError'));
        });
      })) as typeof fetch,
  });
  assert.deepEqual(timedOut, []);
});

test('evaluateScanContext displays only deduplicated Google Web Risk threat names when flagged and preserves existing checks otherwise', async () => {
  const flaggedCtx = makeMinimalContext({
    httpToHttpsCheck: {
      attempted: true,
      enforcesHttps: false,
      redirectedToHttps: false,
      httpAccessibleWithoutRedirect: true,
      statusCode: 200,
    },
    webRiskFindings: [
      {
        errorName: 'Malware Detected',
        detected: true,
        evidence: 'Google Web Risk flagged URL for MALWARE',
        detectionMethod: 'google-web-risk-api',
        category: 'malware',
      },
      {
        errorName: 'Malware Detected',
        detected: true,
        evidence: 'Duplicate threat entry',
        detectionMethod: 'google-web-risk-api',
        category: 'malware',
      },
      {
        errorName: 'Social Engineering Detected',
        detected: true,
        evidence: 'Google Web Risk flagged URL for SOCIAL_ENGINEERING',
        detectionMethod: 'google-web-risk-api',
        category: 'malware',
      },
    ],
  });

  const flaggedReport = await evaluateScanContext(flaggedCtx);
  assert.deepEqual(flaggedReport.errors, ['Malware Detected', 'Social Engineering Detected']);

  // When Web Risk returns no threats, existing scanner behavior remains unchanged
  const normalCtx = makeMinimalContext({
    httpToHttpsCheck: {
      attempted: true,
      enforcesHttps: false,
      redirectedToHttps: false,
      httpAccessibleWithoutRedirect: true,
      statusCode: 200,
    },
    webRiskFindings: [],
  });

  const normalReport = await evaluateScanContext(normalCtx);
  assert.deepEqual(normalReport.errors, ['HTTP to HTTPS Redirect Missing']);
});

test('testsafebrowsing.appspot.com test URLs map accurately to Malware, Social Engineering, Unwanted Software, and Safe', async () => {
  const simulatedWebRiskCatalog: Record<string, string[]> = {
    'https://testsafebrowsing.appspot.com/': [],
    'https://testsafebrowsing.appspot.com/s/malware.html': ['MALWARE'],
    'https://testsafebrowsing.appspot.com/s/phishing.html': ['SOCIAL_ENGINEERING'],
    'https://testsafebrowsing.appspot.com/s/unwanted.html': ['UNWANTED_SOFTWARE'],
  };

  const mockFetch = (async (input: RequestInfo | URL) => {
    const reqUrl = new URL(String(input));
    const queriedUri = reqUrl.searchParams.get('uri') || '';
    const threatTypes = simulatedWebRiskCatalog[queriedUri] ?? [];
    const payload =
      threatTypes.length > 0
        ? { threat: { threatTypes, expireTime: '2026-12-01T00:00:00Z' } }
        : {};
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;

  const cases: Array<{ url: string; expected: string[] }> = [
    { url: 'https://testsafebrowsing.appspot.com/', expected: [] },
    { url: 'https://testsafebrowsing.appspot.com/s/malware.html', expected: ['Malware Detected'] },
    {
      url: 'https://testsafebrowsing.appspot.com/s/phishing.html',
      expected: ['Social Engineering Detected'],
    },
    {
      url: 'https://testsafebrowsing.appspot.com/s/unwanted.html',
      expected: ['Unwanted Software Detected'],
    },
  ];

  for (const testCase of cases) {
    const webRiskFindings = await runWebRiskCheck(testCase.url, {
      apiKey: 'test-web-risk-key',
      fetchFn: mockFetch,
    });
    const ctx = makeMinimalContext({
      inputUrl: testCase.url,
      normalizedUrl: testCase.url,
      parsedInitialUrl: new URL(testCase.url),
      parsedFinalUrl: new URL(testCase.url),
      hostname: 'testsafebrowsing.appspot.com',
      webRiskFindings,
    });
    const report = await evaluateScanContext(ctx);
    assert.deepEqual(report.errors, testCase.expected, `Failed for ${testCase.url}`);
  }
});

test('runWebRiskCheck strips accidental surrounding quotes from API keys', async () => {
  let sentKey = '';
  const mockFetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    sentKey = (init?.headers as Record<string, string>)['X-Goog-Api-Key'] || '';
    return new Response(
      JSON.stringify({ threat: { threatTypes: ['MALWARE'] } }),
      { status: 200, headers: { 'content-type': 'application/json' } }
    );
  }) as typeof fetch;

  const findings = await runWebRiskCheck('https://testsafebrowsing.appspot.com/s/malware.html', {
    apiKey: '  "AIzaQuotedTestKey123"  ',
    fetchFn: mockFetch,
  });

  assert.equal(sentKey, 'AIzaQuotedTestKey123');
  assert.deepEqual(
    findings.map((f) => f.errorName),
    ['Malware Detected']
  );
});

test('runWebRiskCheck automatically falls back to Safe Browsing API v4 when Web Risk returns 403', async () => {
  const calledUrls: string[] = [];
  const mockFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const urlStr = String(input);
    calledUrls.push(urlStr);
    if (urlStr.startsWith(WEB_RISK_API_ENDPOINT)) {
      return new Response(
        JSON.stringify({
          error: { code: 403, status: 'PERMISSION_DENIED', message: 'Permission denied on the service.' },
        }),
        { status: 403, headers: { 'content-type': 'application/json' } }
      );
    }
    assert.equal(init?.method, 'POST');
    assert.equal((init?.headers as Record<string, string>)['X-Goog-Api-Key'], 'safe-browsing-key');
    return new Response(
      JSON.stringify({
        matches: [
          { threatType: 'MALWARE' },
          { threatType: 'MALWARE' },
          { threatType: 'SOCIAL_ENGINEERING' },
        ],
      }),
      { status: 200, headers: { 'content-type': 'application/json' } }
    );
  }) as typeof fetch;

  const findings = await runWebRiskCheck('https://testsafebrowsing.appspot.com/s/malware.html', {
    apiKey: 'safe-browsing-key',
    fetchFn: mockFetch,
  });

  assert.equal(calledUrls.length, 2);
  assert.ok(calledUrls[0].startsWith(WEB_RISK_API_ENDPOINT));
  assert.ok(calledUrls[1].includes('safebrowsing.googleapis.com/v4/threatMatches:find'));
  assert.deepEqual(
    findings.map((f) => f.errorName),
    ['Malware Detected', 'Social Engineering Detected']
  );
});

