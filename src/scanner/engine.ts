import * as cheerio from 'cheerio';
import { createSafeHttpClient } from './httpClient.ts';
import { validateAndNormalizeUrl } from './security.ts';
import { runHttpChecks } from './checks/httpCheck.ts';
import { inspectTlsCertificate, runSslChecks } from './checks/sslCheck.ts';
import { detectWordPressFootprint, runWordPressChecks } from './checks/wordpressCheck.ts';
import { runPhpChecks } from './checks/phpCheck.ts';
import { runMalwareChecks } from './checks/malwareCheck.ts';
import {
  extractSubresourceUrls,
  runWebRiskBatchCheck,
  runWebRiskCheck,
} from './checks/webRiskCheck.ts';
import type {
  ScanCategory,
  ScanCheckResult,
  ScanContext,
  ScanInternalReport,
} from './types.ts';

const CATEGORY_ORDER: ScanCategory[] = [
  'http',
  'ssl',
  'wordpress',
  'php',
  'malware',
];

const OVERALL_SCAN_TIMEOUT_MS = 14_000;

export function deduplicateErrorNames(findings: ScanCheckResult[]): string[] {
  const categoryRank = new Map<ScanCategory, number>(
    CATEGORY_ORDER.map((cat, idx) => [cat, idx])
  );

  const detected = findings
    .filter((f) => f.detected && f.errorName.trim().length > 0)
    .sort((a, b) => {
      const rankA = categoryRank.get(a.category) ?? 99;
      const rankB = categoryRank.get(b.category) ?? 99;
      return rankA - rankB;
    });

  const seen = new Set<string>();
  const uniqueNames: string[] = [];
  for (const item of detected) {
    if (!seen.has(item.errorName)) {
      seen.add(item.errorName);
      uniqueNames.push(item.errorName);
    }
  }
  return uniqueNames;
}

const HIGH_PRIORITY_WP_ERRORS = new Set([
  'WordPress Critical Error (Publicly Exposed)',
  'WordPress Maintenance Mode Stuck',
  'WordPress Installation Page Exposed',
  'WordPress White Screen of Death (Possible)',
  'WordPress Configuration Information Exposed',
  'WordPress Debug Information Exposed',
]);

const HIGH_PRIORITY_PHP_ERRORS = new Set([
  'PHP Fatal Error Exposed',
  'PHP Parse Error Exposed',
  'PHP Memory Error Exposed',
  'PHP Uncaught Exception Exposed',
  'PHP Uncaught Error Exposed',
  'PHP Undefined Function Error Exposed',
]);

const HTTPS_ENFORCEMENT_ERRORS = new Set([
  'HTTPS Not Enforced',
  'HTTP to HTTPS Redirect Missing',
]);

function getFindingPriority(finding: ScanCheckResult): number {
  if (finding.detectionMethod === 'wp-public-error-message') return 1;

  // Network / socket / redirect reachability failures happen before page rendering
  if (
    finding.category === 'http' &&
    finding.detectionMethod !== 'http-status-code' &&
    finding.detectionMethod !== 'blank-page-detection'
  ) {
    return 2;
  }

  // Specific WordPress fatal/outage screens override generic HTTP 500/503
  if (finding.category === 'wordpress' && HIGH_PRIORITY_WP_ERRORS.has(finding.errorName)) return 3;

  // Specific fatal PHP errors override generic HTTP 500
  if (finding.category === 'php' && HIGH_PRIORITY_PHP_ERRORS.has(finding.errorName)) return 4;

  // Browser-blocking SSL/TLS certificate & handshake failures take precedence over
  // blank default responses or generic HTTP status codes served behind an invalid cert
  if (finding.category === 'ssl' && !HTTPS_ENFORCEMENT_ERRORS.has(finding.errorName)) {
    return finding.errorName === 'SSL Certificate Verification Failed' ? 5.5 : 5;
  }

  // White screen / blank pages and HTTP 4xx/5xx status errors
  if (finding.category === 'http') return 6;

  // Malware & compromise indicators
  if (finding.category === 'malware') return 7;

  // Non-fatal PHP warnings/notices and remaining WordPress issues
  if (finding.category === 'php' || finding.category === 'wordpress') return 8;

  // HTTPS enforcement / HTTP-to-HTTPS redirect missing
  if (HTTPS_ENFORCEMENT_ERRORS.has(finding.errorName)) return 9;

  return 10;
}

export function selectPrimaryError(findings: ScanCheckResult[]): ScanCheckResult | null {
  const detected = findings.filter((f) => f.detected && f.errorName.trim().length > 0);
  if (detected.length === 0) return null;

  let best = detected[0];
  let bestPriority = getFindingPriority(best);

  for (let i = 1; i < detected.length; i++) {
    const candidate = detected[i];
    const priority = getFindingPriority(candidate);
    if (priority < bestPriority) {
      best = candidate;
      bestPriority = priority;
    }
  }

  return best;
}

export async function evaluateScanContext(ctx: ScanContext): Promise<ScanInternalReport> {
  const syncFindings: ScanCheckResult[] = [
    ...runHttpChecks(ctx),
    ...runSslChecks(ctx),
    ...runPhpChecks(ctx),
    ...runMalwareChecks(ctx),
  ];

  // If the primary host could not be reached at all, skip secondary WordPress probes.
  const canRunSecondaryChecks = ctx.http.statusCode !== null;

  let asyncFindings: ScanCheckResult[] = [];
  if (canRunSecondaryChecks) {
    const settled = await Promise.allSettled([runWordPressChecks(ctx)]);
    for (const outcome of settled) {
      if (outcome.status === 'fulfilled') {
        asyncFindings = asyncFindings.concat(outcome.value);
      }
    }
  }

  const webRiskFindings = Array.isArray(ctx.webRiskFindings)
    ? ctx.webRiskFindings.filter((f) => f.detected && f.errorName.trim().length > 0)
    : [];

  if (webRiskFindings.length > 0) {
    const uniqueThreatNames = deduplicateErrorNames(webRiskFindings);
    return {
      scannedUrl: ctx.normalizedUrl,
      errors: uniqueThreatNames,
      findings: webRiskFindings,
    };
  }

  const allFindings = [...syncFindings, ...asyncFindings];
  const primary = selectPrimaryError(allFindings);

  return {
    scannedUrl: ctx.normalizedUrl,
    errors: primary ? [primary.errorName] : [],
    findings: primary ? [primary] : [],
  };
}

export async function scanWebsite(rawUrl: string): Promise<ScanInternalReport> {
  const validation = validateAndNormalizeUrl(rawUrl);
  if (!validation.valid || !validation.normalizedUrl || !validation.parsedUrl) {
    throw new Error(validation.error || 'Please enter a valid HTTP or HTTPS website URL.');
  }

  const normalizedUrl = validation.normalizedUrl;
  const parsedInitialUrl = validation.parsedUrl;
  const hostname = parsedInitialUrl.hostname;
  const deadlineMs = Date.now() + OVERALL_SCAN_TIMEOUT_MS;
  const client = createSafeHttpClient();

  // Phase 1: Primary HTTP fetch, TLS inspection, and Google Web Risk check in parallel
  const [httpResult, tlsInfo, webRiskFindings] = await Promise.all([
    client.fetch(normalizedUrl, {
      method: 'GET',
      timeoutMs: 6500,
      maxBytes: 1_500_000,
      maxRedirects: 7,
      followRedirects: true,
      rejectUnauthorized: false,
    }),
    inspectTlsCertificate(hostname, 4500),
    runWebRiskCheck(normalizedUrl),
  ]);

  let parsedFinalUrl = parsedInitialUrl;
  try {
    parsedFinalUrl = new URL(httpResult.finalUrl);
  } catch {
    parsedFinalUrl = parsedInitialUrl;
  }

  let effectiveTlsInfo = tlsInfo;
  if (
    parsedFinalUrl.protocol === 'https:' &&
    parsedFinalUrl.hostname.toLowerCase() !== hostname.toLowerCase() &&
    httpResult.tlsAuthorized === false &&
    tlsInfo.authorized &&
    Date.now() < deadlineMs - 2500
  ) {
    effectiveTlsInfo = await inspectTlsCertificate(parsedFinalUrl.hostname, 3500);
  }

  // Parse HTML once if response looks like HTML
  const contentType = String(httpResult.headers['content-type'] || '').toLowerCase();
  const bodyTrimmed = (httpResult.body || '').trimStart();
  const isHtml =
    Boolean(httpResult.body) &&
    (contentType.includes('text/html') ||
      contentType.includes('application/xhtml+xml') ||
      (!contentType && /^<(?:!doctype|html|head|body)/i.test(bodyTrimmed)));

  const $ = isHtml ? cheerio.load(httpResult.body) : null;

  // Check redirected final URL and embedded HTML subresources (iframes, scripts, stylesheets, images)
  // in a single batch call when the initial URL was not directly flagged
  let effectiveWebRiskFindings = webRiskFindings;
  if (effectiveWebRiskFindings.length === 0 && Date.now() < deadlineMs - 2000) {
    const secondaryThreatUrls: string[] = [];
    if (httpResult.finalUrl && httpResult.finalUrl !== normalizedUrl) {
      secondaryThreatUrls.push(httpResult.finalUrl);
    }
    if ($) {
      secondaryThreatUrls.push(
        ...extractSubresourceUrls($, httpResult.finalUrl || normalizedUrl, 25)
      );
    }
    if (secondaryThreatUrls.length > 0) {
      effectiveWebRiskFindings = await runWebRiskBatchCheck(secondaryThreatUrls, {
        timeoutMs: Math.min(3500, Math.max(500, deadlineMs - Date.now() - 800)),
      });
    }
  }

  // Phase 2: Passive HTTP -> HTTPS enforcement check (single non-redirected probe on http://)
  let httpToHttpsCheck: ScanContext['httpToHttpsCheck'] = undefined;
  if (httpResult.statusCode !== null && Date.now() < deadlineMs - 3000) {
    const httpProbeUrl = `http://${parsedFinalUrl.hostname}${parsedFinalUrl.pathname || '/'}`;
    const probeRes = await client.fetch(httpProbeUrl, {
      method: 'HEAD',
      timeoutMs: 3000,
      maxBytes: 1024,
      followRedirects: false,
    });

    const locRaw = probeRes.headers.location;
    const loc = Array.isArray(locRaw) ? locRaw[0] : locRaw || '';
    const isRedirectStatus =
      probeRes.statusCode !== null && [301, 302, 303, 307, 308].includes(probeRes.statusCode);
    const redirectedToHttps = isRedirectStatus && /^https:\/\//i.test(loc.trim());
    const httpAccessibleWithoutRedirect =
      probeRes.statusCode !== null && probeRes.statusCode >= 200 && probeRes.statusCode < 300;

    httpToHttpsCheck = {
      attempted: true,
      enforcesHttps: redirectedToHttps || probeRes.statusCode === null,
      redirectedToHttps,
      httpAccessibleWithoutRedirect,
      statusCode: probeRes.statusCode,
    };
  }

  const wpSignals = detectWordPressFootprint(httpResult, $);

  const ctx: ScanContext = {
    inputUrl: rawUrl,
    normalizedUrl,
    parsedInitialUrl,
    parsedFinalUrl,
    hostname,
    deadlineMs,
    tls: effectiveTlsInfo,
    http: httpResult,
    httpToHttpsCheck,
    $,
    isHtml,
    isWordPress: wpSignals.length > 0,
    wpSignals,
    client,
    webRiskFindings: effectiveWebRiskFindings,
  };

  return evaluateScanContext(ctx);
}
