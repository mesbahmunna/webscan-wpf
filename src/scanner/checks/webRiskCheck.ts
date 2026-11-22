import type * as cheerio from 'cheerio';
import type { ScanCheckResult } from '../types.ts';

export const WEB_RISK_API_ENDPOINT = 'https://webrisk.googleapis.com/v1/uris:search';

export const WEB_RISK_THREAT_TYPES = [
  'MALWARE',
  'SOCIAL_ENGINEERING',
  'UNWANTED_SOFTWARE',
] as const;

export const SAFE_BROWSING_PLATFORM_TYPES = [
  'ANY_PLATFORM',
  'WINDOWS',
  'LINUX',
  'OSX',
  'ANDROID',
  'IOS',
] as const;

export type WebRiskThreatType = (typeof WEB_RISK_THREAT_TYPES)[number];

export const WEB_RISK_THREAT_NAME_MAP: Record<WebRiskThreatType, string> = {
  MALWARE: 'Malware Detected',
  SOCIAL_ENGINEERING: 'Social Engineering Detected',
  UNWANTED_SOFTWARE: 'Unwanted Software Detected',
};

const DEFAULT_WEB_RISK_TIMEOUT_MS = 6000;
const API_CHECK_TEST_URL = 'https://testsafebrowsing.appspot.com/s/malware.html';

let loggedMissingKeyWarning = false;

export interface WebRiskDiagnostic {
  configured: boolean;
  lastOutcome: 'not-run' | 'ok' | 'unconfigured' | 'http-error' | 'network-error';
  lastHttpStatus?: number;
  lastErrorStatus?: string;
  lastErrorMessage?: string;
}

export interface ApiStatusCheckResult {
  working: boolean;
  configured: boolean;
  provider?: 'Google Web Risk API' | 'Google Safe Browsing API v4';
  message: string;
  latencyMs: number;
}

let lastDiagnostic: Omit<WebRiskDiagnostic, 'configured'> = {
  lastOutcome: 'not-run',
};

interface WebRiskApiResponse {
  threat?: {
    threatTypes?: unknown;
    expireTime?: unknown;
  };
  error?: {
    code?: unknown;
    message?: unknown;
    status?: unknown;
  };
}

export interface WebRiskCheckOptions {
  apiKey?: string;
  timeoutMs?: number;
  fetchFn?: typeof fetch;
}

function getConfiguredWebRiskApiKey(overrideKey?: string): string {
  const raw =
    overrideKey !== undefined
      ? overrideKey
      : process.env.GOOGLE_WEB_RISK_API_KEY ??
        process.env.GOOGLE_WEBRISK_API_KEY ??
        process.env.WEB_RISK_API_KEY;
  if (typeof raw !== 'string') return '';
  let trimmed = raw.trim();
  // Strip accidental surrounding quotes pasted into environment variable UIs
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    trimmed = trimmed.slice(1, -1).trim();
  }
  // Treat obvious template placeholders as unconfigured
  if (!trimmed || trimmed === 'MY_GOOGLE_WEB_RISK_API_KEY') return '';
  return trimmed;
}

export function isWebRiskConfigured(): boolean {
  return getConfiguredWebRiskApiKey().length > 0;
}

export function getWebRiskDiagnostic(): WebRiskDiagnostic {
  return {
    configured: isWebRiskConfigured(),
    ...lastDiagnostic,
  };
}

export const SAFE_BROWSING_API_ENDPOINT =
  'https://safebrowsing.googleapis.com/v4/threatMatches:find';

interface SafeBrowsingApiResponse {
  matches?: Array<{
    threatType?: unknown;
  }>;
  error?: {
    code?: unknown;
    message?: unknown;
    status?: unknown;
  };
}

function mapThreatTypesToFindings(
  rawTypes: unknown[],
  detectionMethod: string,
  sourceLabel: string
): ScanCheckResult[] {
  const seen = new Set<WebRiskThreatType>();
  const results: ScanCheckResult[] = [];

  for (const entry of rawTypes) {
    if (typeof entry !== 'string') continue;
    const normalized = entry.trim().toUpperCase() as WebRiskThreatType;
    if (!(normalized in WEB_RISK_THREAT_NAME_MAP) || seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    results.push({
      errorName: WEB_RISK_THREAT_NAME_MAP[normalized],
      detected: true,
      evidence: `${sourceLabel} flagged URL for ${normalized}`,
      detectionMethod,
      category: 'malware',
    });
  }

  return results;
}

function normalizeHttpUrls(urls: string[], maxCount = 30): string[] {
  const seen = new Set<string>();
  const valid: string[] = [];

  for (const raw of urls) {
    if (typeof raw !== 'string') continue;
    const trimmed = raw.trim();
    if (!trimmed) continue;
    try {
      const parsed = new URL(trimmed);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') continue;
      parsed.hash = '';
      const normalized = parsed.toString();
      if (!seen.has(normalized)) {
        seen.add(normalized);
        valid.push(normalized);
        if (valid.length >= maxCount) break;
      }
    } catch {
      // Skip invalid URLs
    }
  }

  return valid;
}

/**
 * Extracts prioritized embedded subresource URLs (iframes, scripts, stylesheets, images, embeds)
 * from a parsed HTML document so pages embedding malicious third-party or relative assets
 * (such as injected iframes or scripts) are also checked against Google's threat lists.
 */
export function extractSubresourceUrls(
  $: cheerio.CheerioAPI,
  baseUrl: string,
  limit = 25
): string[] {
  const rawCandidates: string[] = [];

  const collect = (selector: string, attr: string) => {
    $(selector).each((_, el) => {
      const val = $(el).attr(attr);
      if (val && val.trim()) {
        rawCandidates.push(val.trim());
      }
    });
  };

  // Prioritize highest-risk embedded vectors first
  collect('iframe[src]', 'src');
  collect('frame[src]', 'src');
  collect('script[src]', 'src');
  collect('link[rel~="stylesheet"][href]', 'href');
  collect('object[data]', 'data');
  collect('embed[src]', 'src');
  collect('img[src]', 'src');

  // Also capture statically assigned asset URLs inside inline scripts (e.g., el.src = "...")
  $('script:not([src])').each((_, el) => {
    const code = $(el).text();
    if (!code) return;
    const regex = /\.(?:src|href)\s*=\s*['"]([^'"\s<>]{3,300})['"]/gi;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(code)) !== null) {
      if (match[1]) {
        rawCandidates.push(match[1].trim());
      }
    }
  });

  let normalizedBase = baseUrl;
  try {
    const parsedBase = new URL(baseUrl);
    parsedBase.hash = '';
    normalizedBase = parsedBase.toString();
  } catch {
    return [];
  }

  const resolved: string[] = [];
  const seen = new Set<string>([normalizedBase]);

  for (const candidate of rawCandidates) {
    if (/^(?:data|javascript|mailto|tel|blob|about):/i.test(candidate)) continue;
    try {
      const abs = new URL(candidate, normalizedBase);
      if (abs.protocol !== 'http:' && abs.protocol !== 'https:') continue;
      abs.hash = '';
      const str = abs.toString();
      if (!seen.has(str)) {
        seen.add(str);
        resolved.push(str);
        if (resolved.length >= limit) break;
      }
    } catch {
      // Ignore malformed attribute values
    }
  }

  return resolved;
}

async function querySafeBrowsingBatch(
  validatedUris: string[],
  apiKey: string,
  fetchFn: typeof fetch,
  signal: AbortSignal
): Promise<{ ok: boolean; status: number; findings: ScanCheckResult[]; detail?: string }> {
  const response = await fetchFn(SAFE_BROWSING_API_ENDPOINT, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'X-Goog-Api-Key': apiKey,
    },
    body: JSON.stringify({
      client: {
        clientId: 'wordpressfixer-scanner',
        clientVersion: '1.0.0',
      },
      threatInfo: {
        threatTypes: [...WEB_RISK_THREAT_TYPES],
        platformTypes: [...SAFE_BROWSING_PLATFORM_TYPES],
        threatEntryTypes: ['URL'],
        threatEntries: validatedUris.map((url) => ({ url })),
      },
    }),
    signal,
  });

  if (!response.ok) {
    let detail = response.statusText || 'Unknown error';
    try {
      const errPayload = (await response.json()) as SafeBrowsingApiResponse;
      if (typeof errPayload?.error?.message === 'string' && errPayload.error.message.trim()) {
        const statusLabel =
          typeof errPayload.error.status === 'string' ? `${errPayload.error.status}: ` : '';
        detail = `${statusLabel}${errPayload.error.message.trim()}`;
      }
    } catch {
      // Ignore non-JSON error bodies
    }
    return { ok: false, status: response.status, findings: [], detail };
  }

  const data = (await response.json()) as SafeBrowsingApiResponse;
  const rawTypes = Array.isArray(data?.matches)
    ? data.matches.map((m) => m?.threatType)
    : [];
  return {
    ok: true,
    status: response.status,
    findings: mapThreatTypesToFindings(
      rawTypes,
      'google-safe-browsing-api',
      'Google Safe Browsing'
    ),
  };
}

async function queryWebRiskSingle(
  validatedUri: string,
  apiKey: string,
  fetchFn: typeof fetch,
  signal: AbortSignal
): Promise<{
  ok: boolean;
  status: number;
  findings: ScanCheckResult[];
  errStatus?: string;
  errMessage?: string;
}> {
  const endpoint = new URL(WEB_RISK_API_ENDPOINT);
  for (const threatType of WEB_RISK_THREAT_TYPES) {
    endpoint.searchParams.append('threatTypes', threatType);
  }
  endpoint.searchParams.set('uri', validatedUri);

  const response = await fetchFn(endpoint.toString(), {
    method: 'GET',
    headers: {
      Accept: 'application/json',
      'X-Goog-Api-Key': apiKey,
    },
    signal,
  });

  if (!response.ok) {
    let errStatus: string | undefined;
    let errMessage = response.statusText || 'Unknown error';
    try {
      const errPayload = (await response.json()) as WebRiskApiResponse;
      if (typeof errPayload?.error?.status === 'string' && errPayload.error.status.trim()) {
        errStatus = errPayload.error.status.trim();
      }
      if (typeof errPayload?.error?.message === 'string' && errPayload.error.message.trim()) {
        errMessage = errPayload.error.message.trim();
      }
    } catch {
      // Ignore non-JSON error bodies
    }
    return {
      ok: false,
      status: response.status,
      findings: [],
      errStatus,
      errMessage,
    };
  }

  const data = (await response.json()) as WebRiskApiResponse;
  const rawTypes = data?.threat?.threatTypes;
  const findings =
    Array.isArray(rawTypes) && rawTypes.length > 0
      ? mapThreatTypesToFindings(rawTypes, 'google-web-risk-api', 'Google Web Risk')
      : [];

  return { ok: true, status: response.status, findings };
}

const SAFE_BROWSING_FALLBACK_TTL_MS = 10 * 60 * 1000;
let preferSafeBrowsingUntil = 0;

/**
 * Checks a batch of URLs (main page + optional redirects/embedded subresources)
 * against Google Web Risk API v1, with automatic fallback to Google Safe Browsing API v4
 * if Web Risk returns HTTP 403.
 */
export async function runWebRiskBatchCheck(
  urls: string[],
  options: WebRiskCheckOptions = {}
): Promise<ScanCheckResult[]> {
  const isProdRuntimeCall = options.apiKey === undefined && options.fetchFn === undefined;
  const apiKey = getConfiguredWebRiskApiKey(options.apiKey);
  if (!apiKey) {
    if (isProdRuntimeCall) {
      lastDiagnostic = { lastOutcome: 'unconfigured' };
      if (!loggedMissingKeyWarning) {
        loggedMissingKeyWarning = true;
        console.warn('[WebRisk] GOOGLE_WEB_RISK_API_KEY is not configured; skipping Web Risk lookup.');
      }
    }
    return [];
  }

  const validatedUris = normalizeHttpUrls(urls, 30);
  if (validatedUris.length === 0) {
    return [];
  }

  const timeoutMs = options.timeoutMs ?? DEFAULT_WEB_RISK_TIMEOUT_MS;
  const fetchFn = options.fetchFn ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    if (isProdRuntimeCall && Date.now() < preferSafeBrowsingUntil) {
      const sbRes = await querySafeBrowsingBatch(
        validatedUris,
        apiKey,
        fetchFn,
        controller.signal
      );
      if (sbRes.ok) {
        lastDiagnostic = { lastOutcome: 'ok', lastHttpStatus: sbRes.status };
        return sbRes.findings;
      }
      preferSafeBrowsingUntil = 0;
    }

    const primaryRes = await queryWebRiskSingle(
      validatedUris[0],
      apiKey,
      fetchFn,
      controller.signal
    );

    if (!primaryRes.ok) {
      const detail = primaryRes.errStatus
        ? `${primaryRes.errStatus}: ${primaryRes.errMessage || 'Unknown error'}`
        : primaryRes.errMessage || 'Unknown error';

      if (primaryRes.status === 403) {
        const fallback = await querySafeBrowsingBatch(
          validatedUris,
          apiKey,
          fetchFn,
          controller.signal
        );
        if (fallback.ok) {
          if (isProdRuntimeCall) {
            preferSafeBrowsingUntil = Date.now() + SAFE_BROWSING_FALLBACK_TTL_MS;
            lastDiagnostic = {
              lastOutcome: 'ok',
              lastHttpStatus: fallback.status,
            };
          }
          return fallback.findings;
        }
        console.warn(
          `[WebRisk] API returned HTTP 403 (${detail}); Safe Browsing v4 fallback returned HTTP ${fallback.status} (${fallback.detail || 'error'})`
        );
      } else {
        console.warn(`[WebRisk] API returned HTTP ${primaryRes.status}: ${detail}`);
      }

      if (isProdRuntimeCall) {
        lastDiagnostic = {
          lastOutcome: 'http-error',
          lastHttpStatus: primaryRes.status,
          lastErrorStatus: primaryRes.errStatus,
          lastErrorMessage: primaryRes.errMessage,
        };
      }
      return [];
    }

    if (isProdRuntimeCall) {
      lastDiagnostic = {
        lastOutcome: 'ok',
        lastHttpStatus: primaryRes.status,
      };
    }

    if (primaryRes.findings.length > 0 || validatedUris.length === 1) {
      return primaryRes.findings;
    }

    // Check up to 8 additional subresource URLs in parallel against Web Risk v1
    const extraUris = validatedUris.slice(1, 9);
    const extraSettled = await Promise.allSettled(
      extraUris.map((uri) => queryWebRiskSingle(uri, apiKey, fetchFn, controller.signal))
    );

    const combined: ScanCheckResult[] = [];
    const seenNames = new Set<string>();
    for (const outcome of extraSettled) {
      if (outcome.status === 'fulfilled' && outcome.value.ok) {
        for (const finding of outcome.value.findings) {
          if (!seenNames.has(finding.errorName)) {
            seenNames.add(finding.errorName);
            combined.push(finding);
          }
        }
      }
    }

    return combined;
  } catch (err) {
    const reason = err instanceof Error ? `${err.name}: ${err.message}` : 'Request failed';
    if (isProdRuntimeCall) {
      lastDiagnostic = {
        lastOutcome: 'network-error',
        lastErrorMessage: reason,
      };
    }
    console.warn(`[WebRisk] Lookup failed gracefully (${reason})`);
    return [];
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Queries Google Web Risk Lookup API (v1/uris:search) for a single URL,
 * with automatic fallback to Google Safe Browsing API v4 on HTTP 403.
 */
export async function runWebRiskCheck(
  targetUrl: string,
  options: WebRiskCheckOptions = {}
): Promise<ScanCheckResult[]> {
  return runWebRiskBatchCheck([targetUrl], options);
}

/**
 * Performs a live backend verification against Google's official malware test URL
 * to confirm whether the configured API key is active and detecting threats.
 * Never exposes the API key in its response.
 */
export async function verifyGoogleThreatApiStatus(
  options: WebRiskCheckOptions = {}
): Promise<ApiStatusCheckResult> {
  const startMs = Date.now();
  const apiKey = getConfiguredWebRiskApiKey(options.apiKey);
  if (!apiKey) {
    return {
      working: false,
      configured: false,
      message: 'API key is not configured (set GOOGLE_WEB_RISK_API_KEY in environment variables).',
      latencyMs: Date.now() - startMs,
    };
  }

  const timeoutMs = options.timeoutMs ?? DEFAULT_WEB_RISK_TIMEOUT_MS;
  const fetchFn = options.fetchFn ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const wrRes = await queryWebRiskSingle(API_CHECK_TEST_URL, apiKey, fetchFn, controller.signal);
    if (wrRes.ok) {
      const detectedMalware = wrRes.findings.some((f) => f.errorName === 'Malware Detected');
      return {
        working: detectedMalware,
        configured: true,
        provider: 'Google Web Risk API',
        message: detectedMalware
          ? 'Google Web Risk API is working properly.'
          : 'Google Web Risk API responded, but did not flag the malware test URL.',
        latencyMs: Date.now() - startMs,
      };
    }

    if (wrRes.status === 403) {
      const sbRes = await querySafeBrowsingBatch(
        [API_CHECK_TEST_URL],
        apiKey,
        fetchFn,
        controller.signal
      );
      if (sbRes.ok) {
        const detectedMalware = sbRes.findings.some((f) => f.errorName === 'Malware Detected');
        return {
          working: detectedMalware,
          configured: true,
          provider: 'Google Safe Browsing API v4',
          message: detectedMalware
            ? 'Google Safe Browsing API v4 is working properly.'
            : 'Google Safe Browsing API v4 responded, but did not flag the malware test URL.',
          latencyMs: Date.now() - startMs,
        };
      }
      return {
        working: false,
        configured: true,
        message: `API rejected (HTTP ${wrRes.status}): ${wrRes.errMessage || sbRes.detail || 'Permission denied. Enable Web Risk API or Safe Browsing API in Google Cloud.'}`,
        latencyMs: Date.now() - startMs,
      };
    }

    return {
      working: false,
      configured: true,
      message: `API error (HTTP ${wrRes.status}): ${wrRes.errMessage || 'Check your API key configuration.'}`,
      latencyMs: Date.now() - startMs,
    };
  } catch (err) {
    const reason = err instanceof Error ? err.message : 'Network or timeout error';
    return {
      working: false,
      configured: true,
      message: `Could not reach Google API (${reason}).`,
      latencyMs: Date.now() - startMs,
    };
  } finally {
    clearTimeout(timer);
  }
}

export const GOOGLE_SITE_STATUS_ENDPOINT =
  'https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status';

export interface SiteStatusCheckOptions {
  timeoutMs?: number;
  fetchFn?: typeof fetch;
}

/**
 * Checks Google Safe Browsing Site Status (the same site-level index used by
 * Google Transparency Report) to catch domain-wide or "Some pages on this site are unsafe"
 * warnings (status 2 = Unsafe, status 3 = Partially Unsafe) that exact-URL lookup APIs
 * do not return when a different page on the same domain is compromised.
 *
 * Fails completely gracefully on any network, timeout, rate-limit, or format issue.
 */
export async function runGoogleSiteStatusCheck(
  targetUrl: string,
  options: SiteStatusCheckOptions = {}
): Promise<ScanCheckResult[]> {
  let validatedUri: string;
  try {
    const parsed = new URL(targetUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return [];
    }
    parsed.hash = '';
    validatedUri = parsed.toString();
  } catch {
    return [];
  }

  const endpoint = `${GOOGLE_SITE_STATUS_ENDPOINT}?site=${encodeURIComponent(validatedUri)}`;
  const timeoutMs = options.timeoutMs ?? 2500;
  const fetchFn = options.fetchFn ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetchFn(endpoint, {
      method: 'GET',
      headers: {
        Accept: 'application/json, text/plain, */*',
      },
      signal: controller.signal,
    });

    if (!response.ok) {
      return [];
    }

    const rawText = await response.text();
    // Strip Google XSSI prefix ")]}'\n"
    const cleaned = rawText.replace(/^\)\]\}'\s*/, '').trim();
    if (!cleaned) return [];

    const parsed = JSON.parse(cleaned) as unknown;
    if (!Array.isArray(parsed) || !Array.isArray(parsed[0])) {
      return [];
    }

    const row = parsed[0] as unknown[];
    if (row[0] !== 'sb.ssr') {
      return [];
    }

    const statusCode = typeof row[1] === 'number' ? row[1] : 0;
    // 2 = Unsafe, 3 = Partially Unsafe ("Some pages on this site are unsafe")
    if (statusCode !== 2 && statusCode !== 3) {
      return [];
    }

    const hasMalware = row[2] === true;
    const hasUnwanted = row[3] === true;
    const hasSocialEngineering = row[4] === true;

    const detectedTypes: WebRiskThreatType[] = [];
    if (hasMalware) detectedTypes.push('MALWARE');
    if (hasSocialEngineering) detectedTypes.push('SOCIAL_ENGINEERING');
    if (hasUnwanted) detectedTypes.push('UNWANTED_SOFTWARE');

    if (detectedTypes.length > 0) {
      return mapThreatTypesToFindings(
        detectedTypes,
        'google-safe-browsing-site-status',
        'Google Safe Browsing Site Status'
      );
    }

    return [
      {
        errorName: 'Unsafe Site Detected',
        detected: true,
        evidence: `Google Safe Browsing Site Status flagged site (status ${statusCode})`,
        detectionMethod: 'google-safe-browsing-site-status',
        category: 'malware',
      },
    ];
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}
