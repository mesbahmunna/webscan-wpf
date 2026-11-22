import type { ScanCheckResult } from '../types.ts';

export const WEB_RISK_API_ENDPOINT = 'https://webrisk.googleapis.com/v1/uris:search';

export const WEB_RISK_THREAT_TYPES = [
  'MALWARE',
  'SOCIAL_ENGINEERING',
  'UNWANTED_SOFTWARE',
] as const;

export type WebRiskThreatType = (typeof WEB_RISK_THREAT_TYPES)[number];

export const WEB_RISK_THREAT_NAME_MAP: Record<WebRiskThreatType, string> = {
  MALWARE: 'Malware Detected',
  SOCIAL_ENGINEERING: 'Social Engineering Detected',
  UNWANTED_SOFTWARE: 'Unwanted Software Detected',
};

const DEFAULT_WEB_RISK_TIMEOUT_MS = 6000;

let loggedMissingKeyWarning = false;

export interface WebRiskDiagnostic {
  configured: boolean;
  lastOutcome: 'not-run' | 'ok' | 'unconfigured' | 'http-error' | 'network-error';
  lastHttpStatus?: number;
  lastErrorStatus?: string;
  lastErrorMessage?: string;
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

async function querySafeBrowsingFallback(
  validatedUri: string,
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
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url: validatedUri }],
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

const SAFE_BROWSING_FALLBACK_TTL_MS = 10 * 60 * 1000;
let preferSafeBrowsingUntil = 0;

/**
 * Queries Google Web Risk Lookup API (v1/uris:search) for MALWARE,
 * SOCIAL_ENGINEERING, and UNWANTED_SOFTWARE.
 *
 * - Keeps the API key strictly on the backend (sent via X-Goog-Api-Key header).
 * - If Web Risk returns HTTP 403 (e.g., key is enabled for Safe Browsing API v4 instead),
 *   falls back to Google Safe Browsing Lookup API v4 with the same threat types.
 * - Deduplicates detected threats and returns only clean threat names.
 * - Fails gracefully on missing credentials, timeouts, HTTP errors, or invalid JSON.
 */
export async function runWebRiskCheck(
  targetUrl: string,
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

  let validatedUri: string;
  try {
    const parsed = new URL(targetUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return [];
    }
    validatedUri = parsed.toString();
  } catch {
    return [];
  }

  const endpoint = new URL(WEB_RISK_API_ENDPOINT);
  for (const threatType of WEB_RISK_THREAT_TYPES) {
    endpoint.searchParams.append('threatTypes', threatType);
  }
  endpoint.searchParams.set('uri', validatedUri);

  const timeoutMs = options.timeoutMs ?? DEFAULT_WEB_RISK_TIMEOUT_MS;
  const fetchFn = options.fetchFn ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    if (isProdRuntimeCall && Date.now() < preferSafeBrowsingUntil) {
      const sbRes = await querySafeBrowsingFallback(
        validatedUri,
        apiKey,
        fetchFn,
        controller.signal
      );
      if (sbRes.ok) {
        lastDiagnostic = { lastOutcome: 'ok', lastHttpStatus: sbRes.status };
        return sbRes.findings;
      }
      // Reset preference if Safe Browsing stopped succeeding
      preferSafeBrowsingUntil = 0;
    }

    const response = await fetchFn(endpoint.toString(), {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'X-Goog-Api-Key': apiKey,
      },
      signal: controller.signal,
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
      const detail = errStatus ? `${errStatus}: ${errMessage}` : errMessage;

      if (response.status === 403) {
        const fallback = await querySafeBrowsingFallback(
          validatedUri,
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
        console.warn(`[WebRisk] API returned HTTP ${response.status}: ${detail}`);
      }

      if (isProdRuntimeCall) {
        lastDiagnostic = {
          lastOutcome: 'http-error',
          lastHttpStatus: response.status,
          lastErrorStatus: errStatus,
          lastErrorMessage: errMessage,
        };
      }
      return [];
    }

    const data = (await response.json()) as WebRiskApiResponse;
    if (isProdRuntimeCall) {
      lastDiagnostic = {
        lastOutcome: 'ok',
        lastHttpStatus: response.status,
      };
    }

    const rawTypes = data?.threat?.threatTypes;
    if (!Array.isArray(rawTypes) || rawTypes.length === 0) {
      return [];
    }

    return mapThreatTypesToFindings(rawTypes, 'google-web-risk-api', 'Google Web Risk');
  } catch (err) {
    // Graceful fallback: never fail or stall a scan if Web Risk API is unreachable
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
