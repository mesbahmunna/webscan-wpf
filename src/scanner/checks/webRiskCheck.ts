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

const DEFAULT_WEB_RISK_TIMEOUT_MS = 4000;

interface WebRiskApiResponse {
  threat?: {
    threatTypes?: unknown;
    expireTime?: unknown;
  };
}

export interface WebRiskCheckOptions {
  apiKey?: string;
  timeoutMs?: number;
  fetchFn?: typeof fetch;
}

function getConfiguredWebRiskApiKey(overrideKey?: string): string {
  const raw = overrideKey !== undefined ? overrideKey : process.env.GOOGLE_WEB_RISK_API_KEY;
  if (typeof raw !== 'string') return '';
  const trimmed = raw.trim();
  // Treat obvious template placeholders as unconfigured
  if (!trimmed || trimmed === 'MY_GOOGLE_WEB_RISK_API_KEY') return '';
  return trimmed;
}

/**
 * Queries Google Web Risk Lookup API (v1/uris:search) for MALWARE,
 * SOCIAL_ENGINEERING, and UNWANTED_SOFTWARE.
 *
 * - Keeps the API key strictly on the backend (sent via X-Goog-Api-Key header).
 * - Deduplicates detected threats and returns only clean threat names.
 * - Fails gracefully on missing credentials, timeouts, HTTP errors, or invalid JSON.
 */
export async function runWebRiskCheck(
  targetUrl: string,
  options: WebRiskCheckOptions = {}
): Promise<ScanCheckResult[]> {
  const apiKey = getConfiguredWebRiskApiKey(options.apiKey);
  if (!apiKey) {
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
    const response = await fetchFn(endpoint.toString(), {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'X-Goog-Api-Key': apiKey,
      },
      signal: controller.signal,
    });

    if (!response.ok) {
      return [];
    }

    const data = (await response.json()) as WebRiskApiResponse;
    const rawTypes = data?.threat?.threatTypes;
    if (!Array.isArray(rawTypes) || rawTypes.length === 0) {
      return [];
    }

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
        evidence: `Google Web Risk flagged URL for ${normalized}`,
        detectionMethod: 'google-web-risk-api',
        category: 'malware',
      });
    }

    return results;
  } catch {
    // Graceful fallback: never fail or stall a scan if Web Risk API is unreachable
    return [];
  } finally {
    clearTimeout(timer);
  }
}
