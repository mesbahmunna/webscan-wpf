import type { CheerioAPI } from 'cheerio';

export type ScanCategory =
  | 'http'
  | 'ssl'
  | 'wordpress'
  | 'php'
  | 'malware';

export interface ScanCheckResult {
  errorName: string;
  detected: boolean;
  evidence: string;
  detectionMethod: string;
  category: ScanCategory;
}

export interface RedirectHop {
  fromUrl: string;
  toUrl: string;
  statusCode: number;
  locationHeader: string;
}

export interface HttpFetchResult {
  ok: boolean;
  initialUrl: string;
  finalUrl: string;
  statusCode: number | null;
  statusMessage: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  bodyTruncated: boolean;
  byteLength: number;
  redirectChain: RedirectHop[];
  resolvedIp: string | null;
  errorCode?: string;
  errorMessage?: string;
  redirectIssue?:
    | 'too-many-redirects'
    | 'redirect-loop'
    | 'invalid-redirect'
    | 'broken-redirect'
    | 'blocked-redirect';
  tlsAuthorized?: boolean;
  tlsAuthError?: string;
  durationMs: number;
}

export interface TlsInspectionResult {
  attempted: boolean;
  connected: boolean;
  authorized: boolean;
  authorizationError?: string;
  errorCode?: string;
  errorMessage?: string;
  validFrom?: string;
  validTo?: string;
  isExpired?: boolean;
  isNotYetValid?: boolean;
  isSelfSigned?: boolean;
  hostnameMismatch?: boolean;
  chainError?: boolean;
  protocol?: string | null;
}

export interface SafeHttpClient {
  fetch: (
    targetUrl: string,
    options?: {
      method?: 'GET' | 'HEAD';
      timeoutMs?: number;
      maxBytes?: number;
      maxRedirects?: number;
      followRedirects?: boolean;
      rejectUnauthorized?: boolean;
    }
  ) => Promise<HttpFetchResult>;
}

export interface ScanContext {
  inputUrl: string;
  normalizedUrl: string;
  parsedInitialUrl: URL;
  parsedFinalUrl: URL;
  hostname: string;
  deadlineMs: number;
  tls: TlsInspectionResult;
  http: HttpFetchResult;
  httpToHttpsCheck?: {
    attempted: boolean;
    enforcesHttps: boolean;
    redirectedToHttps: boolean;
    httpAccessibleWithoutRedirect: boolean;
    statusCode: number | null;
  };
  $: CheerioAPI | null;
  isHtml: boolean;
  isWordPress: boolean;
  wpSignals: string[];
  client: SafeHttpClient;
  webRiskFindings?: ScanCheckResult[];
}

export interface ScanPublicResponse {
  scannedUrl: string;
  errors: string[];
}

export interface ScanInternalReport {
  scannedUrl: string;
  errors: string[];
  findings: ScanCheckResult[];
}
