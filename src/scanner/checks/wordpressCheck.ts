import type { CheerioAPI } from 'cheerio';
import type { HttpFetchResult, ScanCheckResult, ScanContext } from '../types';

export function detectWordPressFootprint(http: HttpFetchResult, $: CheerioAPI | null): string[] {
  const signals: string[] = [];
  const body = http.body || '';
  const headers = http.headers || {};

  const linkHeader = Array.isArray(headers.link) ? headers.link.join(', ') : String(headers.link || '');
  if (/rel=["']?https:\/\/api\.w\.org\/["']?/i.test(linkHeader)) {
    signals.push('header:api.w.org');
  }

  const poweredBy = String(headers['x-powered-by'] || '');
  if (/wordpress/i.test(poweredBy)) {
    signals.push('header:x-powered-by');
  }

  if (headers['x-pingback'] && /xmlrpc\.php/i.test(String(headers['x-pingback']))) {
    signals.push('header:x-pingback');
  }

  if (body.includes('/wp-content/') || body.includes('/wp-includes/')) {
    signals.push('html:wp-paths');
  }

  if ($) {
    const generator = ($('meta[name="generator"]').attr('content') || '').toLowerCase();
    if (generator.includes('wordpress')) {
      signals.push('meta:generator-wordpress');
    }
    if ($('link[rel="https://api.w.org/"]').length > 0) {
      signals.push('link:api.w.org');
    }
  }

  return signals;
}

const MAX_PUBLIC_ERROR_LENGTH = 240;

function normalizePublicErrorMessage(raw: string): string {
  const cleaned = raw.replace(/\s+/g, ' ').trim();
  if (!cleaned) return '';
  if (cleaned.length <= MAX_PUBLIC_ERROR_LENGTH) return cleaned;
  return `${cleaned.slice(0, MAX_PUBLIC_ERROR_LENGTH - 3).trimEnd()}...`;
}

function extractCleanElementText($: CheerioAPI, selector: string): string {
  const el = $(selector).first();
  if (el.length === 0) return '';
  const clone = el.clone();
  clone.find('script, style').remove();
  clone.find('br').replaceWith(' ');
  clone.find('p, li, h1, h2, h3, h4, div').after(' ');
  return normalizePublicErrorMessage(clone.text());
}

export function extractWordPressPublicErrorMessage(
  body: string,
  $: CheerioAPI | null
): string | null {
  if ($) {
    const wpDieMessage = extractCleanElementText($, '.wp-die-message');
    if (wpDieMessage) return wpDieMessage;

    const errorPageMessage = extractCleanElementText($, '#error-page');
    if (errorPageMessage) return errorPageMessage;
  }

  const knownPatterns = [
    /error establishing a database connection[^<\n]*/i,
    /one or more database tables are unavailable[^<\n]*/i,
    /your php installation appears to be missing the mysql extension which is required by wordpress\.?/i,
  ];

  for (const pattern of knownPatterns) {
    const match = body.match(pattern);
    if (match?.[0]) {
      const message = normalizePublicErrorMessage(match[0]);
      if (message) return message;
    }
  }

  return null;
}

export async function runWordPressChecks(ctx: ScanContext): Promise<ScanCheckResult[]> {
  const results: ScanCheckResult[] = [];
  const { http, $, isWordPress, parsedFinalUrl } = ctx;
  const body = http.body || '';
  const lowerBody = body.toLowerCase();

  const push = (errorName: string, evidence: string, detectionMethod: string) => {
    results.push({
      errorName,
      detected: true,
      evidence,
      detectionMethod,
      category: 'wordpress',
    });
  };

  // 1. Publicly exposed WordPress Critical Error (can appear even when normal wp-content paths are absent)
  if (
    /there has been a critical error on this website/i.test(body) ||
    (/wp-die-message/i.test(body) && /critical error/i.test(body))
  ) {
    push(
      'WordPress Critical Error (Publicly Exposed)',
      'WordPress critical error screen text detected in public HTML response',
      'html-signature-match'
    );
  }

  // 2. WordPress Maintenance Mode Stuck
  if (
    /briefly unavailable for scheduled maintenance\.\s*check back in a minute/i.test(body)
  ) {
    push(
      'WordPress Maintenance Mode Stuck',
      'WordPress .maintenance screen detected in public response',
      'html-signature-match'
    );
  }

  // 3. WordPress Installation Page Exposed
  if (
    (/wp-admin\/install\.php/i.test(http.finalUrl) ||
      (/select a default language/i.test(body) && /wp-core-ui/i.test(body)) ||
      (/wordpress.*installation/i.test(body) && /setup-config\.php/i.test(body)) ||
      /welcome to wordpress\. before getting started, you will need to know the following items/i.test(body))
  ) {
    push(
      'WordPress Installation Page Exposed',
      'WordPress setup/installation wizard is publicly accessible',
      'html-signature-match'
    );
  }

  // 4. WordPress Public Error Message (wp_die / database connection error) — show only the actual extracted message
  if (
    /error establishing a database connection/i.test(body) ||
    /one or more database tables are unavailable/i.test(body) ||
    /your php installation appears to be missing the mysql extension which is required by wordpress/i.test(body) ||
    (/id=["']error-page["']/i.test(body) && /class=["'][^"']*wp-die-message/i.test(body))
  ) {
    const extractedMessage = extractWordPressPublicErrorMessage(body, $);
    push(
      extractedMessage || 'WordPress Public Error Message',
      'Public WordPress wp_die or database error message extracted from HTML response',
      'wp-public-error-message'
    );
  }

  // 5. WordPress White Screen of Death (Possible) — only when WP headers or signals exist with empty/blank 500 or 200 body
  const strippedText = $ ? $('body').text().trim() : body.replace(/<[^>]+>/g, '').trim();
  const hasWpHeader = ctx.wpSignals.some((s) => s.startsWith('header:'));
  if (
    (isWordPress || hasWpHeader) &&
    (http.statusCode === 500 || http.statusCode === 200) &&
    body.trim().length < 80 &&
    strippedText.length === 0
  ) {
    push(
      'WordPress White Screen of Death (Possible)',
      `WordPress headers present with empty response body (HTTP ${http.statusCode})`,
      'wp-empty-response-check'
    );
  }

  // 6. WordPress Debug / Config Information Exposed
  if (
    /define\(\s*['"]WP_DEBUG['"]/i.test(body) ||
    /wp-content\/debug\.log/i.test(body) ||
    (/WP_DEBUG_DISPLAY/i.test(body) && /true/i.test(body))
  ) {
    push(
      'WordPress Debug Information Exposed',
      'Public response contains exposed WordPress debug references or output',
      'html-signature-match'
    );
  }

  if (
    /define\(\s*['"]DB_NAME['"]/i.test(body) ||
    /define\(\s*['"]DB_USER['"]/i.test(body) ||
    /define\(\s*['"]AUTH_KEY['"]/i.test(body) ||
    /\$table_prefix\s*=\s*['"][^'"]+['"]/i.test(body)
  ) {
    push(
      'WordPress Configuration Information Exposed',
      'Public response contains exposed wp-config.php configuration directives',
      'html-signature-match'
    );
  }

  // Only proceed with deeper WordPress-specific checks if there is public WordPress evidence
  if (!isWordPress) {
    return results;
  }

  // 7. WordPress Site URL Mismatch
  const expectedHost = parsedFinalUrl.hostname.toLowerCase().replace(/^www\./, '');
  const wpAssetUrls: string[] = [];
  const wpAssetRegex = /https?:\/\/([a-z0-9.-]+)\/wp-(?:content|includes)\//gi;
  let match: RegExpExecArray | null;
  while ((match = wpAssetRegex.exec(body)) !== null && wpAssetUrls.length < 25) {
    wpAssetUrls.push(match[1].toLowerCase().replace(/^www\./, ''));
  }

  if (wpAssetUrls.length >= 2) {
    const mismatchedAssetHosts = wpAssetUrls.filter(
      (h) =>
        h !== expectedHost &&
        !h.endsWith(`.${expectedHost}`) &&
        !h.includes('cdn') &&
        !h.includes('cloudfront') &&
        !h.includes('wp.com') &&
        !h.includes('googleapis') &&
        !h.includes('cloudflare')
    );
    const localAssetHost = mismatchedAssetHosts.find(
      (h) => h === 'localhost' || h.endsWith('.local') || h.endsWith('.test') || /^\d+\.\d+\.\d+\.\d+$/.test(h)
    );
    if (localAssetHost || (mismatchedAssetHosts.length >= 3 && new Set(mismatchedAssetHosts).size === 1)) {
      push(
        'WordPress Site URL Mismatch',
        `WordPress core/content assets reference mismatched host ${localAssetHost || mismatchedAssetHosts[0]} instead of ${parsedFinalUrl.hostname}`,
        'wp-asset-host-comparison'
      );
    }
  }

  if (lowerBody.includes('wp-includes') && http.statusCode !== null && http.statusCode >= 500) {
    push(
      'WordPress Site Unavailable',
      `WordPress site returned HTTP ${http.statusCode}`,
      'wp-http-status-check'
    );
  }

  return results;
}
