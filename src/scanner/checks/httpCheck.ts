import type { ScanCheckResult, ScanContext } from '../types';

const HTTP_STATUS_ERROR_MAP: Record<number, string> = {
  400: 'HTTP 400 – Bad Request',
  401: 'HTTP 401 – Unauthorized',
  403: 'HTTP 403 – Forbidden',
  404: 'HTTP 404 – Not Found',
  405: 'HTTP 405 – Method Not Allowed',
  408: 'HTTP 408 – Request Timeout',
  410: 'HTTP 410 – Gone',
  429: 'HTTP 429 – Too Many Requests',
  451: 'HTTP 451 – Unavailable for Legal Reasons',
  500: 'HTTP 500 – Internal Server Error',
  501: 'HTTP 501 – Not Implemented',
  502: 'HTTP 502 – Bad Gateway',
  503: 'HTTP 503 – Service Unavailable',
  504: 'HTTP 504 – Gateway Timeout',
};

export function runHttpChecks(ctx: ScanContext): ScanCheckResult[] {
  const results: ScanCheckResult[] = [];
  const { http } = ctx;

  const push = (errorName: string, evidence: string, detectionMethod: string) => {
    results.push({
      errorName,
      detected: true,
      evidence,
      detectionMethod,
      category: 'http',
    });
  };

  if (http.statusCode !== null && HTTP_STATUS_ERROR_MAP[http.statusCode]) {
    push(
      HTTP_STATUS_ERROR_MAP[http.statusCode],
      `Received HTTP status ${http.statusCode} ${http.statusMessage} from ${http.finalUrl}`,
      'http-status-code'
    );
  }

  if (http.redirectIssue === 'too-many-redirects') {
    push(
      'Too Many Redirects',
      `Exceeded redirect limit after ${http.redirectChain.length} hops`,
      'redirect-chain-analysis'
    );
  } else if (http.redirectIssue === 'redirect-loop') {
    push(
      'Redirect Loop',
      `Circular redirect detected ending at ${http.finalUrl}`,
      'redirect-chain-analysis'
    );
  } else if (http.redirectIssue === 'invalid-redirect') {
    push(
      'Invalid Redirect',
      http.errorMessage || 'Redirect response had an invalid or missing Location header',
      'redirect-header-validation'
    );
  } else if (http.redirectIssue === 'broken-redirect') {
    push(
      'Broken Redirect',
      `Redirect target ${http.finalUrl} returned status ${http.statusCode ?? http.errorCode ?? 'error'}`,
      'redirect-target-verification'
    );
  }

  const code = (http.errorCode || '').toUpperCase();
  const msg = (http.errorMessage || '').toLowerCase();

  if (code === 'ETIMEDOUT' || code === 'ESOCKETTIMEDOUT' || code === 'ABORT_ERR' || msg.includes('timed out')) {
    push('Connection Timeout', http.errorMessage || `Socket timeout (${code})`, 'socket-error-code');
  } else if (code === 'ECONNREFUSED') {
    push('Connection Refused', `Server refused connection on ${http.finalUrl}`, 'socket-error-code');
  } else if (code === 'ENOTFOUND' || code === 'EAI_NONAME') {
    push('Host Not Found', `Hostname ${ctx.hostname} was not found`, 'connection-lookup');
  } else if (code === 'EAI_AGAIN' || code === 'DNS_LOOKUP_FAILED' || code === 'EHOSTUNREACH' || code === 'ENETUNREACH') {
    push('Server Unreachable', `Unable to reach server (${code})`, 'socket-error-code');
  } else if (
    code.startsWith('HPE_') ||
    code === 'ERR_HTTP_INVALID_HEADER_VALUE' ||
    msg.includes('parse error') ||
    msg.includes('invalid header')
  ) {
    push('Invalid HTTP Response', http.errorMessage || `HTTP parser error (${code})`, 'http-parser');
  } else if (code === 'ECONNRESET' || msg.includes('socket hang up')) {
    push('Empty Response', 'Connection closed by peer without returning a response', 'http-response-inspection');
  }

  if (
    http.statusCode !== null &&
    http.statusCode >= 200 &&
    http.statusCode < 300 &&
    http.statusCode !== 204 &&
    http.statusCode !== 304
  ) {
    const rawBody = http.body || '';
    const withoutBomAndComments = rawBody
      .replace(/^\uFEFF/, '')
      .replace(/<!--[\s\S]*?-->/g, '')
      .trim();

    if (http.byteLength === 0 || withoutBomAndComments.length === 0) {
      push(
        'White Screen / Blank Page',
        `HTTP ${http.statusCode} response returned an empty or blank body`,
        'blank-page-detection'
      );
    } else if (ctx.isHtml && ctx.$) {
      const $ = ctx.$;
      const hasScripts = $('script').length > 0;
      const hasMetaRefresh = $('meta[http-equiv="refresh" i]').length > 0;

      if (!hasScripts && !hasMetaRefresh) {
        const mediaSelector =
          'img, svg, canvas, iframe, video, audio, form, input, button, object, embed, picture';
        const bodyEl = $('body');
        let visibleText = '';
        let hasVisibleElements = false;

        if (bodyEl.length > 0) {
          const clone = bodyEl.clone();
          clone.find('script, style, noscript, template').remove();
          visibleText = clone.text().trim();
          hasVisibleElements = clone.find(mediaSelector).length > 0;
        } else {
          const clone = $.root().clone();
          clone.find('script, style, noscript, template, head').remove();
          visibleText = clone.text().trim();
          hasVisibleElements = clone.find(mediaSelector).length > 0;
        }

        if (visibleText.length === 0 && !hasVisibleElements) {
          push(
            'White Screen / Blank Page',
            `HTTP ${http.statusCode} HTML page rendered with no visible content`,
            'blank-page-detection'
          );
        }
      }
    }
  }

  return results;
}
