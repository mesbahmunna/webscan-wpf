import tls from 'node:tls';
import { resolveAndValidateHost } from '../security.ts';
import type { ScanCheckResult, ScanContext, TlsInspectionResult } from '../types.ts';

export async function inspectTlsCertificate(hostname: string, timeoutMs = 4500): Promise<TlsInspectionResult> {
  const resolved = await resolveAndValidateHost(hostname);
  if (!resolved.allowed || !resolved.pinned) {
    return {
      attempted: false,
      connected: false,
      authorized: false,
      errorCode: resolved.dnsErrorCode || 'BLOCKED_HOST',
      errorMessage: resolved.blockedReason || 'DNS resolution failed',
    };
  }

  return new Promise((resolve) => {
    let settled = false;
    const finish = (res: TlsInspectionResult) => {
      if (!settled) {
        settled = true;
        resolve(res);
      }
    };

    const socket = tls.connect(
      {
        host: resolved.pinned!.address,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: timeoutMs,
      },
      () => {
        try {
          const authorized = socket.authorized;
          const authErr = socket.authorizationError ? String(socket.authorizationError) : undefined;
          const cert = socket.getPeerCertificate(true);
          const protocol = socket.getProtocol();

          const now = Date.now();
          const validFromMs = cert?.valid_from ? Date.parse(cert.valid_from) : NaN;
          const validToMs = cert?.valid_to ? Date.parse(cert.valid_to) : NaN;
          const isExpired = !Number.isNaN(validToMs) && validToMs < now;
          const isNotYetValid = !Number.isNaN(validFromMs) && validFromMs > now;

          const errUpper = (authErr || '').toUpperCase();
          const isSelfSigned =
            errUpper.includes('DEPTH_ZERO_SELF_SIGNED_CERT') ||
            errUpper.includes('SELF_SIGNED_CERT_IN_CHAIN') ||
            errUpper.includes('SELF SIGNED');
          const hostnameMismatch =
            errUpper.includes('ERR_TLS_CERT_ALTNAME_INVALID') ||
            errUpper.includes('HOSTNAME') ||
            errUpper.includes('ALTNAME');
          const chainError =
            errUpper.includes('UNABLE_TO_VERIFY_LEAF_SIGNATURE') ||
            errUpper.includes('UNABLE_TO_GET_ISSUER_CERT') ||
            errUpper.includes('CERT_UNTRUSTED') ||
            errUpper.includes('UNABLE_TO_GET_ISSUER_CERT_LOCALLY');

          socket.end();
          finish({
            attempted: true,
            connected: true,
            authorized,
            authorizationError: authErr,
            validFrom: cert?.valid_from,
            validTo: cert?.valid_to,
            isExpired,
            isNotYetValid,
            isSelfSigned,
            hostnameMismatch,
            chainError,
            protocol,
          });
        } catch (err) {
          socket.destroy();
          finish({
            attempted: true,
            connected: false,
            authorized: false,
            errorCode: (err as NodeJS.ErrnoException)?.code || 'TLS_INSPECT_ERROR',
            errorMessage: (err as Error).message,
          });
        }
      }
    );

    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      finish({
        attempted: true,
        connected: false,
        authorized: false,
        errorCode: 'ETIMEDOUT',
        errorMessage: 'TLS handshake timed out',
      });
    });

    socket.on('error', (err: NodeJS.ErrnoException) => {
      socket.destroy();
      finish({
        attempted: true,
        connected: false,
        authorized: false,
        errorCode: err.code || 'TLS_ERROR',
        errorMessage: err.message,
      });
    });
  });
}

export function runSslChecks(ctx: ScanContext): ScanCheckResult[] {
  const results: ScanCheckResult[] = [];
  const { tls: tlsInfo, parsedFinalUrl, httpToHttpsCheck } = ctx;

  const push = (errorName: string, evidence: string, detectionMethod: string) => {
    results.push({
      errorName,
      detected: true,
      evidence,
      detectionMethod,
      category: 'ssl',
    });
  };

  if (tlsInfo.attempted) {
    if (!tlsInfo.connected) {
      const code = (tlsInfo.errorCode || '').toUpperCase();
      const msg = (tlsInfo.errorMessage || '').toLowerCase();

      if (
        code.includes('SSL') ||
        msg.includes('handshake') ||
        msg.includes('sslv3') ||
        msg.includes('wrong version number') ||
        msg.includes('alert')
      ) {
        push('SSL Handshake Failed', tlsInfo.errorMessage || code, 'tls-socket-handshake');
      } else if (code.includes('TLS') || msg.includes('tls') || msg.includes('cipher') || msg.includes('protocol')) {
        push('TLS Connection Error', tlsInfo.errorMessage || code, 'tls-socket-handshake');
      }

      if (ctx.parsedInitialUrl.protocol === 'https:' || code === 'ECONNREFUSED' || code === 'ECONNRESET') {
        push(
          'HTTPS Connection Failed',
          `Failed to establish HTTPS connection on port 443 (${tlsInfo.errorCode || tlsInfo.errorMessage || 'error'})`,
          'tls-port-443-probe'
        );
      }
    } else if (!tlsInfo.authorized) {
      const authErr = tlsInfo.authorizationError || 'Certificate verification failed';
      const errUpper = authErr.toUpperCase();

      if (tlsInfo.isExpired || errUpper.includes('CERT_HAS_EXPIRED')) {
        push('SSL Certificate Expired', `Certificate expired on ${tlsInfo.validTo || 'unknown date'}`, 'tls-cert-expiry');
      }
      if (tlsInfo.isNotYetValid || errUpper.includes('CERT_NOT_YET_VALID')) {
        push('SSL Certificate Invalid', `Certificate not valid until ${tlsInfo.validFrom || 'future date'}`, 'tls-cert-validity');
      }
      if (tlsInfo.hostnameMismatch) {
        push('SSL Certificate Hostname Mismatch', authErr, 'tls-cert-hostname');
      }
      if (tlsInfo.isSelfSigned) {
        push('SSL Certificate Self-Signed', authErr, 'tls-cert-issuer');
      }
      if (tlsInfo.chainError) {
        push('SSL Certificate Chain Error', authErr, 'tls-cert-chain');
      }

      if (!tlsInfo.isExpired && !tlsInfo.hostnameMismatch && !tlsInfo.isSelfSigned && !tlsInfo.chainError) {
        push('SSL Certificate Invalid', authErr, 'tls-cert-validation');
      }
      push('SSL Certificate Verification Failed', authErr, 'tls-cert-verification');
    }
  }

  // HTTP -> HTTPS enforcement checks
  if (parsedFinalUrl.protocol === 'http:' && ctx.http.statusCode !== null && ctx.http.statusCode < 400) {
    push(
      'HTTPS Not Enforced',
      `Final destination ${parsedFinalUrl.toString()} is served over unencrypted HTTP`,
      'protocol-inspection'
    );
  }

  if (httpToHttpsCheck?.attempted && httpToHttpsCheck.httpAccessibleWithoutRedirect && !httpToHttpsCheck.redirectedToHttps) {
    push(
      'HTTP to HTTPS Redirect Missing',
      `HTTP version of ${ctx.hostname} returned status ${httpToHttpsCheck.statusCode} without redirecting to HTTPS`,
      'http-redirect-probe'
    );
    if (parsedFinalUrl.protocol === 'https:') {
      push(
        'HTTPS Not Enforced',
        `HTTP requests to ${ctx.hostname} are served directly instead of redirecting to HTTPS`,
        'http-redirect-probe'
      );
    }
  }

  return results;
}
