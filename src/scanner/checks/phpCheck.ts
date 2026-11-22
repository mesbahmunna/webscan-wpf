import type { ScanCheckResult, ScanContext } from '../types';

interface PhpSignatureRule {
  errorName: string;
  pattern: RegExp;
  method: string;
}

const PHP_EXPOSED_RULES: PhpSignatureRule[] = [
  {
    errorName: 'PHP Fatal Error Exposed',
    pattern: /(?:<b>)?\s*Fatal error\s*(?:<\/b>)?:\s*[^\n<]{4,300}\s+in\s+(?:<b>)?(?:\/|[a-zA-Z]:\\)[^\n<]+(?:\.php|eval\(\)'d code)/i,
    method: 'php-fatal-signature',
  },
  {
    errorName: 'PHP Parse Error Exposed',
    pattern: /(?:<b>)?\s*Parse error\s*(?:<\/b>)?:\s*syntax error[^\n<]{0,250}\s+in\s+(?:<b>)?(?:\/|[a-zA-Z]:\\)[^\n<]+\.php/i,
    method: 'php-parse-signature',
  },
  {
    errorName: 'PHP Warning Exposed',
    pattern: /(?:<b>)?\s*Warning\s*(?:<\/b>)?:\s*[^\n<]{4,300}\s+in\s+(?:<b>)?(?:\/|[a-zA-Z]:\\)[^\n<]+\.php\s*(?:<\/b>)?\s*on line\s*(?:<b>)?\d+/i,
    method: 'php-warning-signature',
  },
  {
    errorName: 'PHP Notice Exposed',
    pattern: /(?:<b>)?\s*Notice\s*(?:<\/b>)?:\s*[^\n<]{4,300}\s+in\s+(?:<b>)?(?:\/|[a-zA-Z]:\\)[^\n<]+\.php\s*(?:<\/b>)?\s*on line\s*(?:<b>)?\d+/i,
    method: 'php-notice-signature',
  },
  {
    errorName: 'PHP Deprecated Error Exposed',
    pattern: /(?:<b>)?\s*Deprecated\s*(?:<\/b>)?:\s*[^\n<]{4,300}\s+in\s+(?:<b>)?(?:\/|[a-zA-Z]:\\)[^\n<]+\.php\s*(?:<\/b>)?\s*on line\s*(?:<b>)?\d+/i,
    method: 'php-deprecated-signature',
  },
  {
    errorName: 'PHP Uncaught Exception Exposed',
    pattern: /Uncaught\s+(?:[A-Za-z0-9_\\]+)?Exception\b[^\n<]{0,250}(?:in\s+(?:\/|[a-zA-Z]:\\)[^\n<]+\.php|Stack trace:)/i,
    method: 'php-uncaught-exception-signature',
  },
  {
    errorName: 'PHP Uncaught Error Exposed',
    pattern: /Uncaught\s+(?:Type|Parse|Arithmetic|DivisionByZero|Assertion|Compile|Value|UnhandledMatch)?Error\b:\s*[^\n<]{4,250}\s+in\s+(?:\/|[a-zA-Z]:\\)[^\n<]+\.php/i,
    method: 'php-uncaught-error-signature',
  },
  {
    errorName: 'PHP Memory Error Exposed',
    pattern: /Allowed memory size of \d+ bytes exhausted \(tried to allocate \d+ bytes\)/i,
    method: 'php-memory-exhausted-signature',
  },
  {
    errorName: 'PHP Undefined Function Error Exposed',
    pattern: /Call to undefined function\s+[a-zA-Z0-9_\\]+\(\)/i,
    method: 'php-undefined-function-signature',
  },
  {
    errorName: 'PHP Undefined Variable Error Exposed',
    pattern: /Undefined variable:?\s+\$?[a-zA-Z_][a-zA-Z0-9_]*\s+in\s+(?:<b>)?(?:\/|[a-zA-Z]:\\)[^\n<]+\.php/i,
    method: 'php-undefined-variable-signature',
  },
  {
    errorName: 'PHP Stack Trace Exposed',
    pattern: /Stack trace:\s*[\r\n<]+(?:#0\s+(?:\/|[a-zA-Z]:\\)[^\n<]+\.php\(\d+\):)/i,
    method: 'php-stack-trace-signature',
  },
  {
    errorName: 'PHP Configuration Information Exposed',
    pattern: /<title>\s*phpinfo\(\)\s*<\/title>|PHP Version\s+\d+\.\d+\.\d+[\s\S]{0,400}System[\s\S]{0,200}Configure Command/i,
    method: 'phpinfo-signature',
  },
];

export function runPhpChecks(ctx: ScanContext): ScanCheckResult[] {
  const results: ScanCheckResult[] = [];
  const body = ctx.http.body || '';
  if (!body) return results;

  // Limit regex scanning slice to avoid ReDoS or wasted CPU on huge bodies
  const sample = body.slice(0, 350_000);

  let anyPhpErrorMatch = false;

  for (const rule of PHP_EXPOSED_RULES) {
    const match = sample.match(rule.pattern);
    if (match) {
      anyPhpErrorMatch = true;
      results.push({
        errorName: rule.errorName,
        detected: true,
        evidence: match[0].slice(0, 160),
        detectionMethod: rule.method,
        category: 'php',
      });
    }
  }

  // PHP File Path Exposed: full server filesystem path to a .php file exposed in error output
  const filePathPattern =
    /(?:\/(?:var\/www|home\/[a-z0-9._-]+|srv\/www|usr\/local\/|opt\/|public_html|www\/)|[A-Z]:\\(?:xampp|wamp|inetpub|laragon|Users)\\)[^\s"'<>]{1,180}\.php\b/i;
  const pathMatch = sample.match(filePathPattern);
  if (pathMatch && (anyPhpErrorMatch || /\bon line\s*(?:<b>)?\d+/i.test(sample))) {
    results.push({
      errorName: 'PHP File Path Exposed',
      detected: true,
      evidence: pathMatch[0].slice(0, 160),
      detectionMethod: 'php-server-path-signature',
      category: 'php',
    });
  }

  return results;
}
