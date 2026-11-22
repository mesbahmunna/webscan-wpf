import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildResultsCsv,
  detectWebsiteColumnIndex,
  escapeCsvCell,
  extractBulkScanItems,
  parseCsvText,
} from './csvParser';

test('parseCsvText handles headers, quoted commas, escaped quotes, and CRLF', () => {
  const csv = '\uFEFF"Company, Inc.",Website,Notes\r\n"Acme, ""Corp""",https://example.com,"Main, live"\r\nBeta,wordpressfixer.com,Secondary\r\n\r\n';
  const parsed = parseCsvText(csv);

  assert.deepEqual(parsed.headers, ['Company, Inc.', 'Website', 'Notes']);
  assert.equal(parsed.rows.length, 2);
  assert.deepEqual(parsed.rows[0], ['Acme, "Corp"', 'https://example.com', 'Main, live']);
  assert.deepEqual(parsed.rows[1], ['Beta', 'wordpressfixer.com', 'Secondary']);
  assert.equal(parsed.detectedWebsiteColumnIndex, 1);
});

test('parseCsvText supports headerless URL-only CSV files', () => {
  const csv = 'https://example.com\nhttps://wordpressfixer.com\n';
  const parsed = parseCsvText(csv);

  assert.deepEqual(parsed.headers, ['Column 1']);
  assert.equal(parsed.rows.length, 2);
  assert.equal(parsed.detectedWebsiteColumnIndex, 0);
});

test('detectWebsiteColumnIndex finds website column by content when header is generic', () => {
  const headers = ['ID', 'Name', 'Field A', 'Email'];
  const rows = [
    ['1', 'Alpha', 'https://alpha.example.com', 'hello@alpha.example.com'],
    ['2', 'Beta', 'beta.example.org', 'info@beta.example.org'],
  ];
  assert.equal(detectWebsiteColumnIndex(headers, rows), 2);
});

test('extractBulkScanItems validates URLs, flags private/invalid entries, and deduplicates', () => {
  const csv = [
    'Client,Site URL',
    'A,https://example.com',
    'B,example.com/',
    'C,http://127.0.0.1',
    'D,ftp://files.example.com',
    'E,https://wordpressfixer.com',
  ].join('\n');

  const parsed = parseCsvText(csv);
  const extracted = extractBulkScanItems(parsed, 1, { deduplicate: true });

  assert.equal(extracted.duplicateCount, 1);
  assert.equal(extracted.items.length, 4);
  assert.equal(extracted.items[0].normalizedUrl, 'https://example.com/');
  assert.equal(extracted.items[0].validationError, null);
  assert.equal(extracted.items[1].normalizedUrl, null);
  assert.ok(extracted.items[1].validationError);
  assert.equal(extracted.items[2].normalizedUrl, null);
  assert.ok(extracted.items[2].validationError);
  assert.equal(extracted.items[3].normalizedUrl, 'https://wordpressfixer.com/');
});

test('escapeCsvCell neutralizes formula injection and buildResultsCsv formats cleanly', () => {
  assert.equal(escapeCsvCell('=CMD()'), "'=CMD()");
  assert.equal(escapeCsvCell('+1234'), "'+1234");
  assert.equal(escapeCsvCell('a,b'), '"a,b"');

  const out = buildResultsCsv([
    { website: 'https://example.com/', status: 'Errors Found', errors: ['Missing H1 Tag', 'Sitemap Missing'] },
    { website: 'https://clean.example.com/', status: 'No Errors Found', errors: [] },
  ]);

  assert.ok(out.includes('Website,Status,Detected Errors'));
  assert.ok(out.includes('https://example.com/,Errors Found,Missing H1 Tag | Sitemap Missing'));
  assert.ok(out.includes('https://clean.example.com/,No Errors Found,No Errors Found'));
});

test('extractBulkScanItems has no 100-row limit and extracts large CSV batches completely', () => {
  const lines = ['Website'];
  for (let i = 1; i <= 500; i++) {
    lines.push(`https://site-${i}.example.com`);
  }

  const parsed = parseCsvText(lines.join('\n'));
  const extracted = extractBulkScanItems(parsed, 0, { deduplicate: true });

  assert.equal(parsed.rows.length, 500);
  assert.equal(extracted.items.length, 500);
  assert.equal(extracted.truncatedCount, 0);
  assert.equal(extracted.duplicateCount, 0);
});

