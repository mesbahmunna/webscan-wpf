import { validateClientUrl } from './urlValidation';

export interface ParsedCsvData {
  headers: string[];
  rows: string[][];
  detectedWebsiteColumnIndex: number;
}

export interface BulkScanItemSeed {
  id: string;
  rowIndex: number;
  rawValue: string;
  normalizedUrl: string | null;
  validationError: string | null;
}

/**
 * RFC 4180-compliant CSV parser handling quoted values, embedded commas,
 * escaped double quotes (""), and CRLF/LF line endings.
 */
export function parseCsvText(input: string): ParsedCsvData {
  // Strip UTF-8 BOM if present
  const text = input.replace(/^\uFEFF/, '');
  const rawRows: string[][] = [];
  let currentRow: string[] = [];
  let currentField = '';
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];

    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          currentField += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        currentField += ch;
      }
      continue;
    }

    if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      currentRow.push(currentField.trim());
      currentField = '';
    } else if (ch === '\r') {
      if (text[i + 1] === '\n') i++;
      currentRow.push(currentField.trim());
      rawRows.push(currentRow);
      currentRow = [];
      currentField = '';
    } else if (ch === '\n') {
      currentRow.push(currentField.trim());
      rawRows.push(currentRow);
      currentRow = [];
      currentField = '';
    } else {
      currentField += ch;
    }
  }

  // Push trailing field/row if non-empty
  if (currentField.length > 0 || currentRow.length > 0) {
    currentRow.push(currentField.trim());
    rawRows.push(currentRow);
  }

  // Filter completely blank rows
  const nonEmptyRows = rawRows.filter((row) => row.some((cell) => cell.trim().length > 0));
  if (nonEmptyRows.length === 0) {
    return { headers: [], rows: [], detectedWebsiteColumnIndex: 0 };
  }

  const firstRow = nonEmptyRows[0];
  const looksLikeHeaderRow = !firstRow.some((cell) =>
    /^https?:\/\//i.test(cell) || /^[a-z0-9-]+\.[a-z]{2,}(?:\/|$)/i.test(cell)
  );

  let headers: string[];
  let dataRows: string[][];

  if (looksLikeHeaderRow && nonEmptyRows.length > 1) {
    headers = firstRow.map((h, idx) => h || `Column ${idx + 1}`);
    dataRows = nonEmptyRows.slice(1);
  } else if (nonEmptyRows.length === 1 && looksLikeHeaderRow) {
    headers = firstRow.map((h, idx) => h || `Column ${idx + 1}`);
    dataRows = [];
  } else {
    headers = firstRow.map((_h, idx) => `Column ${idx + 1}`);
    dataRows = nonEmptyRows;
  }

  // Normalize row lengths to header length (iterative max avoids call-stack overflow on large CSVs)
  let colCount = headers.length;
  for (let i = 0; i < dataRows.length; i++) {
    if (dataRows[i].length > colCount) {
      colCount = dataRows[i].length;
    }
  }
  while (headers.length < colCount) {
    headers.push(`Column ${headers.length + 1}`);
  }
  const normalizedRows = dataRows.map((row) => {
    if (row.length === colCount) return row;
    const padded = row.slice(0, colCount);
    while (padded.length < colCount) padded.push('');
    return padded;
  });

  const detectedWebsiteColumnIndex = detectWebsiteColumnIndex(headers, normalizedRows);

  return {
    headers,
    rows: normalizedRows,
    detectedWebsiteColumnIndex,
  };
}

export function detectWebsiteColumnIndex(headers: string[], rows: string[][]): number {
  if (headers.length === 0) return 0;

  // Priority 1: Header name match
  const headerPatterns = [
    /^(?:website|website[_\s-]?url|site[_\s-]?url|url|domain|domain[_\s-]?name|homepage|web)$/i,
    /(?:website|url|domain|site|link|homepage)/i,
  ];

  for (const pattern of headerPatterns) {
    const idx = headers.findIndex((h) => pattern.test(h.trim()));
    if (idx !== -1) return idx;
  }

  // Priority 2: Content inspection across first 10 rows
  const sampleRows = rows.slice(0, 10);
  let bestIdx = 0;
  let bestScore = -1;

  for (let col = 0; col < headers.length; col++) {
    let score = 0;
    for (const row of sampleRows) {
      const val = (row[col] || '').trim();
      if (!val) continue;
      if (/^https?:\/\//i.test(val)) score += 3;
      else if (/^[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:\/.*)?$/i.test(val) && !val.includes('@')) score += 2;
    }
    if (score > bestScore) {
      bestScore = score;
      bestIdx = col;
    }
  }

  return bestIdx;
}

export function extractBulkScanItems(
  parsed: ParsedCsvData,
  columnIndex: number,
  options?: { deduplicate?: boolean; maxRows?: number }
): {
  items: BulkScanItemSeed[];
  truncatedCount: number;
  duplicateCount: number;
} {
  const deduplicate = options?.deduplicate ?? true;
  const maxRows = options?.maxRows ?? Number.POSITIVE_INFINITY;

  const seenNormalized = new Set<string>();
  const items: BulkScanItemSeed[] = [];
  let duplicateCount = 0;
  let truncatedCount = 0;

  for (let i = 0; i < parsed.rows.length; i++) {
    const row = parsed.rows[i];
    const rawValue = (row[columnIndex] || '').trim();
    if (!rawValue) continue;

    const validation = validateClientUrl(rawValue);
    const normalizedUrl = validation.valid && validation.normalized ? validation.normalized : null;

    if (deduplicate && normalizedUrl) {
      if (seenNormalized.has(normalizedUrl)) {
        duplicateCount++;
        continue;
      }
      seenNormalized.add(normalizedUrl);
    }

    if (items.length >= maxRows) {
      truncatedCount++;
      continue;
    }

    items.push({
      id: `row-${i + 1}-${rawValue.slice(0, 24)}`,
      rowIndex: i + 1,
      rawValue,
      normalizedUrl,
      validationError: validation.valid ? null : validation.error || 'Invalid website URL.',
    });
  }

  return { items, truncatedCount, duplicateCount };
}

/**
 * Neutralize spreadsheet formula injection and properly quote CSV fields.
 */
export function escapeCsvCell(value: string): string {
  let safe = String(value ?? '');
  if (/^[=+\-@\t\r]/.test(safe)) {
    safe = `'${safe}`;
  }
  if (/[",\r\n]/.test(safe)) {
    return `"${safe.replace(/"/g, '""')}"`;
  }
  return safe;
}

export function buildResultsCsv(
  rows: Array<{
    website: string;
    status: string;
    errors: string[];
  }>
): string {
  const header = ['Website', 'Status', 'Detected Errors'].map(escapeCsvCell).join(',');
  const lines = rows.map((row) => {
    const errorsText =
      row.status === 'No Errors Found'
        ? 'No Errors Found'
        : row.errors.join(' | ');
    return [row.website, row.status, errorsText].map(escapeCsvCell).join(',');
  });
  return [header, ...lines].join('\r\n');
}

export const SAMPLE_CSV_CONTENT = [
  'Company,Website,Notes',
  'Example Org,https://example.com,Primary site',
  'WordPressFixer,https://wordpressfixer.com,Business site',
  'IANA Reserved,https://iana.org,Reference domain',
].join('\r\n');
