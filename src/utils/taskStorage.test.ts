import test from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveTaskName,
  getFailedRowIds,
  getPendingRowIds,
  loadActiveTaskId,
  loadSavedTasks,
  saveActiveTaskId,
  saveTasks,
  summarizeTaskProgress,
  type BulkScanTask,
  type StorageLike,
} from './taskStorage';
import type { BulkScanRow } from '../components/BulkResultsTable';

function createMemoryStorage(): StorageLike {
  const map = new Map<string, string>();
  return {
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => {
      map.set(k, v);
    },
    removeItem: (k) => {
      map.delete(k);
    },
  };
}

function makeSampleTask(overrides: Partial<BulkScanTask> = {}): BulkScanTask {
  const rows: BulkScanRow[] = [
    {
      id: 'row-1',
      rowIndex: 1,
      rawValue: 'https://example.com',
      normalizedUrl: 'https://example.com/',
      status: 'errors',
      errors: ['HTTPS Not Enforced'],
      failureReason: null,
    },
    {
      id: 'row-2',
      rowIndex: 2,
      rawValue: 'https://clean.example.com',
      normalizedUrl: 'https://clean.example.com/',
      status: 'clean',
      errors: [],
      failureReason: null,
    },
    {
      id: 'row-3',
      rowIndex: 3,
      rawValue: 'https://timeout.example.com',
      normalizedUrl: 'https://timeout.example.com/',
      status: 'failed',
      errors: [],
      failureReason: 'Network error while contacting the scanner service.',
    },
    {
      id: 'row-4',
      rowIndex: 4,
      rawValue: 'http://127.0.0.1',
      normalizedUrl: null,
      status: 'invalid',
      errors: [],
      failureReason: 'Scanning local, private, or internal addresses is not permitted.',
    },
  ];

  return {
    id: 'task-1',
    name: 'client-sites',
    fileName: 'client-sites.csv',
    createdAt: 1000,
    updatedAt: 2000,
    parsedCsv: {
      headers: ['Website'],
      rows: [['https://example.com']],
      detectedWebsiteColumnIndex: 0,
    },
    selectedColumnIndex: 0,
    deduplicate: true,
    duplicateCount: 0,
    truncatedCount: 0,
    rows,
    ...overrides,
  };
}

test('saveTasks and loadSavedTasks persist tasks and active task ID across reload', () => {
  const storage = createMemoryStorage();
  const task1 = makeSampleTask({ id: 'task-1', updatedAt: 1000 });
  const task2 = makeSampleTask({ id: 'task-2', name: 'batch-2', updatedAt: 5000 });

  saveTasks([task1, task2], storage);
  saveActiveTaskId('task-2', storage);

  const loaded = loadSavedTasks(storage);
  assert.equal(loaded.length, 2);
  // Sorted most recently updated first
  assert.equal(loaded[0].id, 'task-2');
  assert.equal(loaded[1].id, 'task-1');
  assert.equal(loadActiveTaskId(storage), 'task-2');
});

test('loadSavedTasks recovers rows stuck in scanning status back to pending after reload', () => {
  const storage = createMemoryStorage();
  const task = makeSampleTask({
    rows: [
      {
        id: 'row-in-flight',
        rowIndex: 1,
        rawValue: 'https://example.com',
        normalizedUrl: 'https://example.com/',
        status: 'scanning',
        errors: [],
        failureReason: null,
      },
    ],
  });

  saveTasks([task], storage);
  const loaded = loadSavedTasks(storage);
  assert.equal(loaded[0].rows[0].status, 'pending');
  assert.deepEqual(getPendingRowIds(loaded[0].rows), ['row-in-flight']);
});

test('getFailedRowIds selects both failed and error rows while excluding clean and invalid rows', () => {
  const task = makeSampleTask();
  assert.deepEqual(getFailedRowIds(task.rows), ['row-1', 'row-3']);

  const summary = summarizeTaskProgress(task.rows);
  assert.equal(summary.total, 4);
  assert.equal(summary.validCount, 3);
  assert.equal(summary.scannedCount, 3);
  assert.equal(summary.failedOrErrorCount, 2);
  assert.equal(summary.cleanCount, 1);
  assert.equal(summary.pendingCount, 0);
});

test('deriveTaskName strips .csv extension cleanly', () => {
  assert.equal(deriveTaskName('agency-clients.csv'), 'agency-clients');
  assert.equal(deriveTaskName('BATCH.CSV'), 'BATCH');
  assert.equal(deriveTaskName('   '), 'Bulk Scan Task');
});
