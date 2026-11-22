import type { BulkScanRow } from '../components/BulkResultsTable';
import type { ParsedCsvData } from './csvParser';

export interface BulkScanTask {
  id: string;
  name: string;
  fileName: string;
  createdAt: number;
  updatedAt: number;
  parsedCsv: ParsedCsvData;
  selectedColumnIndex: number;
  deduplicate: boolean;
  duplicateCount: number;
  truncatedCount: number;
  rows: BulkScanRow[];
}

export interface StorageLike {
  getItem: (key: string) => string | null;
  setItem: (key: string, value: string) => void;
  removeItem: (key: string) => void;
}

const TASKS_STORAGE_KEY = 'wpfixer_bulk_tasks_v1';
const ACTIVE_TASK_STORAGE_KEY = 'wpfixer_active_task_v1';
const MAX_LOCALSTORAGE_TASKS = 25;

const IDB_NAME = 'wpfixer_tasks_db';
const IDB_VERSION = 1;
const IDB_STORE = 'tasks';
const IDB_KEY = 'all_tasks';

function getBrowserStorage(): StorageLike | null {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      return window.localStorage;
    }
  } catch {
    // Ignore storage access errors in restricted environments
  }
  return null;
}

function getIndexedDB(): IDBFactory | null {
  try {
    if (typeof window !== 'undefined' && window.indexedDB) {
      return window.indexedDB;
    }
  } catch {
    // Ignore IndexedDB access errors in restricted environments
  }
  return null;
}

function openTasksDb(): Promise<IDBDatabase | null> {
  const idb = getIndexedDB();
  if (!idb) return Promise.resolve(null);

  return new Promise((resolve) => {
    try {
      const req = idb.open(IDB_NAME, IDB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(IDB_STORE)) {
          db.createObjectStore(IDB_STORE);
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

export function deriveTaskName(fileName: string): string {
  const cleaned = fileName.trim().replace(/\.csv$/i, '').trim();
  return cleaned || 'Bulk Scan Task';
}

export function createTaskId(): string {
  return `task-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
}

/**
 * Resets any rows that were mid-scan ('scanning') before a reload back to 'pending'
 * so tasks never get permanently stuck after page refresh.
 */
export function sanitizeLoadedTask(task: BulkScanTask): BulkScanTask {
  return {
    ...task,
    rows: Array.isArray(task.rows)
      ? task.rows.map((row) =>
          row.status === 'scanning' ? { ...row, status: 'pending' } : row
        )
      : [],
  };
}

function normalizeTaskList(parsed: unknown): BulkScanTask[] {
  if (!Array.isArray(parsed)) return [];
  return parsed
    .filter(
      (item): item is BulkScanTask =>
        Boolean(item) &&
        typeof item === 'object' &&
        typeof (item as BulkScanTask).id === 'string' &&
        typeof (item as BulkScanTask).fileName === 'string' &&
        Array.isArray((item as BulkScanTask).rows)
    )
    .map(sanitizeLoadedTask)
    .sort((a, b) => b.updatedAt - a.updatedAt);
}

export function loadSavedTasks(storage: StorageLike | null = getBrowserStorage()): BulkScanTask[] {
  if (!storage) return [];
  try {
    const raw = storage.getItem(TASKS_STORAGE_KEY);
    if (!raw) return [];
    return normalizeTaskList(JSON.parse(raw) as unknown);
  } catch {
    return [];
  }
}

export function saveTasks(
  tasks: BulkScanTask[],
  storage: StorageLike | null = getBrowserStorage()
): void {
  if (!storage) return;
  const trimmed = [...tasks]
    .sort((a, b) => b.updatedAt - a.updatedAt)
    .slice(0, MAX_LOCALSTORAGE_TASKS);

  try {
    storage.setItem(TASKS_STORAGE_KEY, JSON.stringify(trimmed));
  } catch {
    // If quota exceeded, keep the most recent tasks only
    for (let limit = Math.min(10, trimmed.length); limit >= 1; limit -= 2) {
      try {
        storage.setItem(TASKS_STORAGE_KEY, JSON.stringify(trimmed.slice(0, limit)));
        return;
      } catch {
        // continue shrinking
      }
    }
  }
}

/**
 * Loads saved tasks from IndexedDB (supporting unlimited large CSV batches),
 * automatically migrating any legacy tasks stored in localStorage.
 */
export async function loadSavedTasksAsync(): Promise<BulkScanTask[]> {
  const db = await openTasksDb();
  if (!db) {
    return loadSavedTasks();
  }

  const fromIdb = await new Promise<BulkScanTask[] | null>((resolve) => {
    try {
      const tx = db.transaction(IDB_STORE, 'readonly');
      const store = tx.objectStore(IDB_STORE);
      const req = store.get(IDB_KEY);
      req.onsuccess = () => {
        resolve(req.result !== undefined ? normalizeTaskList(req.result) : null);
      };
      req.onerror = () => resolve(null);
      tx.oncomplete = () => db.close();
      tx.onerror = () => db.close();
    } catch {
      db.close();
      resolve(null);
    }
  });

  if (fromIdb !== null) {
    return fromIdb;
  }

  return loadSavedTasks();
}

/**
 * Persists saved tasks to IndexedDB so large unlimited CSV batches survive reloads
 * without hitting the 5 MB localStorage quota.
 */
export async function saveTasksAsync(tasks: BulkScanTask[]): Promise<void> {
  const sorted = [...tasks].sort((a, b) => b.updatedAt - a.updatedAt);
  const db = await openTasksDb();
  if (!db) {
    saveTasks(sorted);
    return;
  }

  const savedToIdb = await new Promise<boolean>((resolve) => {
    try {
      const tx = db.transaction(IDB_STORE, 'readwrite');
      const store = tx.objectStore(IDB_STORE);
      store.put(sorted, IDB_KEY);
      tx.oncomplete = () => {
        db.close();
        resolve(true);
      };
      tx.onerror = () => {
        db.close();
        resolve(false);
      };
    } catch {
      db.close();
      resolve(false);
    }
  });

  if (!savedToIdb) {
    saveTasks(sorted);
  }
}

export function loadActiveTaskId(storage: StorageLike | null = getBrowserStorage()): string | null {
  if (!storage) return null;
  try {
    const id = storage.getItem(ACTIVE_TASK_STORAGE_KEY);
    return id && id.trim() ? id : null;
  } catch {
    return null;
  }
}

export function saveActiveTaskId(
  taskId: string | null,
  storage: StorageLike | null = getBrowserStorage()
): void {
  if (!storage) return;
  try {
    if (taskId) {
      storage.setItem(ACTIVE_TASK_STORAGE_KEY, taskId);
    } else {
      storage.removeItem(ACTIVE_TASK_STORAGE_KEY);
    }
  } catch {
    // ignore
  }
}

/**
 * Returns IDs of all scannable rows that failed or returned detected errors,
 * excluding clean ('No Errors Found'), pending, and invalid URL rows.
 */
export function getFailedRowIds(rows: BulkScanRow[]): string[] {
  return rows
    .filter(
      (row) =>
        Boolean(row.normalizedUrl) &&
        (row.status === 'failed' || row.status === 'errors')
    )
    .map((row) => row.id);
}

/**
 * Returns IDs of valid rows that have not been scanned yet.
 */
export function getPendingRowIds(rows: BulkScanRow[]): string[] {
  return rows
    .filter((row) => Boolean(row.normalizedUrl) && row.status === 'pending')
    .map((row) => row.id);
}

export function summarizeTaskProgress(rows: BulkScanRow[]): {
  total: number;
  validCount: number;
  scannedCount: number;
  failedOrErrorCount: number;
  cleanCount: number;
  pendingCount: number;
} {
  let validCount = 0;
  let scannedCount = 0;
  let failedOrErrorCount = 0;
  let cleanCount = 0;
  let pendingCount = 0;

  for (const r of rows) {
    if (r.normalizedUrl) validCount++;
    if (r.status === 'errors' || r.status === 'failed') {
      scannedCount++;
      failedOrErrorCount++;
    } else if (r.status === 'clean') {
      scannedCount++;
      cleanCount++;
    } else if (r.status === 'pending' || r.status === 'scanning') {
      if (r.normalizedUrl) pendingCount++;
    }
  }

  return {
    total: rows.length,
    validCount,
    scannedCount,
    failedOrErrorCount,
    cleanCount,
    pendingCount,
  };
}
