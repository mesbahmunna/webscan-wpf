import { useEffect, useMemo, useRef, useState } from 'react';
import {
  buildResultsCsv,
  extractBulkScanItems,
  parseCsvText,
  type ParsedCsvData,
} from '../utils/csvParser';
import {
  createTaskId,
  deriveTaskName,
  getFailedRowIds,
  getPendingRowIds,
  type BulkScanTask,
} from '../utils/taskStorage';
import { BulkCsvUploader } from './BulkCsvUploader';
import { BulkResultsTable, type BulkScanRow } from './BulkResultsTable';

const BULK_CONCURRENCY = 4;

interface BulkScannerWorkspaceProps {
  activeTask: BulkScanTask | null;
  onCreateTask: (task: BulkScanTask) => void;
  onUpdateTask: (taskId: string, updater: (task: BulkScanTask) => BulkScanTask) => void;
  onNewTask: () => void;
  onDeleteTask: (taskId: string) => void;
  onScanningTaskChange: (taskId: string | null) => void;
}

function buildRowsFromExtraction(
  parsed: ParsedCsvData,
  columnIndex: number,
  deduplicate: boolean
): {
  rows: BulkScanRow[];
  duplicateCount: number;
  truncatedCount: number;
} {
  const { items, duplicateCount, truncatedCount } = extractBulkScanItems(parsed, columnIndex, {
    deduplicate,
  });

  const rows: BulkScanRow[] = items.map((item) => ({
    id: item.id,
    rowIndex: item.rowIndex,
    rawValue: item.rawValue,
    normalizedUrl: item.normalizedUrl,
    status: item.normalizedUrl ? 'pending' : 'invalid',
    errors: [],
    failureReason: item.validationError,
  }));

  return { rows, duplicateCount, truncatedCount };
}

async function scanSingleUrlRequest(
  targetUrl: string,
  signal: AbortSignal
): Promise<{ ok: true; errors: string[] } | { ok: false; error: string }> {
  const maxAttempts = 6;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: targetUrl }),
      signal,
    });

    if (response.status === 429 && attempt < maxAttempts - 1) {
      const retryAfter = Number(response.headers.get('Retry-After') || '4');
      const waitMs = Math.min(Math.max(retryAfter, 2), 15) * 1000;
      await new Promise((resolve, reject) => {
        const timer = setTimeout(resolve, waitMs);
        signal.addEventListener(
          'abort',
          () => {
            clearTimeout(timer);
            reject(new DOMException('Aborted', 'AbortError'));
          },
          { once: true }
        );
      });
      continue;
    }

    const payload = (await response.json().catch(() => ({}))) as {
      errors?: string[];
      error?: string;
    };

    if (!response.ok) {
      return {
        ok: false,
        error: payload.error || 'Unable to scan this website.',
      };
    }

    return {
      ok: true,
      errors: Array.isArray(payload.errors) ? payload.errors : [],
    };
  }

  return { ok: false, error: 'Rate limit reached while scanning.' };
}

export function BulkScannerWorkspace({
  activeTask,
  onCreateTask,
  onUpdateTask,
  onNewTask,
  onDeleteTask,
  onScanningTaskChange,
}: BulkScannerWorkspaceProps) {
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  const abortControllerRef = useRef<AbortController | null>(null);
  const activeTaskId = activeTask?.id ?? null;

  // Abort any in-flight scan cleanly if user switches tasks or unmounts
  useEffect(() => {
    setUploadError(null);
    return () => {
      abortControllerRef.current?.abort();
    };
  }, [activeTaskId]);

  const rows = activeTask?.rows ?? [];
  const fileName = activeTask?.fileName ?? null;
  const taskName = activeTask?.name ?? null;
  const parsedCsv = activeTask?.parsedCsv ?? null;
  const selectedColumnIndex = activeTask?.selectedColumnIndex ?? 0;
  const deduplicate = activeTask?.deduplicate ?? true;
  const duplicateCount = activeTask?.duplicateCount ?? 0;
  const truncatedCount = activeTask?.truncatedCount ?? 0;

  const handleFileLoaded = (name: string, content: string) => {
    const parsed = parseCsvText(content);
    if (parsed.headers.length === 0 || parsed.rows.length === 0) {
      setUploadError('No rows were found in the uploaded CSV file.');
      return;
    }
    setUploadError(null);

    const colIdx = parsed.detectedWebsiteColumnIndex;
    const dedup = activeTask ? activeTask.deduplicate : true;
    const built = buildRowsFromExtraction(parsed, colIdx, dedup);
    const now = Date.now();

    if (!activeTask) {
      const newTask: BulkScanTask = {
        id: createTaskId(),
        name: deriveTaskName(name),
        fileName: name,
        createdAt: now,
        updatedAt: now,
        parsedCsv: parsed,
        selectedColumnIndex: colIdx,
        deduplicate: dedup,
        duplicateCount: built.duplicateCount,
        truncatedCount: built.truncatedCount,
        rows: built.rows,
      };
      onCreateTask(newTask);
      return;
    }

    onUpdateTask(activeTask.id, (prev) => ({
      ...prev,
      name: deriveTaskName(name),
      fileName: name,
      parsedCsv: parsed,
      selectedColumnIndex: colIdx,
      duplicateCount: built.duplicateCount,
      truncatedCount: built.truncatedCount,
      rows: built.rows,
    }));
  };

  const handleColumnChange = (colIdx: number) => {
    if (!activeTask) return;
    const built = buildRowsFromExtraction(activeTask.parsedCsv, colIdx, activeTask.deduplicate);
    onUpdateTask(activeTask.id, (prev) => ({
      ...prev,
      selectedColumnIndex: colIdx,
      duplicateCount: built.duplicateCount,
      truncatedCount: built.truncatedCount,
      rows: built.rows,
    }));
  };

  const handleDeduplicateChange = (checked: boolean) => {
    if (!activeTask) return;
    const built = buildRowsFromExtraction(
      activeTask.parsedCsv,
      activeTask.selectedColumnIndex,
      checked
    );
    onUpdateTask(activeTask.id, (prev) => ({
      ...prev,
      deduplicate: checked,
      duplicateCount: built.duplicateCount,
      truncatedCount: built.truncatedCount,
      rows: built.rows,
    }));
  };

  const handleDeleteCurrentTask = () => {
    if (!activeTask) return;
    abortControllerRef.current?.abort();
    setIsScanning(false);
    onScanningTaskChange(null);
    onDeleteTask(activeTask.id);
  };

  const executeScanQueue = async (
    taskId: string,
    snapshotRows: BulkScanRow[],
    targetIds: string[]
  ) => {
    if (targetIds.length === 0) return;

    abortControllerRef.current?.abort();
    const controller = new AbortController();
    abortControllerRef.current = controller;
    setIsScanning(true);
    onScanningTaskChange(taskId);

    const updateTaskRows = (rowUpdater: (prevRows: BulkScanRow[]) => BulkScanRow[]) => {
      onUpdateTask(taskId, (task) => ({
        ...task,
        rows: rowUpdater(task.rows),
      }));
    };

    // Reset only the targeted rows to pending before scanning
    const targetSet = new Set(targetIds);
    updateTaskRows((prev) =>
      prev.map((row) =>
        targetSet.has(row.id) && row.normalizedUrl
          ? { ...row, status: 'pending', errors: [], failureReason: null }
          : row
      )
    );

    const queue = snapshotRows.filter((r) => targetSet.has(r.id) && r.normalizedUrl);
    let cursor = 0;

    const worker = async () => {
      while (cursor < queue.length && !controller.signal.aborted) {
        const item = queue[cursor++];
        if (!item.normalizedUrl) continue;

        updateTaskRows((prev) =>
          prev.map((r) => (r.id === item.id ? { ...r, status: 'scanning' } : r))
        );

        try {
          const outcome = await scanSingleUrlRequest(item.normalizedUrl, controller.signal);
          if (controller.signal.aborted) {
            updateTaskRows((prev) =>
              prev.map((r) =>
                r.id === item.id && r.status === 'scanning' ? { ...r, status: 'pending' } : r
              )
            );
            break;
          }

          if (outcome.ok) {
            updateTaskRows((prev) =>
              prev.map((r) =>
                r.id === item.id
                  ? {
                      ...r,
                      status: outcome.errors.length > 0 ? 'errors' : 'clean',
                      errors: outcome.errors,
                      failureReason: null,
                    }
                  : r
              )
            );
          } else {
            updateTaskRows((prev) =>
              prev.map((r) =>
                r.id === item.id
                  ? {
                      ...r,
                      status: 'failed',
                      errors: [],
                      failureReason: outcome.error,
                    }
                  : r
              )
            );
          }
        } catch (err) {
          if ((err as Error)?.name === 'AbortError') {
            updateTaskRows((prev) =>
              prev.map((r) =>
                r.id === item.id && r.status === 'scanning' ? { ...r, status: 'pending' } : r
              )
            );
            break;
          }
          updateTaskRows((prev) =>
            prev.map((r) =>
              r.id === item.id
                ? {
                    ...r,
                    status: 'failed',
                    errors: [],
                    failureReason: 'Network error while contacting the scanner service.',
                  }
                : r
            )
          );
        }
      }
    };

    try {
      const workers = Array.from(
        { length: Math.min(BULK_CONCURRENCY, queue.length) },
        () => worker()
      );
      await Promise.all(workers);
    } finally {
      if (abortControllerRef.current === controller) {
        setIsScanning(false);
        onScanningTaskChange(null);
        abortControllerRef.current = null;
      }
    }
  };

  const handleStartScan = () => {
    if (!activeTask) return;
    const validIds = activeTask.rows.filter((r) => r.normalizedUrl).map((r) => r.id);
    if (validIds.length === 0) return;
    void executeScanQueue(activeTask.id, activeTask.rows, validIds);
  };

  const handleResumeScan = () => {
    if (!activeTask || isScanning) return;
    const pendingIds = getPendingRowIds(activeTask.rows);
    if (pendingIds.length === 0) return;
    void executeScanQueue(activeTask.id, activeTask.rows, pendingIds);
  };

  const handleRescanFailed = () => {
    if (!activeTask || isScanning) return;
    const failedIds = getFailedRowIds(activeTask.rows);
    if (failedIds.length === 0) return;
    void executeScanQueue(activeTask.id, activeTask.rows, failedIds);
  };

  const handleStopScan = () => {
    abortControllerRef.current?.abort();
  };

  const handleRescanRow = (rowId: string) => {
    if (!activeTask || isScanning) return;
    void executeScanQueue(activeTask.id, activeTask.rows, [rowId]);
  };

  const handleExportCsv = () => {
    const csvContent = buildResultsCsv(
      rows.map((r) => ({
        website: r.normalizedUrl || r.rawValue,
        status:
          r.status === 'errors'
            ? 'Errors Found'
            : r.status === 'clean'
              ? 'No Errors Found'
              : r.status === 'invalid'
                ? 'Invalid URL'
                : r.status === 'failed'
                  ? 'Scan Failed'
                  : 'Pending',
        errors:
          r.status === 'errors'
            ? r.errors
            : r.status === 'invalid' || r.status === 'failed'
              ? [r.failureReason || 'Invalid URL']
              : [],
      }))
    );

    const safePrefix = (taskName || 'wordpressfixer')
      .toLowerCase()
      .replace(/[^a-z0-9-_]+/g, '-')
      .replace(/^-+|-+$/g, '');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${safePrefix || 'wordpressfixer'}-scan-results.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const metrics = useMemo(() => {
    let validCount = 0;
    let invalidCount = 0;
    let scannedCount = 0;
    let failedOrErrorCount = 0;
    let cleanCount = 0;
    let pendingCount = 0;

    for (const r of rows) {
      if (r.normalizedUrl) validCount++;
      else invalidCount++;

      if (r.status === 'errors' || r.status === 'failed') {
        scannedCount++;
        failedOrErrorCount++;
      } else if (r.status === 'clean') {
        scannedCount++;
        cleanCount++;
      } else if ((r.status === 'pending' || r.status === 'scanning') && r.normalizedUrl) {
        pendingCount++;
      }
    }

    return {
      total: rows.length,
      validCount,
      invalidCount,
      scannedCount,
      failedOrErrorCount,
      cleanCount,
      pendingCount,
    };
  }, [rows]);

  const previewValues = useMemo(
    () => rows.slice(0, 3).map((r) => r.rawValue),
    [rows]
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 text-balance">
          Website Error Scanner
        </h1>
        <p className="mt-1.5 text-sm sm:text-base text-slate-600">
          Scan your website for publicly detectable errors and issues.
        </p>
      </div>

      {/* Dashboard Summary Strip */}
      <div
        data-testid="dashboard-summary"
        className="bg-white border border-slate-200/90 rounded-xl shadow-[0_1px_2px_rgba(15,23,42,0.03)] grid grid-cols-2 lg:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-slate-200/80"
      >
        <div className="p-4 sm:p-5">
          <p className="text-xs font-medium text-slate-500">Total Websites</p>
          <p className="mt-1.5 text-2xl font-bold text-slate-900 font-mono tabular-nums">
            {metrics.total}
          </p>
        </div>

        <div className="p-4 sm:p-5">
          <p className="text-xs font-medium text-slate-500">Scanned</p>
          <p className="mt-1.5 text-2xl font-bold text-slate-900 font-mono tabular-nums">
            {metrics.scannedCount}
            <span className="text-sm font-normal text-slate-400"> / {metrics.validCount}</span>
          </p>
        </div>

        <div className="p-4 sm:p-5">
          <p className="text-xs font-medium text-slate-500">With Errors</p>
          <p className="mt-1.5 text-2xl font-bold text-red-600 font-mono tabular-nums">
            {metrics.failedOrErrorCount}
          </p>
        </div>

        <div className="p-4 sm:p-5">
          <p className="text-xs font-medium text-slate-500">No Errors Found</p>
          <p className="mt-1.5 text-2xl font-bold text-emerald-600 font-mono tabular-nums">
            {metrics.cleanCount}
          </p>
        </div>
      </div>

      <BulkCsvUploader
        taskName={taskName}
        fileName={fileName}
        parsedCsv={parsedCsv}
        selectedColumnIndex={selectedColumnIndex}
        deduplicate={deduplicate}
        validCount={metrics.validCount}
        invalidCount={metrics.invalidCount}
        duplicateCount={duplicateCount}
        truncatedCount={truncatedCount}
        pendingCount={metrics.pendingCount}
        previewValues={previewValues}
        uploadError={uploadError}
        isScanning={isScanning}
        hasCompletedAny={metrics.scannedCount > 0}
        onFileLoaded={handleFileLoaded}
        onUploadError={setUploadError}
        onColumnChange={handleColumnChange}
        onDeduplicateChange={handleDeduplicateChange}
        onStartScan={handleStartScan}
        onResumeScan={handleResumeScan}
        onStopScan={handleStopScan}
        onNewTask={onNewTask}
        onDeleteTask={handleDeleteCurrentTask}
      />

      {rows.length > 0 && activeTask && (
        <BulkResultsTable
          key={activeTask.id}
          rows={rows}
          isScanning={isScanning}
          scannedCount={metrics.scannedCount}
          scannableCount={metrics.validCount}
          failedCount={metrics.failedOrErrorCount}
          onRescanRow={handleRescanRow}
          onRescanFailed={handleRescanFailed}
          onExportCsv={handleExportCsv}
        />
      )}
    </div>
  );
}
