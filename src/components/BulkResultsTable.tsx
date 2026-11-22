import { useMemo, useState } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Clock,
  Download,
  Loader2,
  RotateCcw,
  Search,
  XCircle,
} from 'lucide-react';

const PAGE_SIZE = 100;

export type BulkRowStatus =
  | 'pending'
  | 'scanning'
  | 'errors'
  | 'clean'
  | 'invalid'
  | 'failed';

export interface BulkScanRow {
  id: string;
  rowIndex: number;
  rawValue: string;
  normalizedUrl: string | null;
  status: BulkRowStatus;
  errors: string[];
  failureReason: string | null;
}

type StatusFilter = 'all' | 'errors' | 'clean' | 'pending' | 'invalid';

interface BulkResultsTableProps {
  rows: BulkScanRow[];
  isScanning: boolean;
  scannedCount: number;
  scannableCount: number;
  failedCount: number;
  onRescanRow: (rowId: string) => void;
  onRescanFailed: () => void;
  onExportCsv: () => void;
}

export function BulkResultsTable({
  rows,
  isScanning,
  scannedCount,
  scannableCount,
  failedCount,
  onRescanRow,
  onRescanFailed,
  onExportCsv,
}: BulkResultsTableProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [currentPage, setCurrentPage] = useState(1);

  const counts = useMemo(() => {
    let errors = 0;
    let clean = 0;
    let pending = 0;
    let invalid = 0;
    for (const r of rows) {
      if (r.status === 'errors' || r.status === 'failed') errors++;
      else if (r.status === 'clean') clean++;
      else if (r.status === 'pending' || r.status === 'scanning') pending++;
      else if (r.status === 'invalid') invalid++;
    }
    return { all: rows.length, errors, clean, pending, invalid };
  }, [rows]);

  const filteredRows = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return rows.filter((row) => {
      if (statusFilter === 'errors' && row.status !== 'errors' && row.status !== 'failed') {
        return false;
      }
      if (statusFilter === 'clean' && row.status !== 'clean') return false;
      if (statusFilter === 'pending' && row.status !== 'pending' && row.status !== 'scanning') {
        return false;
      }
      if (statusFilter === 'invalid' && row.status !== 'invalid') return false;

      if (!q) return true;
      const inUrl = (row.normalizedUrl || row.rawValue).toLowerCase().includes(q);
      const inErrors = row.errors.some((e) => e.toLowerCase().includes(q));
      return inUrl || inErrors;
    });
  }, [rows, searchQuery, statusFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredRows.length / PAGE_SIZE));
  const safePage = Math.min(currentPage, totalPages);
  const pageStartIdx = (safePage - 1) * PAGE_SIZE;
  const paginatedRows = useMemo(
    () => filteredRows.slice(pageStartIdx, pageStartIdx + PAGE_SIZE),
    [filteredRows, pageStartIdx]
  );

  const progressPct =
    scannableCount > 0 ? Math.min(100, Math.round((scannedCount / scannableCount) * 100)) : 0;

  const canExport = rows.some((r) => r.status === 'errors' || r.status === 'clean' || r.status === 'invalid' || r.status === 'failed');

  const filters: Array<{ id: StatusFilter; label: string; count: number }> = [
    { id: 'all', label: 'All', count: counts.all },
    { id: 'errors', label: 'Errors Found', count: counts.errors },
    { id: 'clean', label: 'No Errors Found', count: counts.clean },
    { id: 'pending', label: 'Pending', count: counts.pending },
    { id: 'invalid', label: 'Invalid', count: counts.invalid },
  ];

  return (
    <section
      aria-labelledby="bulk-results-heading"
      data-testid="bulk-results-section"
      className="bg-white border border-slate-200/90 rounded-xl shadow-[0_1px_2px_rgba(15,23,42,0.03)] overflow-hidden"
    >
      {isScanning && (
        <div
          role="status"
          aria-live="polite"
          className="px-5 sm:px-6 py-3 bg-[#EFF6FF]/70 border-b border-blue-100"
        >
          <div className="flex items-center justify-between gap-3 text-xs font-medium text-[#1E3A8A]">
            <span className="inline-flex items-center gap-2">
              <Loader2 className="w-3.5 h-3.5 animate-spin text-[#1D4ED8]" aria-hidden="true" />
              <span>Scanning websites…</span>
            </span>
            <span className="font-mono tabular-nums">
              {scannedCount} / {scannableCount} ({progressPct}%)
            </span>
          </div>
          <div className="mt-2 h-1.5 w-full rounded-full bg-blue-100 overflow-hidden" aria-hidden="true">
            <div
              className="h-full rounded-full bg-[#1D4ED8] transition-transform duration-300 origin-left"
              style={{ transform: `scaleX(${Math.max(0.04, progressPct / 100)})` }}
            />
          </div>
        </div>
      )}

      <div className="px-5 sm:px-6 py-4 border-b border-slate-200/80 flex flex-col gap-3.5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 id="bulk-results-heading" className="text-base font-semibold text-slate-900">
            Scan Results
          </h2>

          <div className="flex flex-wrap items-center gap-2.5">
            <div className="relative">
              <Search
                className="w-3.5 h-3.5 text-slate-400 pointer-events-none absolute left-3 top-1/2 -translate-y-1/2"
                aria-hidden="true"
              />
              <input
                type="search"
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setCurrentPage(1);
                }}
                placeholder="Filter URL or error…"
                aria-label="Filter results by website URL or error name"
                className="h-9 w-48 sm:w-60 pl-8 pr-3 rounded-lg border border-slate-300 bg-white text-xs text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-[#1D4ED8] focus:ring-2 focus:ring-[#1D4ED8]/15"
              />
            </div>

            {!isScanning && failedCount > 0 && (
              <button
                type="button"
                onClick={onRescanFailed}
                data-testid="rescan-all-failed-btn"
                className="h-9 px-3.5 rounded-lg border border-red-200 bg-red-50/75 hover:bg-red-100/80 hover:border-red-300 text-red-700 text-xs font-semibold inline-flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-600 focus-visible:ring-offset-2"
              >
                <RotateCcw className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Rescan All Failed ({failedCount})</span>
              </button>
            )}

            <button
              type="button"
              disabled={!canExport}
              onClick={onExportCsv}
              className="h-9 px-3.5 rounded-lg border border-slate-300 bg-white hover:bg-slate-50 hover:border-slate-400 disabled:opacity-45 disabled:cursor-not-allowed text-slate-700 text-xs font-semibold inline-flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#1D4ED8] focus-visible:ring-offset-2"
            >
              <Download className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Export CSV</span>
            </button>
          </div>
        </div>

        <div
          role="tablist"
          aria-label="Filter scan results by status"
          className="flex items-center gap-1 p-1 bg-slate-100 rounded-lg overflow-x-auto"
        >
          {filters.map((tab) => {
            const active = statusFilter === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => {
                  setStatusFilter(tab.id);
                  setCurrentPage(1);
                }}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer inline-flex items-center gap-1.5 ${
                  active
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <span>{tab.label}</span>
                <span className="font-mono tabular-nums text-[11px] text-slate-400">
                  {tab.count}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse" data-testid="bulk-results-table">
          <thead>
            <tr className="border-b border-slate-200 bg-slate-50/70 text-xs font-semibold text-slate-600">
              <th scope="col" className="py-3 pl-5 sm:pl-6 pr-3 w-12 font-mono">
                #
              </th>
              <th scope="col" className="py-3 px-3 min-w-[210px]">
                Website
              </th>
              <th scope="col" className="py-3 px-3 w-40">
                Status
              </th>
              <th scope="col" className="py-3 px-3 min-w-[280px]">
                Detected Errors
              </th>
              <th scope="col" className="py-3 pl-3 pr-5 sm:pr-6 w-24 text-right">
                Action
              </th>
            </tr>
          </thead>

          <tbody className="divide-y divide-slate-100 text-sm">
            {paginatedRows.length === 0 ? (
              <tr>
                <td colSpan={5} className="py-10 px-6 text-center text-sm text-slate-500">
                  No websites match the current filter.
                </td>
              </tr>
            ) : (
              paginatedRows.map((row) => (
                <tr
                  key={row.id}
                  data-testid="bulk-result-row"
                  className="align-top hover:bg-slate-50/60 transition-colors"
                >
                  <td className="py-3.5 pl-5 sm:pl-6 pr-3 font-mono text-xs text-slate-400 tabular-nums">
                    {row.rowIndex}
                  </td>

                  <td className="py-3.5 px-3">
                    <div className="font-mono text-[13px] text-slate-900 break-all">
                      {row.normalizedUrl || row.rawValue}
                    </div>
                  </td>

                  <td className="py-3.5 px-3 whitespace-nowrap">
                    {row.status === 'pending' && (
                      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-500">
                        <Clock className="w-3.5 h-3.5 text-slate-400" aria-hidden="true" />
                        <span>Pending</span>
                      </span>
                    )}
                    {row.status === 'scanning' && (
                      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-[#1D4ED8]">
                        <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                        <span>Scanning…</span>
                      </span>
                    )}
                    {row.status === 'errors' && (
                      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-700">
                        <AlertCircle className="w-3.5 h-3.5 text-red-600" aria-hidden="true" />
                        <span className="font-mono tabular-nums">
                          {row.errors.length} {row.errors.length === 1 ? 'Error' : 'Errors'}
                        </span>
                      </span>
                    )}
                    {row.status === 'clean' && (
                      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-700">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" aria-hidden="true" />
                        <span>No Errors Found</span>
                      </span>
                    )}
                    {row.status === 'invalid' && (
                      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-amber-700">
                        <XCircle className="w-3.5 h-3.5 text-amber-600" aria-hidden="true" />
                        <span>Invalid URL</span>
                      </span>
                    )}
                    {row.status === 'failed' && (
                      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-red-700">
                        <AlertCircle className="w-3.5 h-3.5 text-red-600" aria-hidden="true" />
                        <span>Scan Failed</span>
                      </span>
                    )}
                  </td>

                  <td className="py-3.5 px-3">
                    {row.status === 'errors' && (
                      <ul className="space-y-1.5" data-testid="row-error-list">
                        {row.errors.map((errName) => (
                          <li
                            key={errName}
                            className="flex items-start gap-2 text-[13.5px] font-medium text-slate-800 leading-snug"
                          >
                            <AlertCircle
                              className="w-3.5 h-3.5 text-red-600 shrink-0 mt-0.5"
                              aria-hidden="true"
                            />
                            <span>{errName}</span>
                          </li>
                        ))}
                      </ul>
                    )}

                    {row.status === 'clean' && (
                      <span className="inline-flex items-center gap-1.5 text-[13.5px] font-medium text-slate-700">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" aria-hidden="true" />
                        <span>No Errors Found</span>
                      </span>
                    )}

                    {row.status === 'pending' && (
                      <span className="text-xs text-slate-400">Waiting to scan</span>
                    )}

                    {row.status === 'scanning' && (
                      <span className="text-xs text-slate-500">Checking website…</span>
                    )}

                    {(row.status === 'invalid' || row.status === 'failed') && (
                      <span className="text-xs text-slate-600">
                        {row.failureReason || 'Invalid website URL.'}
                      </span>
                    )}
                  </td>

                  <td className="py-3.5 pl-3 pr-5 sm:pr-6 text-right whitespace-nowrap">
                    {row.normalizedUrl &&
                      row.status !== 'scanning' &&
                      !isScanning && (
                        <button
                          type="button"
                          onClick={() => onRescanRow(row.id)}
                          aria-label={`Scan ${row.normalizedUrl} again`}
                          className="h-8 px-2.5 rounded-md border border-slate-200 bg-white hover:bg-slate-50 hover:border-slate-300 text-slate-600 hover:text-slate-900 text-xs font-medium inline-flex items-center gap-1 transition-colors cursor-pointer"
                        >
                          <RotateCcw className="w-3 h-3" aria-hidden="true" />
                          <span>Scan</span>
                        </button>
                      )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {filteredRows.length > PAGE_SIZE && (
        <div
          data-testid="bulk-results-pagination"
          className="px-5 sm:px-6 py-3.5 border-t border-slate-200/80 bg-slate-50/50 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-600"
        >
          <span className="font-mono tabular-nums">
            Showing {pageStartIdx + 1}–{Math.min(pageStartIdx + PAGE_SIZE, filteredRows.length)} of{' '}
            {filteredRows.length.toLocaleString()} websites
          </span>

          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={safePage <= 1}
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              className="h-8 px-2.5 rounded-md border border-slate-300 bg-white hover:bg-slate-50 disabled:opacity-45 disabled:cursor-not-allowed text-slate-700 font-medium inline-flex items-center gap-1 transition-colors whitespace-nowrap cursor-pointer"
            >
              <ChevronLeft className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Previous</span>
            </button>
            <span className="font-mono tabular-nums px-1.5 text-slate-500">
              Page {safePage} / {totalPages}
            </span>
            <button
              type="button"
              disabled={safePage >= totalPages}
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              className="h-8 px-2.5 rounded-md border border-slate-300 bg-white hover:bg-slate-50 disabled:opacity-45 disabled:cursor-not-allowed text-slate-700 font-medium inline-flex items-center gap-1 transition-colors whitespace-nowrap cursor-pointer"
            >
              <span>Next</span>
              <ChevronRight className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
