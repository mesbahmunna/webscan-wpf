import { useRef, useState, type ChangeEvent, type DragEvent } from 'react';
import {
  AlertCircle,
  Download,
  FileSpreadsheet,
  Play,
  Plus,
  RotateCcw,
  Square,
  Trash2,
  Upload,
} from 'lucide-react';
import { SAMPLE_CSV_CONTENT, type ParsedCsvData } from '../utils/csvParser';

interface BulkCsvUploaderProps {
  taskName: string | null;
  fileName: string | null;
  parsedCsv: ParsedCsvData | null;
  selectedColumnIndex: number;
  deduplicate: boolean;
  validCount: number;
  invalidCount: number;
  duplicateCount: number;
  truncatedCount: number;
  pendingCount: number;
  previewValues: string[];
  uploadError: string | null;
  isScanning: boolean;
  hasCompletedAny: boolean;
  onFileLoaded: (fileName: string, content: string) => void;
  onUploadError: (message: string) => void;
  onColumnChange: (index: number) => void;
  onDeduplicateChange: (checked: boolean) => void;
  onStartScan: () => void;
  onResumeScan: () => void;
  onStopScan: () => void;
  onNewTask: () => void;
  onDeleteTask: () => void;
}

export function BulkCsvUploader({
  taskName,
  fileName,
  parsedCsv,
  selectedColumnIndex,
  deduplicate,
  validCount,
  invalidCount,
  duplicateCount,
  truncatedCount,
  pendingCount,
  previewValues,
  uploadError,
  isScanning,
  hasCompletedAny,
  onFileLoaded,
  onUploadError,
  onColumnChange,
  onDeduplicateChange,
  onStartScan,
  onResumeScan,
  onStopScan,
  onNewTask,
  onDeleteTask,
}: BulkCsvUploaderProps) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const readCsvFile = (file: File) => {
    const isCsvName = file.name.toLowerCase().endsWith('.csv');
    const isCsvMime =
      file.type === 'text/csv' ||
      file.type === 'application/vnd.ms-excel' ||
      file.type === 'text/plain' ||
      file.type === '';

    if (!isCsvName && !isCsvMime) {
      onUploadError('Please upload a valid .csv file.');
      return;
    }

    if (file.size === 0) {
      onUploadError('The uploaded CSV file is empty.');
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const content = typeof reader.result === 'string' ? reader.result : '';
      onFileLoaded(file.name, content);
    };
    reader.onerror = () => {
      onUploadError('Unable to read the selected CSV file.');
    };
    reader.readAsText(file);
  };

  const handleFileInput = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      readCsvFile(file);
    }
    e.target.value = '';
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    if (isScanning) return;
    const file = e.dataTransfer.files?.[0];
    if (file) {
      readCsvFile(file);
    }
  };

  const handleDownloadSample = () => {
    const blob = new Blob([SAMPLE_CSV_CONTENT], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'wordpressfixer-sample-websites.csv';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const canResume = !isScanning && hasCompletedAny && pendingCount > 0;

  return (
    <section
      aria-label="Bulk CSV Upload and Column Mapping"
      className="bg-white border border-slate-200/90 rounded-xl shadow-[0_1px_2px_rgba(15,23,42,0.03)] p-5 sm:p-6"
    >
      <input
        ref={fileInputRef}
        id="csv-file-input"
        type="file"
        accept=".csv,text/csv"
        onChange={handleFileInput}
        disabled={isScanning}
        className="sr-only"
      />

      {!parsedCsv ? (
        <div>
          <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
            <div>
              <h2 className="text-base font-semibold text-slate-900">Upload Website CSV</h2>
              <p className="text-sm text-slate-500 mt-0.5">
                Upload a CSV file to create a saved bulk scan task and choose the website URL column.
              </p>
            </div>

            <button
              type="button"
              onClick={handleDownloadSample}
              className="h-9 px-3.5 rounded-lg border border-slate-300 bg-white hover:bg-slate-50 hover:border-slate-400 text-slate-700 text-xs font-semibold inline-flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#1D4ED8] focus-visible:ring-offset-2"
            >
              <Download className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Download Sample CSV</span>
            </button>
          </div>

          <div
            onDragOver={(e) => {
              e.preventDefault();
              setIsDragging(true);
            }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
            className={`rounded-lg border-2 border-dashed p-8 text-center transition-colors ${
              isDragging
                ? 'border-[#1D4ED8] bg-[#EFF6FF]/60'
                : 'border-slate-300 bg-slate-50/50 hover:border-slate-400'
            }`}
          >
            <div className="w-11 h-11 rounded-lg bg-white border border-slate-200 mx-auto flex items-center justify-center text-[#1D4ED8] mb-3">
              <Upload className="w-5 h-5" aria-hidden="true" />
            </div>
            <p className="text-sm font-semibold text-slate-900">
              Drop your CSV file here, or browse from your computer
            </p>
            <p className="text-xs text-slate-500 mt-1">
              Saved automatically in this browser · Unlimited websites per CSV
            </p>

            <div className="mt-4">
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="h-10 px-5 rounded-lg bg-[#1D4ED8] hover:bg-[#1E40AF] active:bg-[#1E3A8A] text-white text-sm font-semibold inline-flex items-center gap-2 transition-colors whitespace-nowrap cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#1D4ED8] focus-visible:ring-offset-2"
              >
                <FileSpreadsheet className="w-4 h-4" aria-hidden="true" />
                <span>Choose CSV File</span>
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-200/80">
            <div className="flex items-center gap-3 min-w-0">
              <div className="w-10 h-10 rounded-lg bg-[#EFF6FF] text-[#1D4ED8] flex items-center justify-center shrink-0">
                <FileSpreadsheet className="w-5 h-5" aria-hidden="true" />
              </div>
              <div className="min-w-0">
                <p className="text-sm font-semibold text-slate-900 truncate" data-testid="csv-filename">
                  {taskName || fileName}
                </p>
                <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 mt-0.5 font-mono tabular-nums">
                  {fileName && fileName !== taskName && (
                    <>
                      <span className="truncate max-w-[180px]">{fileName}</span>
                      <span aria-hidden="true">·</span>
                    </>
                  )}
                  <span>{parsedCsv.rows.length} rows</span>
                  <span aria-hidden="true">·</span>
                  <span>{parsedCsv.headers.length} columns</span>
                  {duplicateCount > 0 && (
                    <>
                      <span aria-hidden="true">·</span>
                      <span>
                        {duplicateCount} {duplicateCount === 1 ? 'duplicate' : 'duplicates'} removed
                      </span>
                    </>
                  )}
                  {truncatedCount > 0 && (
                    <>
                      <span aria-hidden="true">·</span>
                      <span>{truncatedCount} over batch limit</span>
                    </>
                  )}
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 shrink-0">
              <button
                type="button"
                disabled={isScanning}
                onClick={onNewTask}
                className="h-9 px-3 rounded-lg border border-slate-300 bg-white hover:bg-slate-50 disabled:opacity-50 disabled:cursor-not-allowed text-slate-700 text-xs font-semibold inline-flex items-center gap-1.5 transition-colors whitespace-nowrap cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" aria-hidden="true" />
                <span>New Task</span>
              </button>
              <button
                type="button"
                disabled={isScanning}
                onClick={() => fileInputRef.current?.click()}
                className="h-9 px-3 rounded-lg border border-slate-300 bg-white hover:bg-slate-50 disabled:opacity-50 disabled:cursor-not-allowed text-slate-700 text-xs font-semibold inline-flex items-center gap-1.5 transition-colors whitespace-nowrap cursor-pointer"
              >
                <Upload className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Replace CSV</span>
              </button>
              <button
                type="button"
                disabled={isScanning}
                onClick={onDeleteTask}
                aria-label="Delete saved task"
                className="h-9 px-3 rounded-lg border border-slate-200 bg-white hover:bg-red-50 hover:border-red-200 hover:text-red-700 disabled:opacity-50 disabled:cursor-not-allowed text-slate-500 text-xs font-semibold inline-flex items-center gap-1.5 transition-colors whitespace-nowrap cursor-pointer"
              >
                <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Delete</span>
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end">
            <div className="md:col-span-5">
              <label
                htmlFor="website-column-select"
                className="block text-sm font-medium text-slate-700 mb-1.5"
              >
                Website Column
              </label>
              <select
                id="website-column-select"
                value={selectedColumnIndex}
                disabled={isScanning}
                onChange={(e) => onColumnChange(Number(e.target.value))}
                className="w-full h-11 px-3.5 rounded-lg border border-slate-300 bg-white text-sm font-medium text-slate-900 hover:border-slate-400 focus:outline-none focus:border-[#1D4ED8] focus:ring-2 focus:ring-[#1D4ED8]/15 disabled:bg-slate-50 disabled:text-slate-500 disabled:cursor-not-allowed"
              >
                {parsedCsv.headers.map((header, idx) => (
                  <option key={`${header}-${idx}`} value={idx}>
                    {header}
                  </option>
                ))}
              </select>
            </div>

            <div className="md:col-span-4 flex items-center h-11">
              <label className="inline-flex items-center gap-2.5 text-sm text-slate-700 select-none cursor-pointer">
                <input
                  type="checkbox"
                  checked={deduplicate}
                  disabled={isScanning}
                  onChange={(e) => onDeduplicateChange(e.target.checked)}
                  className="w-4 h-4 rounded border-slate-300 text-[#1D4ED8] focus:ring-[#1D4ED8]"
                />
                <span className="whitespace-nowrap">Deduplicate website URLs</span>
              </label>
            </div>

            <div className="md:col-span-3 flex items-center justify-stretch md:justify-end">
              {isScanning ? (
                <button
                  type="button"
                  onClick={onStopScan}
                  className="w-full md:w-auto h-11 px-5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-sm font-semibold inline-flex items-center justify-center gap-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-900 focus-visible:ring-offset-2"
                >
                  <Square className="w-3.5 h-3.5 fill-current" aria-hidden="true" />
                  <span>Stop Scan</span>
                </button>
              ) : canResume ? (
                <button
                  type="button"
                  onClick={onResumeScan}
                  data-testid="resume-scan-btn"
                  className="w-full md:w-auto h-11 px-5 rounded-lg bg-[#1D4ED8] hover:bg-[#1E40AF] active:bg-[#1E3A8A] text-white text-sm font-semibold inline-flex items-center justify-center gap-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#1D4ED8] focus-visible:ring-offset-2"
                >
                  <Play className="w-4 h-4 fill-current" aria-hidden="true" />
                  <span>Resume Scan ({pendingCount})</span>
                </button>
              ) : (
                <button
                  type="button"
                  disabled={validCount === 0}
                  onClick={onStartScan}
                  className="w-full md:w-auto h-11 px-5 rounded-lg bg-[#1D4ED8] hover:bg-[#1E40AF] active:bg-[#1E3A8A] disabled:bg-slate-300 disabled:text-slate-600 disabled:cursor-not-allowed text-white text-sm font-semibold inline-flex items-center justify-center gap-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#1D4ED8] focus-visible:ring-offset-2"
                >
                  {hasCompletedAny ? (
                    <>
                      <RotateCcw className="w-4 h-4" aria-hidden="true" />
                      <span>Scan All Again</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4 fill-current" aria-hidden="true" />
                      <span>Start Bulk Scan</span>
                    </>
                  )}
                </button>
              )}
            </div>
          </div>

          <div className="pt-3.5 border-t border-slate-100 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-500">
            <div className="flex flex-wrap items-center gap-2 min-w-0">
              <span className="font-medium text-slate-600">Column preview:</span>
              {previewValues.length > 0 ? (
                <span className="font-mono text-slate-700 truncate" data-testid="column-preview">
                  {previewValues.join(' · ')}
                </span>
              ) : (
                <span>No values in selected column</span>
              )}
            </div>

            <div className="flex items-center gap-2 font-mono tabular-nums shrink-0" data-testid="column-counts">
              <span className="text-slate-700 font-medium">{validCount} valid</span>
              {invalidCount > 0 && (
                <>
                  <span aria-hidden="true">·</span>
                  <span className="text-amber-700 font-medium">{invalidCount} invalid</span>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {uploadError && (
        <p role="alert" className="mt-3 flex items-center gap-2 text-sm text-red-700">
          <AlertCircle className="w-4 h-4 shrink-0 text-red-600" aria-hidden="true" />
          <span>{uploadError}</span>
        </p>
      )}
    </section>
  );
}
