import { motion } from 'motion/react';
import { AlertCircle, CheckCircle2, RotateCcw } from 'lucide-react';

interface ScanResultsProps {
  errors: string[];
  onScanAgain: () => void;
}

export function ScanResults({ errors, onScanAgain }: ScanResultsProps) {
  const hasErrors = errors.length > 0;

  return (
    <motion.section
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
      aria-labelledby="scan-results-heading"
      data-testid="scan-results"
      className="pt-6 mt-6 border-t border-slate-200"
    >
      <div className="flex items-center justify-between gap-3 mb-4">
        <h2 id="scan-results-heading" className="text-base font-semibold text-slate-900">
          Scan Results
        </h2>

        <button
          type="button"
          onClick={onScanAgain}
          className="h-9 px-3.5 rounded-lg border border-slate-300 bg-white hover:bg-slate-50 hover:border-slate-400 text-slate-700 text-xs font-semibold inline-flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#1D4ED8] focus-visible:ring-offset-2"
        >
          <RotateCcw className="w-3.5 h-3.5" aria-hidden="true" />
          <span>Scan Again</span>
        </button>
      </div>

      {hasErrors ? (
        <ul
          data-testid="error-list"
          className="divide-y divide-slate-100 border-t border-b border-slate-200/80"
        >
          {errors.map((errorName) => (
            <li
              key={errorName}
              className="py-3.5 flex items-center gap-3 text-[14.5px] font-medium text-slate-800"
            >
              <AlertCircle
                className="w-4 h-4 text-red-600 shrink-0"
                aria-hidden="true"
              />
              <span className="leading-snug">{errorName}</span>
            </li>
          ))}
        </ul>
      ) : (
        <div
          data-testid="no-errors-found"
          className="py-9 px-4 flex flex-col items-center justify-center text-center border-t border-b border-slate-200/80"
        >
          <CheckCircle2 className="w-7 h-7 text-emerald-600 mb-2.5" aria-hidden="true" />
          <p className="text-base font-semibold text-slate-900">No Errors Found</p>
        </div>
      )}
    </motion.section>
  );
}
