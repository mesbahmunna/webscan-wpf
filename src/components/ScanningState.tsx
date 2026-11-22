import { motion } from 'motion/react';
import { Loader2 } from 'lucide-react';

interface ScanningStateProps {
  targetUrl: string;
}

export function ScanningState({ targetUrl }: ScanningStateProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -4 }}
      transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
      role="status"
      aria-live="polite"
      className="pt-6 mt-6 border-t border-slate-200"
    >
      <div className="flex items-center gap-3">
        <Loader2 className="w-5 h-5 text-[#1D4ED8] animate-spin shrink-0" aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-slate-900">Scanning website…</p>
          <p className="text-xs font-mono text-slate-500 truncate mt-0.5">{targetUrl}</p>
        </div>
      </div>

      <div
        className="mt-4 h-1.5 w-full rounded-full bg-slate-100 overflow-hidden"
        aria-hidden="true"
      >
        <div className="h-full w-1/2 rounded-full bg-[#1D4ED8] animate-scan-bar" />
      </div>
    </motion.div>
  );
}
