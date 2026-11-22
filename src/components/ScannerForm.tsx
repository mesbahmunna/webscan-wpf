import type { FormEvent, RefObject } from 'react';
import { AlertCircle, Globe, Search, X } from 'lucide-react';

interface ScannerFormProps {
  url: string;
  onUrlChange: (value: string) => void;
  onSubmit: (e: FormEvent<HTMLFormElement>) => void;
  isScanning: boolean;
  validationError: string | null;
  inputRef: RefObject<HTMLInputElement | null>;
}

export function ScannerForm({
  url,
  onUrlChange,
  onSubmit,
  isScanning,
  validationError,
  inputRef,
}: ScannerFormProps) {
  return (
    <form onSubmit={onSubmit} noValidate aria-label="Website Error Scanner Form">
      <label htmlFor="website-url" className="block text-sm font-medium text-slate-700 mb-2">
        Website URL
      </label>

      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
        <div className="relative flex-1 min-w-0">
          <Globe
            className="w-4.5 h-4.5 text-slate-400 pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2"
            aria-hidden="true"
          />
          <input
            ref={inputRef}
            id="website-url"
            name="url"
            type="text"
            inputMode="url"
            autoComplete="url"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            value={url}
            onChange={(e) => onUrlChange(e.target.value)}
            disabled={isScanning}
            placeholder="https://example.com"
            aria-invalid={Boolean(validationError)}
            aria-describedby={validationError ? 'url-validation-error' : undefined}
            className={`w-full h-12 pl-10 pr-10 rounded-lg border bg-white font-mono text-sm text-slate-900 placeholder:text-slate-400 transition-colors focus:outline-none focus:ring-2 ${
              validationError
                ? 'border-red-300 focus:border-red-500 focus:ring-red-500/15'
                : 'border-slate-300 hover:border-slate-400 focus:border-[#1D4ED8] focus:ring-[#1D4ED8]/15'
            } disabled:bg-slate-50 disabled:text-slate-500 disabled:cursor-not-allowed`}
          />
          {url.length > 0 && !isScanning && (
            <button
              type="button"
              onClick={() => {
                onUrlChange('');
                inputRef.current?.focus();
              }}
              aria-label="Clear website URL"
              className="absolute right-2.5 top-1/2 -translate-y-1/2 w-7 h-7 inline-flex items-center justify-center rounded-md text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#1D4ED8]"
            >
              <X className="w-4 h-4" aria-hidden="true" />
            </button>
          )}
        </div>

        <button
          type="submit"
          disabled={isScanning}
          className="h-12 px-6 rounded-lg bg-[#1D4ED8] hover:bg-[#1E40AF] active:bg-[#1E3A8A] disabled:bg-slate-300 disabled:text-slate-600 disabled:cursor-not-allowed text-white text-sm font-semibold inline-flex items-center justify-center gap-2 transition-colors whitespace-nowrap shrink-0 shadow-[0_1px_2px_rgba(15,23,42,0.08)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#1D4ED8] focus-visible:ring-offset-2 cursor-pointer"
        >
          <Search className="w-4 h-4 shrink-0" aria-hidden="true" />
          <span>{isScanning ? 'Scanning…' : 'Scan Website'}</span>
        </button>
      </div>

      {validationError && (
        <p
          id="url-validation-error"
          role="alert"
          className="mt-2.5 flex items-center gap-2 text-sm text-red-700"
        >
          <AlertCircle className="w-4 h-4 shrink-0 text-red-600" aria-hidden="true" />
          <span>{validationError}</span>
        </p>
      )}
    </form>
  );
}
