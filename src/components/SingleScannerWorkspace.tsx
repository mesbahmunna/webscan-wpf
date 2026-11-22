import { useRef, useState, type FormEvent } from 'react';
import { AnimatePresence } from 'motion/react';
import { ScannerForm } from './ScannerForm';
import { ScanningState } from './ScanningState';
import { ScanResults } from './ScanResults';
import { validateClientUrl } from '../utils/urlValidation';

interface ScanResultState {
  scannedUrl: string;
  errors: string[];
}

export function SingleScannerWorkspace() {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [activeTarget, setActiveTarget] = useState('');
  const [validationError, setValidationError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResultState | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  const handleUrlChange = (value: string) => {
    setUrl(value);
    if (validationError) {
      setValidationError(null);
    }
  };

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (isScanning) return;

    const validation = validateClientUrl(url);
    if (!validation.valid || !validation.normalized) {
      setValidationError(validation.error || 'Please enter a valid HTTP or HTTPS website URL.');
      return;
    }

    setValidationError(null);
    setResult(null);
    setActiveTarget(validation.normalized);
    setIsScanning(true);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: validation.normalized }),
      });

      const payload = (await response.json().catch(() => ({}))) as {
        scannedUrl?: string;
        errors?: string[];
        error?: string;
      };

      if (!response.ok) {
        setValidationError(
          payload.error || 'Unable to scan this website right now. Please try again.'
        );
        return;
      }

      setResult({
        scannedUrl: payload.scannedUrl || validation.normalized,
        errors: Array.isArray(payload.errors) ? payload.errors : [],
      });
    } catch {
      setValidationError('Network error while contacting the scanner service. Please try again.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleScanAgain = () => {
    setResult(null);
    setValidationError(null);
    setUrl('');
    setActiveTarget('');
    setTimeout(() => {
      inputRef.current?.focus();
    }, 20);
  };

  return (
    <div className="max-w-3xl space-y-6">
      <div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 text-balance">
          Website Error Scanner
        </h1>
        <p className="mt-1.5 text-sm sm:text-base text-slate-600">
          Scan your website for publicly detectable errors and issues.
        </p>
      </div>

      <div className="bg-white border border-slate-200/90 rounded-xl shadow-[0_1px_2px_rgba(15,23,42,0.03)] p-5 sm:p-7">
        <ScannerForm
          url={url}
          onUrlChange={handleUrlChange}
          onSubmit={handleSubmit}
          isScanning={isScanning}
          validationError={validationError}
          inputRef={inputRef}
        />

        <AnimatePresence mode="wait">
          {isScanning && <ScanningState key="scanning" targetUrl={activeTarget} />}
          {!isScanning && result && (
            <ScanResults
              key="results"
              errors={result.errors}
              onScanAgain={handleScanAgain}
            />
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
