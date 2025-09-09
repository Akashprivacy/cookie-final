import React, { useState, useCallback, useEffect, useRef } from 'react';
import { URLInputForm } from './URLInputForm';
import { ScanResultDisplay } from './ScanResultDisplay';
import { ScanningProgress } from './ScanningProgress';
import { AlertTriangleIcon } from './Icons';
import type { ScanResultData } from '../types';

// FIX: Use window.location.origin since frontend and backend are on same domain
const API_BASE_URL = (() => {
  // Check if we're in development (localhost)
  if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    return 'http://localhost:3001'; // Backend port in development
  }
  // In production, use the same origin
  return window.location.origin;
})();

// Debug logging to verify API URL
console.log('[FRONTEND] API_BASE_URL:', API_BASE_URL);
console.log('[FRONTEND] Current location:', window.location.href);

type ScanDepth = 'lite' | 'medium' | 'deep';

export const CookieScannerView: React.FC = () => {
  const [url, setUrl] = useState<string>('');
  const [scanDepth, setScanDepth] = useState<ScanDepth>('lite');
  const [scanResult, setScanResult] = useState<ScanResultData | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [scanLogs, setScanLogs] = useState<string[]>([]);
  const eventSourceRef = useRef<EventSource | null>(null);

  const handleScan = useCallback(() => {
    if (!url) {
      setError('Please enter a valid website URL.');
      return;
    }
    setError(null);
    setIsLoading(true);
    setScanResult(null);
    setScanLogs([]);

    const scanUrl = new URL(`${API_BASE_URL}/api/scan`);
    scanUrl.searchParams.append('url', url);
    scanUrl.searchParams.append('depth', scanDepth);

    console.log('[FRONTEND] Starting scan with URL:', scanUrl.toString());

    eventSourceRef.current = new EventSource(scanUrl.toString());

    eventSourceRef.current.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'log') {
          setScanLogs(prev => [...prev, data.message]);
        } else if (data.type === 'result') {
          setScanResult(data.payload);
          setIsLoading(false);
          eventSourceRef.current?.close();
        } else if (data.type === 'error') {
          setError(data.message);
          setIsLoading(false);
          eventSourceRef.current?.close();
        }
      } catch (e) {
        console.error("Failed to parse SSE message:", event.data);
      }
    };

    eventSourceRef.current.onerror = (event) => {
      console.error('[FRONTEND] EventSource error:', event);
      console.error('[FRONTEND] EventSource readyState:', eventSourceRef.current?.readyState);
      console.error('[FRONTEND] API URL being used:', scanUrl.toString());
      
      setError('A connection error occurred with the scanner service. The server might be down or busy.');
      setIsLoading(false);
      eventSourceRef.current?.close();
    };

    eventSourceRef.current.onopen = () => {
      console.log('[FRONTEND] EventSource connection opened successfully');
    };

  }, [url, scanDepth]);

  useEffect(() => {
    return () => {
      eventSourceRef.current?.close();
    };
  }, []);
  
  return (
    <>
      <div className="max-w-3xl mx-auto mt-6 space-y-6">
        {/* Debug info - remove this in production */}
        {process.env.NODE_ENV === 'development' && (
          <div className="bg-yellow-50 border border-yellow-200 p-3 rounded text-sm">
            <strong>Debug:</strong> API_BASE_URL = {API_BASE_URL}
          </div>
        )}
        
        <URLInputForm
          url={url}
          setUrl={setUrl}
          onScan={handleScan}
          isLoading={isLoading}
        />
        <div className="bg-[var(--bg-secondary)] p-4 rounded-xl border border-[var(--border-primary)] shadow-sm">
            <label className="block text-sm font-medium text-[var(--text-primary)] mb-3">Scan Depth</label>
            <div className="flex justify-center items-center p-1 bg-[var(--bg-tertiary)] rounded-lg space-x-1 flex-wrap">
                {(['lite', 'medium', 'deep'] as ScanDepth[]).map(depth => {
                    const depthConfig = {
                        lite: { label: 'Lite Scan', pages: 10 },
                        medium: { label: 'Medium Scan', pages: 50 },
                        deep: { label: 'Deep Scan', pages: 100 },
                    };
                    return (
                        <button
                            key={depth}
                            onClick={() => setScanDepth(depth)}
                            disabled={isLoading}
                            className={`flex-1 px-4 py-2 text-sm font-semibold rounded-md transition-colors duration-200 text-center disabled:cursor-not-allowed ${
                                scanDepth === depth
                                    ? 'bg-brand-blue text-white shadow-sm'
                                    : 'text-[var(--text-primary)] hover:bg-[var(--bg-secondary)] disabled:text-slate-500'
                            }`}
                            aria-pressed={scanDepth === depth}
                        >
                            {depthConfig[depth].label} <span className="text-xs opacity-80">({depthConfig[depth].pages} pages)</span>
                        </button>
                    )
                })}
            </div>
        </div>
      </div>

      <div className="mt-12">
        {isLoading && <ScanningProgress logs={scanLogs} />}
        {error && (
          <div className="max-w-4xl mx-auto bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-500/30 text-red-700 dark:text-red-300 p-4 rounded-lg flex items-start space-x-4" role="alert">
            <AlertTriangleIcon className="h-6 w-6 text-red-500 dark:text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-bold text-red-800 dark:text-red-200">Scan Error</p>
              <p className="text-sm">{error}</p>
              {/* Debug info for troubleshooting */}
              <details className="mt-2 text-xs opacity-75">
                <summary className="cursor-pointer">Debug Info</summary>
                <div className="mt-1 space-y-1">
                  <div>API Base URL: {API_BASE_URL}</div>
                  <div>Current Location: {window.location.href}</div>
                  <div>Hostname: {window.location.hostname}</div>
                </div>
              </details>
            </div>
          </div>
        )}
        {scanResult && !isLoading && <ScanResultDisplay result={scanResult} scannedUrl={url} />}
        {!isLoading && !error && !scanResult && (
           <div className="text-center text-[var(--text-primary)] mt-16 animate-fade-in-up">
            <p>Your comprehensive compliance report will appear here.</p>
          </div>
        )}
      </div>
    </>
  );
};
