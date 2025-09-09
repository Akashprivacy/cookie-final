import React, { useState, useCallback, useEffect, useRef } from 'react';
import { URLInputForm } from './URLInputForm';
import { ScanResultDisplay } from './ScanResultDisplay';
import { ScanningProgress } from './ScanningProgress';
import { AlertTriangleIcon } from './Icons';
import type { ScanResultData } from '../types';

// Enhanced API URL detection with better error handling
const API_BASE_URL = (() => {
  const hostname = window.location.hostname;
  const protocol = window.location.protocol;
  
  // Check if we're in development
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return 'http://localhost:3001'; // Backend port in development
  }
  
  // In production, use the same origin
  return `${protocol}//${hostname}${window.location.port ? ':' + window.location.port : ''}`;
})();

// Debug logging
console.log('[FRONTEND] API_BASE_URL:', API_BASE_URL);
console.log('[FRONTEND] Current location:', window.location.href);

type ScanDepth = 'lite' | 'medium' | 'deep';

interface ConnectionState {
  attempts: number;
  maxAttempts: number;
  retryDelay: number;
}

export const CookieScannerView: React.FC = () => {
  const [url, setUrl] = useState<string>('');
  const [scanDepth, setScanDepth] = useState<ScanDepth>('lite');
  const [scanResult, setScanResult] = useState<ScanResultData | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [scanLogs, setScanLogs] = useState<string[]>([]);
  const [connectionState, setConnectionState] = useState<ConnectionState>({
    attempts: 0,
    maxAttempts: 3,
    retryDelay: 1000
  });
  
  const eventSourceRef = useRef<EventSource | null>(null);
  const retryTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Enhanced EventSource connection with retry logic
  const createEventSourceConnection = useCallback((scanUrl: string, attempt: number = 1) => {
    console.log(`[FRONTEND] Creating EventSource connection (attempt ${attempt}):`, scanUrl);
    
    // Clear any existing connections
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    try {
      // Create EventSource with explicit configuration
      eventSourceRef.current = new EventSource(scanUrl);
      
      eventSourceRef.current.onopen = (event) => {
        console.log('[FRONTEND] EventSource connection opened successfully');
        setConnectionState(prev => ({ ...prev, attempts: 0 }));
        setScanLogs(prev => [...prev, `Connected to scanner service (attempt ${attempt})`]);
      };

      eventSourceRef.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          console.log('[FRONTEND] Received message:', data);
          
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
        } catch (parseError) {
          console.error('[FRONTEND] Failed to parse SSE message:', event.data, parseError);
          setScanLogs(prev => [...prev, `Warning: Received malformed data from server`]);
        }
      };

      eventSourceRef.current.onerror = (event) => {
        console.error('[FRONTEND] EventSource error:', event);
        console.error('[FRONTEND] EventSource readyState:', eventSourceRef.current?.readyState);
        console.error('[FRONTEND] EventSource url:', eventSourceRef.current?.url);
        
        const readyState = eventSourceRef.current?.readyState;
        
        if (readyState === EventSource.CONNECTING) {
          console.log('[FRONTEND] EventSource is connecting...');
          return; // Let it continue trying to connect
        }
        
        if (readyState === EventSource.CLOSED) {
          console.log('[FRONTEND] EventSource connection closed');
          
          // Check if we should retry
          if (attempt < connectionState.maxAttempts && isLoading) {
            const retryDelay = connectionState.retryDelay * attempt;
            console.log(`[FRONTEND] Retrying connection in ${retryDelay}ms...`);
            
            setScanLogs(prev => [...prev, `Connection lost, retrying in ${retryDelay/1000}s... (${attempt}/${connectionState.maxAttempts})`]);
            
            retryTimeoutRef.current = setTimeout(() => {
              createEventSourceConnection(scanUrl, attempt + 1);
            }, retryDelay);
            
            return;
          }
        }
        
        // If we get here, the connection failed and we're not retrying
        let errorMessage = 'Connection to scanner service failed.';
        
        if (attempt >= connectionState.maxAttempts) {
          errorMessage = `Failed to connect after ${connectionState.maxAttempts} attempts. `;
        }
        
        // Add specific error details based on the situation
        if (hostname === 'localhost' || hostname === '127.0.0.1') {
          errorMessage += ' Make sure the backend server is running on port 3001.';
        } else {
          errorMessage += ' The server might be down or there may be a network issue.';
        }
        
        setError(errorMessage);
        setIsLoading(false);
        eventSourceRef.current?.close();
      };

    } catch (createError) {
      console.error('[FRONTEND] Failed to create EventSource:', createError);
      setError(`Failed to establish connection: ${createError.message}`);
      setIsLoading(false);
    }
  }, [connectionState.maxAttempts, connectionState.retryDelay, isLoading]);

  // Test backend connectivity before starting scan
  const testBackendConnectivity = useCallback(async (): Promise<boolean> => {
    try {
      console.log('[FRONTEND] Testing backend connectivity...');
      const testUrl = `${API_BASE_URL}/health`;
      
      const response = await fetch(testUrl, {
        method: 'GET',
        mode: 'cors',
        headers: {
          'Accept': 'application/json',
        },
      });
      
      if (response.ok) {
        console.log('[FRONTEND] Backend connectivity test passed');
        return true;
      } else {
        console.error('[FRONTEND] Backend connectivity test failed:', response.status, response.statusText);
        return false;
      }
    } catch (fetchError) {
      console.error('[FRONTEND] Backend connectivity test error:', fetchError);
      return false;
    }
  }, []);

  const handleScan = useCallback(async () => {
    if (!url) {
      setError('Please enter a valid website URL.');
      return;
    }

    // Clear previous state
    setError(null);
    setIsLoading(true);
    setScanResult(null);
    setScanLogs([]);
    setConnectionState(prev => ({ ...prev, attempts: 0 }));

    // Clear any existing timeouts
    if (retryTimeoutRef.current) {
      clearTimeout(retryTimeoutRef.current);
    }

    setScanLogs(['Initializing scanner...']);

    // Test backend connectivity first
    const isBackendReachable = await testBackendConnectivity();
    if (!isBackendReachable) {
      setError('Cannot reach the scanner service. Please check if the backend server is running.');
      setIsLoading(false);
      return;
    }

    setScanLogs(prev => [...prev, 'Backend service available, starting scan...']);

    // Construct scan URL
    const scanUrl = new URL(`${API_BASE_URL}/api/scan`);
    scanUrl.searchParams.append('url', encodeURIComponent(url));
    scanUrl.searchParams.append('depth', scanDepth);

    console.log('[FRONTEND] Starting scan with URL:', scanUrl.toString());
    setScanLogs(prev => [...prev, `Connecting to: ${scanUrl.toString()}`]);

    // Start EventSource connection
    createEventSourceConnection(scanUrl.toString());
  }, [url, scanDepth, testBackendConnectivity, createEventSourceConnection]);

  // Cleanup function
  useEffect(() => {
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
      if (retryTimeoutRef.current) {
        clearTimeout(retryTimeoutRef.current);
      }
    };
  }, []);

  // Stop scan function
  const handleStopScan = useCallback(() => {
    console.log('[FRONTEND] Stopping scan...');
    setIsLoading(false);
    
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }
    
    if (retryTimeoutRef.current) {
      clearTimeout(retryTimeoutRef.current);
    }
    
    setScanLogs(prev => [...prev, 'Scan stopped by user']);
  }, []);
  
  return (
    <>
      <div className="max-w-3xl mx-auto mt-6 space-y-6">
        {/* Debug info - remove this in production */}
        {process.env.NODE_ENV === 'development' && (
          <div className="bg-yellow-50 border border-yellow-200 p-3 rounded text-sm">
            <strong>Debug:</strong> API_BASE_URL = {API_BASE_URL}
            <br />
            <strong>Connection attempts:</strong> {connectionState.attempts}/{connectionState.maxAttempts}
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

        {/* Stop scan button when loading */}
        {isLoading && (
          <div className="text-center">
            <button
              onClick={handleStopScan}
              className="px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-md transition-colors duration-200"
            >
              Stop Scan
            </button>
          </div>
        )}
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
                  <div>Protocol: {window.location.protocol}</div>
                  <div>Port: {window.location.port || 'default'}</div>
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
