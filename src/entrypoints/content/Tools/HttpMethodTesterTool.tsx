import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faPlay, faCheckCircle, faTimesCircle, faCopy } from '@fortawesome/free-solid-svg-icons';

export type HttpMethodTesterData = {
  url?: string;
  results?: HttpMethodResult[];
  testedAt?: number;
  isTesting?: boolean;
  error?: string;
};

type HttpMethodResult = {
  method: string;
  status: number;
  allowed: boolean;
  headers?: Record<string, string>;
  error?: string;
};

type Props = {
  data: HttpMethodTesterData | undefined;
  onChange: (data: HttpMethodTesterData) => void;
};

const HTTP_METHODS = [
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'HEAD',
  'OPTIONS',
  'TRACE',
  'CONNECT'
];

const HttpMethodTester: React.FC<Props> = ({ data, onChange }) => {
  const url = data?.url ?? '';
  const results = data?.results ?? [];
  const testedAt = data?.testedAt;
  const isTesting = data?.isTesting ?? false;
  const error = data?.error ?? '';
  const [copied, setCopied] = useState(false);

  const handleUseCurrentPage = () => {
    onChange({ ...data, url: window.location.href });
  };

  const handleTest = async () => {
    if (!url.trim()) return;

    onChange({ ...data, isTesting: true, error: '', results: [] });

    const testResults: HttpMethodResult[] = [];

    for (const method of HTTP_METHODS) {
      try {
        const response = await fetch(url, {
          method,
          mode: 'cors',
          credentials: 'omit',
          headers: {
            'Content-Type': 'application/json'
          }
        });

        const headers: Record<string, string> = {};
        response.headers.forEach((value, key) => {
          headers[key] = value;
        });

        // Check Allow header from OPTIONS response
        const allowHeader = headers['allow'] || headers['Allow'];

        testResults.push({
          method,
          status: response.status,
          allowed: response.status !== 405 && response.status !== 501,
          headers
        });
      } catch (e) {
        testResults.push({
          method,
          status: 0,
          allowed: false,
          error: e instanceof Error ? e.message : 'Request failed'
        });
      }
    }

    onChange({
      ...data,
      results: testResults,
      testedAt: Date.now(),
      isTesting: false
    });
  };

  const handleCopyReport = () => {
    const report = results.map(r =>
      `${r.method}: ${r.status} (${r.allowed ? 'Allowed' : 'Not Allowed'})`
    ).join('\n');

    navigator.clipboard.writeText(`HTTP Methods Test - ${url}\n\n${report}`);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const allowedMethods = results.filter(r => r.allowed);
  const blockedMethods = results.filter(r => !r.allowed);

  // Check for potentially dangerous methods
  const dangerousMethods = results.filter(r =>
    r.allowed && ['PUT', 'DELETE', 'TRACE', 'CONNECT'].includes(r.method)
  );

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">HTTP Method Tester</div>
        <div className="flex gap-2">
          {results.length > 0 && (
            <button
              onClick={handleCopyReport}
              className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors flex items-center gap-1"
            >
              <FontAwesomeIcon icon={faCopy} className="w-3 h-3" />
              {copied ? 'Copied!' : 'Copy Report'}
            </button>
          )}
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Tests which HTTP methods are allowed on a target URL.
      </div>

      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
        <div className="text-[10px] text-slate-500 mb-1">Target URL</div>
        <div className="flex gap-2">
          <input
            type="url"
            value={url}
            onChange={(e) => onChange({ ...data, url: e.target.value })}
            placeholder="https://example.com/api/endpoint"
            className="flex-1 rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
          />
          <button
            onClick={handleUseCurrentPage}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Current
          </button>
        </div>
      </div>

      <button
        onClick={handleTest}
        disabled={!url.trim() || isTesting}
        className="w-full rounded bg-blue-600/20 border border-blue-500/30 px-2 py-1.5 text-[11px] text-blue-300 hover:bg-blue-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faPlay} className="w-3 h-3" />
        {isTesting ? 'Testing...' : 'Test HTTP Methods'}
      </button>

      {error && (
        <div className="text-red-400 text-[10px] bg-red-900/20 border border-red-500/30 p-2 rounded mb-3">
          {error}
        </div>
      )}

      <div className="flex-1 overflow-y-auto space-y-2 min-h-0">
        {results.length > 0 && (
          <>
            {dangerousMethods.length > 0 && (
              <div className="p-2 rounded bg-red-900/20 border border-red-500/30">
                <div className="text-red-400 font-medium text-[11px] mb-1">
                  Potentially Dangerous Methods Allowed
                </div>
                <div className="text-[10px] text-slate-300">
                  {dangerousMethods.map(m => m.method).join(', ')} - These methods may pose security risks.
                </div>
              </div>
            )}

            <div className="flex justify-between items-center">
              <div className="text-[11px] text-slate-300">
                <span className="text-green-400">{allowedMethods.length} Allowed</span>
                {' / '}
                <span className="text-red-400">{blockedMethods.length} Blocked</span>
              </div>
            </div>

            <div className="grid grid-cols-3 gap-1">
              {results.map((result, index) => (
                <div
                  key={index}
                  className={`p-1.5 rounded text-[10px] border ${
                    result.allowed
                      ? 'bg-green-900/20 border-green-500/30 text-green-400'
                      : 'bg-slate-800/50 border-slate-700 text-slate-400'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-medium">{result.method}</span>
                    <FontAwesomeIcon
                      icon={result.allowed ? faCheckCircle : faTimesCircle}
                      className={`w-2.5 h-2.5 ${result.allowed ? 'text-green-400' : 'text-slate-500'}`}
                    />
                  </div>
                  <div className="text-slate-500 text-[9px] mt-0.5">
                    {result.status > 0 ? result.status : 'Error'}
                  </div>
                </div>
              ))}
            </div>

            {testedAt && (
              <div className="text-[10px] text-slate-500">
                Tested: {new Date(testedAt).toLocaleTimeString()}
              </div>
            )}
          </>
        )}
      </div>

      <div className="text-[10px] text-slate-500 space-y-0.5 border-t border-slate-700 pt-2 mt-3">
        <div><strong>Method Descriptions:</strong></div>
        <div className="grid grid-cols-2 gap-0.5 text-[9px]">
          <span><strong>GET:</strong> Retrieve data</span>
          <span><strong>POST:</strong> Create data</span>
          <span><strong>PUT:</strong> Replace data</span>
          <span><strong>PATCH:</strong> Modify data</span>
          <span><strong>DELETE:</strong> Remove data</span>
          <span><strong>OPTIONS:</strong> Get allowed methods</span>
        </div>
      </div>
    </div>
  );
};

export class HttpMethodTesterTool {
  static Component = HttpMethodTester;
}
