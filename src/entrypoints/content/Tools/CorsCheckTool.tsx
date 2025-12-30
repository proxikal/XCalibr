import React, { useState } from 'react';
import type {
  CorsCheckData
} from './tool-types';

const CorsCheckToolComponent = ({
  data,
  onChange,
  onCheck
}: {
  data: CorsCheckData | undefined;
  onChange: (next: CorsCheckData) => void;
  onCheck: (url: string) => Promise<void>;
}) => {
  const url = data?.url ?? '';
  const result = data?.result;
  const [isLoading, setIsLoading] = useState(false);

  const handleCheck = async (targetUrl: string) => {
    setIsLoading(true);
    await onCheck(targetUrl);
    setIsLoading(false);
  };

  const handleCheckCurrentPage = async () => {
    const currentUrl = window.location.href;
    onChange({ ...data, url: currentUrl });
    await handleCheck(currentUrl);
  };

  const getHeaderStyle = (value: string | null | undefined) => {
    if (!value || value === 'None') return 'text-slate-500';
    if (value === '*') return 'text-amber-400';
    return 'text-emerald-400';
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">CORS Check</div>
        <button
          type="button"
          onClick={handleCheckCurrentPage}
          disabled={isLoading}
          className="rounded bg-blue-600 px-2 py-1 text-[10px] text-white hover:bg-blue-500 transition-colors disabled:opacity-50"
        >
          {isLoading ? 'Checking...' : 'Check Current Page'}
        </button>
      </div>

      <div className="flex gap-2">
        <input
          type="text"
          value={url}
          onChange={(event) => onChange({ ...data, url: event.target.value })}
          className="flex-1 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-blue-500"
          placeholder="https://example.com"
        />
        <button
          type="button"
          onClick={() => handleCheck(url)}
          disabled={!url || isLoading}
          className="rounded bg-slate-800 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          Check
        </button>
      </div>

      {data?.error ? (
        <div className="rounded border border-rose-500/30 bg-rose-500/10 px-2 py-1.5 text-[11px] text-rose-300">
          {data.error}
        </div>
      ) : null}

      {result ? (
        <div className="rounded border border-slate-700 bg-slate-800/50 p-3 space-y-2">
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-400">Status</span>
            <span className={result.status === 200 ? 'text-emerald-400' : 'text-amber-400'}>
              {result.status ?? 'Unknown'}
            </span>
          </div>
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-400">Access-Control-Allow-Origin</span>
            <span className={getHeaderStyle(result.acao)}>
              {result.acao ?? 'None'}
            </span>
          </div>
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-400">Access-Control-Allow-Credentials</span>
            <span className={getHeaderStyle(result.acc)}>
              {result.acc ?? 'None'}
            </span>
          </div>
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-400">Allow-Methods</span>
            <span className={getHeaderStyle(result.methods)}>
              {result.methods ?? 'None'}
            </span>
          </div>
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-400">Allow-Headers</span>
            <span className={`${getHeaderStyle(result.headers)} max-w-[150px] truncate`} title={result.headers ?? undefined}>
              {result.headers ?? 'None'}
            </span>
          </div>
        </div>
      ) : (
        <div className="text-[11px] text-slate-500 text-center py-4">
          Enter a URL or click "Check Current Page" to inspect CORS headers.
        </div>
      )}
    </div>
  );
};
export class CorsCheckTool {
  static Component = CorsCheckToolComponent;
}
