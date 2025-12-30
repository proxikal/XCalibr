import React, { useState } from 'react';
import type {
  HeaderInspectorData
} from './tool-types';

const HeaderInspectorToolComponent = ({
  data,
  onRefresh
}: {
  data: HeaderInspectorData | undefined;
  onRefresh: () => Promise<void>;
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const headers = data?.headers ?? [];
  const updatedAt = data?.updatedAt;
  const securityHeaders = new Set([
    'content-security-policy',
    'strict-transport-security',
    'x-frame-options'
  ]);

  const handleRefresh = async () => {
    setIsLoading(true);
    await onRefresh();
    setIsLoading(false);
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs text-slate-200">Current Tab Headers</div>
          <div className="text-[11px] text-slate-500">
            {data?.url ?? 'No data yet'}
          </div>
        </div>
        <button
          type="button"
          onClick={handleRefresh}
          disabled={isLoading}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          {isLoading ? 'Loading...' : 'Refresh'}
        </button>
      </div>

      {data?.error ? (
        <div className="rounded border border-rose-500/30 bg-rose-500/10 px-2 py-1 text-[11px] text-rose-200">
          {data.error}
        </div>
      ) : null}

      {updatedAt ? (
        <div className="text-[10px] text-slate-500">
          Updated {new Date(updatedAt).toLocaleTimeString()}
        </div>
      ) : null}

      <div className="space-y-2">
        {headers.length === 0 ? (
          <div className="text-[11px] text-slate-500">
            No headers captured yet.
          </div>
        ) : (
          headers.map((header) => {
            const isSecurity = securityHeaders.has(header.name.toLowerCase());
            return (
              <div
                key={`${header.name}-${header.value}`}
                className={`rounded border px-2 py-1 text-[11px] ${
                  isSecurity
                    ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
                    : 'border-slate-800 bg-slate-800/60 text-slate-300'
                }`}
              >
                <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                  {header.name}
                </div>
                <div className="break-words">{header.value}</div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
export class HeaderInspectorTool {
  static Component = HeaderInspectorToolComponent;
}
