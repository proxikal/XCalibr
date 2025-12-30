import React, { useState, useMemo } from 'react';
import type {
  HeaderInspectorData
} from './tool-types';

const SECURITY_HEADERS = new Set([
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'x-xss-protection',
  'referrer-policy',
  'permissions-policy'
]);

const CACHING_HEADERS = new Set([
  'cache-control',
  'expires',
  'etag',
  'last-modified',
  'age',
  'vary'
]);

type HeaderCategory = 'security' | 'caching' | 'general';

const HeaderInspectorToolComponent = ({
  data,
  onRefresh
}: {
  data: HeaderInspectorData | undefined;
  onRefresh: () => Promise<void>;
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const [filter, setFilter] = useState<HeaderCategory | 'all'>('all');
  const headers = data?.headers ?? [];
  const updatedAt = data?.updatedAt;

  const categorizeHeader = (name: string): HeaderCategory => {
    const lower = name.toLowerCase();
    if (SECURITY_HEADERS.has(lower)) return 'security';
    if (CACHING_HEADERS.has(lower)) return 'caching';
    return 'general';
  };

  const categorizedHeaders = useMemo(() => {
    const security = headers.filter((h) => categorizeHeader(h.name) === 'security');
    const caching = headers.filter((h) => categorizeHeader(h.name) === 'caching');
    const general = headers.filter((h) => categorizeHeader(h.name) === 'general');
    return { security, caching, general, all: headers };
  }, [headers]);

  const filteredHeaders = categorizedHeaders[filter];

  const handleRefresh = async () => {
    setIsLoading(true);
    await onRefresh();
    setIsLoading(false);
  };

  const handleExportJSON = () => {
    const exportData = {
      url: data?.url,
      status: data?.status,
      headers: headers.map((h) => ({ name: h.name, value: h.value })),
      capturedAt: updatedAt ? new Date(updatedAt).toISOString() : null
    };
    const json = JSON.stringify(exportData, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `headers-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getCategoryStyle = (category: HeaderCategory) => {
    switch (category) {
      case 'security':
        return 'border-emerald-500/40 bg-emerald-500/10';
      case 'caching':
        return 'border-amber-500/40 bg-amber-500/10';
      default:
        return 'border-slate-700 bg-slate-800/50';
    }
  };

  const getCategoryLabel = (category: HeaderCategory) => {
    switch (category) {
      case 'security':
        return { text: 'Security', color: 'text-emerald-400' };
      case 'caching':
        return { text: 'Cache', color: 'text-amber-400' };
      default:
        return { text: 'General', color: 'text-slate-500' };
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-2">
        <div className="text-xs text-slate-200">Header Inspector</div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={handleExportJSON}
            disabled={headers.length === 0}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors disabled:opacity-50"
          >
            Export
          </button>
          <button
            type="button"
            onClick={handleRefresh}
            disabled={isLoading}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors disabled:opacity-50"
          >
            {isLoading ? 'Loading...' : 'Refresh'}
          </button>
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-2 truncate" title={data?.url}>
        {data?.url ?? 'No data yet'}
        {data?.status && <span className="ml-2 text-slate-400">Status: {data.status}</span>}
      </div>

      {data?.error ? (
        <div className="rounded border border-rose-500/30 bg-rose-500/10 px-2 py-1 text-[11px] text-rose-200 mb-2">
          {data.error}
        </div>
      ) : null}

      <div className="flex gap-1 mb-2">
        {(['all', 'security', 'caching', 'general'] as const).map((cat) => (
          <button
            key={cat}
            type="button"
            onClick={() => setFilter(cat)}
            className={`flex-1 rounded px-1.5 py-1 text-[9px] border transition-colors ${
              filter === cat
                ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                : 'bg-slate-800 border-slate-700 text-slate-400'
            }`}
          >
            {cat.charAt(0).toUpperCase() + cat.slice(1)} ({categorizedHeaders[cat].length})
          </button>
        ))}
      </div>

      {updatedAt && (
        <div className="text-[9px] text-slate-500 mb-2">
          Updated {new Date(updatedAt).toLocaleTimeString()}
        </div>
      )}

      <div className="flex-1 overflow-y-auto space-y-1.5 min-h-0">
        {filteredHeaders.length === 0 ? (
          <div className="text-[11px] text-slate-500 text-center py-4">
            No headers captured yet.
          </div>
        ) : (
          filteredHeaders.map((header, idx) => {
            const category = categorizeHeader(header.name);
            const label = getCategoryLabel(category);
            return (
              <div
                key={`${header.name}-${idx}`}
                className={`rounded border p-2 ${getCategoryStyle(category)}`}
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <div className="text-[10px] font-medium text-slate-200 break-all">
                    {header.name}
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className={`text-[8px] ${label.color}`}>{label.text}</span>
                    <button
                      type="button"
                      onClick={() => navigator.clipboard.writeText(header.value)}
                      className="text-[9px] text-slate-500 hover:text-slate-300"
                      title="Copy value"
                    >
                      ⧉
                    </button>
                  </div>
                </div>
                <div className="text-[10px] text-slate-400 break-all line-clamp-3">
                  {header.value}
                </div>
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
