import React, { useState } from 'react';
import type {
  StorageExplorerData
} from './tool-types';

type StorageEntry = { key: string; value: string };

const ITEMS_PER_PAGE = 10;

const StorageExplorerToolComponent = ({
  data,
  onRefresh
}: {
  data: StorageExplorerData | undefined;
  onRefresh: () => void;
}) => {
  const local = data?.local ?? [];
  const session = data?.session ?? [];
  const [activeTab, setActiveTab] = useState<'local' | 'session'>('local');
  const [localPage, setLocalPage] = useState(0);
  const [sessionPage, setSessionPage] = useState(0);
  const [expandedKeys, setExpandedKeys] = useState<Set<string>>(new Set());

  const activeData = activeTab === 'local' ? local : session;
  const currentPage = activeTab === 'local' ? localPage : sessionPage;
  const setPage = activeTab === 'local' ? setLocalPage : setSessionPage;
  const totalPages = Math.ceil(activeData.length / ITEMS_PER_PAGE);
  const paginatedData = activeData.slice(
    currentPage * ITEMS_PER_PAGE,
    (currentPage + 1) * ITEMS_PER_PAGE
  );

  const toggleExpand = (key: string) => {
    setExpandedKeys((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const handleExportJSON = () => {
    const exportData = { local, session };
    const json = JSON.stringify(exportData, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `storage-export-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const tryParseJSON = (value: string): string | object => {
    try {
      return JSON.parse(value);
    } catch {
      return value;
    }
  };

  const renderValue = (entry: StorageEntry, prefix: string) => {
    const key = `${prefix}-${entry.key}`;
    const isExpanded = expandedKeys.has(key);
    const parsed = tryParseJSON(entry.value);
    const isObject = typeof parsed === 'object';
    const displayValue = isObject
      ? JSON.stringify(parsed, null, 2)
      : entry.value;
    const truncatedValue =
      displayValue.length > 60 && !isExpanded
        ? `${displayValue.slice(0, 60)}...`
        : displayValue;

    return (
      <div
        key={key}
        className="rounded border border-slate-700 bg-slate-800/50 p-2"
      >
        <div className="flex items-start justify-between gap-2">
          <div className="flex-1 min-w-0">
            <div className="text-[11px] font-medium text-blue-300 break-all">
              {entry.key}
            </div>
            <pre
              className={`text-[10px] text-slate-400 mt-1 whitespace-pre-wrap break-all ${
                isExpanded ? '' : 'line-clamp-2'
              }`}
            >
              {truncatedValue}
            </pre>
          </div>
          <div className="flex gap-1 flex-shrink-0">
            {displayValue.length > 60 && (
              <button
                type="button"
                onClick={() => toggleExpand(key)}
                className="text-[9px] text-slate-500 hover:text-slate-300"
              >
                {isExpanded ? '▲' : '▼'}
              </button>
            )}
            <button
              type="button"
              onClick={() => navigator.clipboard.writeText(entry.value)}
              className="text-[9px] text-slate-500 hover:text-slate-300"
              title="Copy value"
            >
              ⧉
            </button>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Storage Explorer</div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={handleExportJSON}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Export JSON
          </button>
          <button
            type="button"
            onClick={onRefresh}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>

      <div className="flex gap-1 mb-3">
        <button
          type="button"
          onClick={() => setActiveTab('local')}
          className={`flex-1 rounded px-2 py-1.5 text-[11px] border transition-colors ${
            activeTab === 'local'
              ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
              : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
          }`}
        >
          Local ({local.length})
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('session')}
          className={`flex-1 rounded px-2 py-1.5 text-[11px] border transition-colors ${
            activeTab === 'session'
              ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
              : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
          }`}
        >
          Session ({session.length})
        </button>
      </div>

      <div className="flex-1 overflow-y-auto space-y-2 min-h-0">
        {paginatedData.length === 0 ? (
          <div className="text-[11px] text-slate-500 text-center py-4">
            No {activeTab} storage entries.
          </div>
        ) : (
          paginatedData.map((entry) => renderValue(entry, activeTab))
        )}
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-3 pt-2 border-t border-slate-700">
          <button
            type="button"
            onClick={() => setPage(Math.max(0, currentPage - 1))}
            disabled={currentPage === 0}
            className="text-[10px] text-slate-400 hover:text-slate-200 disabled:opacity-30"
          >
            ← Prev
          </button>
          <span className="text-[10px] text-slate-500">
            {currentPage + 1} / {totalPages}
          </span>
          <button
            type="button"
            onClick={() => setPage(Math.min(totalPages - 1, currentPage + 1))}
            disabled={currentPage >= totalPages - 1}
            className="text-[10px] text-slate-400 hover:text-slate-200 disabled:opacity-30"
          >
            Next →
          </button>
        </div>
      )}
    </div>
  );
};
export class StorageExplorerTool {
  static Component = StorageExplorerToolComponent;
}
