import React, { useState, useMemo } from 'react';
import type {
  RequestLogData,
  RequestLogEntry
} from './tool-types';

const ENTRIES_PER_PAGE = 10;

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
};

const formatTiming = (ms: number | undefined): string => {
  if (ms === undefined || ms === 0) return '-';
  return `${ms.toFixed(1)}ms`;
};

const getInitiatorColor = (type: string): string => {
  switch (type) {
    case 'fetch':
    case 'xmlhttprequest':
      return 'text-blue-400';
    case 'script':
      return 'text-amber-400';
    case 'css':
    case 'link':
      return 'text-purple-400';
    case 'img':
    case 'image':
      return 'text-emerald-400';
    case 'font':
      return 'text-pink-400';
    case 'iframe':
      return 'text-cyan-400';
    case 'video':
    case 'audio':
      return 'text-rose-400';
    default:
      return 'text-slate-400';
  }
};

const getInitiatorIcon = (type: string): string => {
  switch (type) {
    case 'fetch':
    case 'xmlhttprequest':
      return '⚡';
    case 'script':
      return '📜';
    case 'css':
    case 'link':
      return '🎨';
    case 'img':
    case 'image':
      return '🖼';
    case 'font':
      return '🔤';
    case 'iframe':
      return '📦';
    case 'video':
      return '🎬';
    case 'audio':
      return '🔊';
    default:
      return '📄';
  }
};

const getStatusColor = (status: number | undefined): string => {
  if (!status) return 'text-slate-500';
  if (status >= 200 && status < 300) return 'text-emerald-400';
  if (status >= 300 && status < 400) return 'text-amber-400';
  if (status >= 400) return 'text-red-400';
  return 'text-slate-400';
};

const TimingBar = ({ label, value, max, color }: { label: string; value: number; max: number; color: string }) => {
  const percentage = max > 0 ? Math.min((value / max) * 100, 100) : 0;
  return (
    <div className="flex items-center gap-2">
      <span className="text-[9px] text-slate-500 w-16 shrink-0">{label}</span>
      <div className="flex-1 h-1.5 bg-slate-800 rounded overflow-hidden">
        <div
          className={`h-full ${color} transition-all`}
          style={{ width: `${percentage}%` }}
        />
      </div>
      <span className="text-[9px] text-slate-400 w-14 text-right">{formatTiming(value)}</span>
    </div>
  );
};

const RequestDetails = ({ entry }: { entry: RequestLogEntry }) => {
  const dnsTime = (entry.domainLookupEnd ?? 0) - (entry.domainLookupStart ?? 0);
  const connectTime = (entry.connectEnd ?? 0) - (entry.connectStart ?? 0);
  const tlsTime = entry.secureConnectionStart
    ? (entry.connectEnd ?? 0) - entry.secureConnectionStart
    : 0;
  const waitingTime = (entry.responseStart ?? 0) - (entry.requestStart ?? 0);
  const downloadTime = (entry.responseEnd ?? 0) - (entry.responseStart ?? 0);
  const maxTime = Math.max(dnsTime, connectTime, tlsTime, waitingTime, downloadTime, 1);

  // Parse URL for details
  let urlInfo: { protocol: string; host: string; pathname: string; search: string } | null = null;
  try {
    const url = new URL(entry.name);
    urlInfo = {
      protocol: url.protocol.replace(':', ''),
      host: url.host,
      pathname: url.pathname,
      search: url.search
    };
  } catch {
    // Invalid URL
  }

  return (
    <div className="mt-2 pt-2 border-t border-slate-700 space-y-3">
      {/* URL Info */}
      {urlInfo && (
        <div className="space-y-1">
          <div className="text-[9px] uppercase tracking-widest text-slate-500">URL Details</div>
          <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[10px]">
            <span className="text-slate-500">Protocol</span>
            <span className="text-slate-300">{urlInfo.protocol}</span>
            <span className="text-slate-500">Host</span>
            <span className="text-slate-300 truncate" title={urlInfo.host}>{urlInfo.host}</span>
            <span className="text-slate-500">Path</span>
            <span className="text-slate-300 truncate" title={urlInfo.pathname}>{urlInfo.pathname}</span>
            {urlInfo.search && (
              <>
                <span className="text-slate-500">Query</span>
                <span className="text-slate-300 truncate" title={urlInfo.search}>{urlInfo.search}</span>
              </>
            )}
          </div>
        </div>
      )}

      {/* General Info */}
      <div className="space-y-1">
        <div className="text-[9px] uppercase tracking-widest text-slate-500">Request Info</div>
        <div className="grid grid-cols-2 gap-2 text-[10px]">
          <div>
            <span className="text-slate-500">Type: </span>
            <span className={getInitiatorColor(entry.initiatorType)}>{entry.initiatorType}</span>
          </div>
          {entry.responseStatus !== undefined && entry.responseStatus > 0 && (
            <div>
              <span className="text-slate-500">Status: </span>
              <span className={getStatusColor(entry.responseStatus)}>{entry.responseStatus}</span>
            </div>
          )}
          {entry.nextHopProtocol && (
            <div>
              <span className="text-slate-500">Protocol: </span>
              <span className="text-slate-300">{entry.nextHopProtocol}</span>
            </div>
          )}
          <div>
            <span className="text-slate-500">Duration: </span>
            <span className="text-slate-300">{entry.duration.toFixed(1)}ms</span>
          </div>
        </div>
      </div>

      {/* Size Info */}
      <div className="space-y-1">
        <div className="text-[9px] uppercase tracking-widest text-slate-500">Size</div>
        <div className="grid grid-cols-3 gap-2 text-[10px]">
          <div>
            <span className="text-slate-500">Transfer: </span>
            <span className="text-slate-300">{formatBytes(entry.transferSize)}</span>
          </div>
          {entry.encodedBodySize !== undefined && entry.encodedBodySize > 0 && (
            <div>
              <span className="text-slate-500">Encoded: </span>
              <span className="text-slate-300">{formatBytes(entry.encodedBodySize)}</span>
            </div>
          )}
          {entry.decodedBodySize !== undefined && entry.decodedBodySize > 0 && (
            <div>
              <span className="text-slate-500">Decoded: </span>
              <span className="text-slate-300">{formatBytes(entry.decodedBodySize)}</span>
            </div>
          )}
        </div>
      </div>

      {/* Timing Waterfall */}
      <div className="space-y-1.5">
        <div className="text-[9px] uppercase tracking-widest text-slate-500">Timing Waterfall</div>
        {dnsTime > 0 && (
          <TimingBar label="DNS" value={dnsTime} max={maxTime} color="bg-cyan-500" />
        )}
        {connectTime > 0 && (
          <TimingBar label="Connect" value={connectTime} max={maxTime} color="bg-amber-500" />
        )}
        {tlsTime > 0 && (
          <TimingBar label="TLS" value={tlsTime} max={maxTime} color="bg-purple-500" />
        )}
        {waitingTime > 0 && (
          <TimingBar label="Waiting" value={waitingTime} max={maxTime} color="bg-blue-500" />
        )}
        {downloadTime > 0 && (
          <TimingBar label="Download" value={downloadTime} max={maxTime} color="bg-emerald-500" />
        )}
        {dnsTime === 0 && connectTime === 0 && waitingTime === 0 && downloadTime === 0 && (
          <div className="text-[10px] text-slate-500 italic">No timing data available (cached or cross-origin)</div>
        )}
      </div>
    </div>
  );
};

const RequestLogToolComponent = ({
  data,
  onChange,
  onClear
}: {
  data: RequestLogData | undefined;
  onChange: (next: RequestLogData) => void;
  onClear: () => Promise<void>;
}) => {
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);

  const entries = data?.entries ?? [];
  const filterCategory = data?.filterCategory ?? 'all';
  const page = data?.page ?? 0;

  // Get unique categories from entries
  const categories = useMemo(() => {
    const types = new Set<string>();
    entries.forEach(e => types.add(e.initiatorType));
    return ['all', ...Array.from(types).sort()];
  }, [entries]);

  // Filter entries by category
  const filteredEntries = useMemo(() => {
    if (filterCategory === 'all') return entries;
    return entries.filter(e => e.initiatorType === filterCategory);
  }, [entries, filterCategory]);

  // Paginate entries
  const totalPages = Math.ceil(filteredEntries.length / ENTRIES_PER_PAGE);
  const paginatedEntries = filteredEntries.slice(
    page * ENTRIES_PER_PAGE,
    (page + 1) * ENTRIES_PER_PAGE
  );

  const handleCategoryChange = (category: string) => {
    onChange({ ...data, filterCategory: category, page: 0 });
    setExpandedIndex(null);
  };

  const handlePageChange = (newPage: number) => {
    onChange({ ...data, page: newPage });
    setExpandedIndex(null);
  };

  const handleClear = async () => {
    await onClear();
    setExpandedIndex(null);
  };

  const handleSavePlainText = () => {
    const text = filteredEntries.map((e) =>
      `${e.name}\n  Type: ${e.initiatorType} | Duration: ${e.duration.toFixed(1)}ms | Size: ${formatBytes(e.transferSize)}${e.responseStatus ? ` | Status: ${e.responseStatus}` : ''}`
    ).join('\n\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `requests-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleSaveJSON = () => {
    const json = JSON.stringify(filteredEntries, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `requests-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const toggleExpand = (index: number) => {
    setExpandedIndex(expandedIndex === index ? null : index);
  };

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between mb-2 flex-shrink-0">
        <div className="text-xs text-slate-200">Request Log</div>
        <button
          type="button"
          onClick={handleClear}
          className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Clear
        </button>
      </div>

      {/* Stats */}
      <div className="text-[10px] text-slate-500 mb-2 flex-shrink-0">
        {filteredEntries.length} request{filteredEntries.length !== 1 ? 's' : ''}
        {filterCategory !== 'all' && ` (${filterCategory})`}
        {entries.length !== filteredEntries.length && ` of ${entries.length} total`}
      </div>

      {/* Category Filter */}
      {categories.length > 1 && (
        <div className="mb-2 flex-shrink-0">
          <div className="text-[9px] uppercase tracking-widest text-slate-500 mb-1">Filter by Type</div>
          <div className="flex flex-wrap gap-1">
            {categories.map((cat) => (
              <button
                key={cat}
                type="button"
                onClick={() => handleCategoryChange(cat)}
                className={`rounded px-2 py-1 text-[10px] border transition-colors ${
                  filterCategory === cat
                    ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                    : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                }`}
              >
                {cat === 'all' ? (
                  'All'
                ) : (
                  <>
                    <span className="mr-1">{getInitiatorIcon(cat)}</span>
                    {cat}
                  </>
                )}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Request List */}
      <div className="flex-1 overflow-y-auto space-y-1 min-h-0 mb-2">
        {paginatedEntries.length === 0 ? (
          <div className="text-[11px] text-slate-500 text-center py-4">
            {entries.length === 0
              ? 'No requests captured yet. Network activity will appear here.'
              : 'No requests match the current filter.'}
          </div>
        ) : (
          paginatedEntries.map((entry, index) => {
            const globalIndex = page * ENTRIES_PER_PAGE + index;
            const isExpanded = expandedIndex === globalIndex;
            return (
              <div
                key={`${entry.name}-${entry.startTime}-${globalIndex}`}
                className={`rounded border transition-colors ${
                  isExpanded
                    ? 'border-blue-500/50 bg-slate-800/80'
                    : 'border-slate-700 bg-slate-800/50 hover:border-slate-600'
                }`}
              >
                <div
                  role="button"
                  tabIndex={0}
                  onClick={() => toggleExpand(globalIndex)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      toggleExpand(globalIndex);
                    }
                  }}
                  className="w-full p-2 text-left cursor-pointer"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className={`text-[10px] ${getInitiatorColor(entry.initiatorType)}`}>
                          {getInitiatorIcon(entry.initiatorType)}
                        </span>
                        <span className="text-[10px] text-slate-300 truncate flex-1" title={entry.name}>
                          {entry.name.split('/').pop() || entry.name}
                        </span>
                        {entry.responseStatus !== undefined && entry.responseStatus > 0 && (
                          <span className={`text-[9px] ${getStatusColor(entry.responseStatus)}`}>
                            {entry.responseStatus}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 mt-1 text-[9px]">
                        <span className={getInitiatorColor(entry.initiatorType)}>
                          {entry.initiatorType}
                        </span>
                        <span className="text-slate-500">
                          {entry.duration.toFixed(1)}ms
                        </span>
                        {entry.transferSize > 0 && (
                          <span className="text-slate-500">
                            {formatBytes(entry.transferSize)}
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-1 flex-shrink-0">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          navigator.clipboard.writeText(entry.name);
                        }}
                        className="text-[9px] text-slate-500 hover:text-slate-300 p-1"
                        title="Copy URL"
                      >
                        ⧉
                      </button>
                      <span className="text-[9px] text-slate-600">
                        {isExpanded ? '▼' : '▶'}
                      </span>
                    </div>
                  </div>
                </div>
                {isExpanded && (
                  <div className="px-2 pb-2">
                    <RequestDetails entry={entry} />
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mb-2 pt-2 border-t border-slate-700 flex-shrink-0">
          <button
            type="button"
            onClick={() => handlePageChange(Math.max(0, page - 1))}
            disabled={page === 0}
            className="text-[10px] text-slate-400 hover:text-slate-200 disabled:opacity-30"
          >
            ← Prev
          </button>
          <span className="text-[10px] text-slate-500">
            Page {page + 1} of {totalPages}
          </span>
          <button
            type="button"
            onClick={() => handlePageChange(Math.min(totalPages - 1, page + 1))}
            disabled={page >= totalPages - 1}
            className="text-[10px] text-slate-400 hover:text-slate-200 disabled:opacity-30"
          >
            Next →
          </button>
        </div>
      )}

      {/* Export Buttons */}
      {entries.length > 0 && (
        <div className="flex gap-2 flex-shrink-0">
          <button
            type="button"
            onClick={handleSavePlainText}
            className="flex-1 rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Save as Text
          </button>
          <button
            type="button"
            onClick={handleSaveJSON}
            className="flex-1 rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Save as JSON
          </button>
        </div>
      )}
    </div>
  );
};
export class RequestLogTool {
  static Component = RequestLogToolComponent;
}
