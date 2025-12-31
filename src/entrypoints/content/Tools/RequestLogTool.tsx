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

const getStatusBgColor = (status: number | undefined): string => {
  if (!status) return 'bg-slate-700';
  if (status >= 200 && status < 300) return 'bg-emerald-500/20';
  if (status >= 300 && status < 400) return 'bg-amber-500/20';
  if (status >= 400) return 'bg-red-500/20';
  return 'bg-slate-700';
};

type DetailsTab = 'timing' | 'headers' | 'initiator';

const WaterfallBar = ({ entry, maxDuration }: { entry: RequestLogEntry; maxDuration: number }) => {
  const dnsTime = (entry.domainLookupEnd ?? 0) - (entry.domainLookupStart ?? 0);
  const connectTime = (entry.connectEnd ?? 0) - (entry.connectStart ?? 0);
  const tlsTime = entry.secureConnectionStart
    ? (entry.connectEnd ?? 0) - entry.secureConnectionStart
    : 0;
  const waitingTime = (entry.responseStart ?? 0) - (entry.requestStart ?? 0);
  const downloadTime = (entry.responseEnd ?? 0) - (entry.responseStart ?? 0);

  const scale = maxDuration > 0 ? 100 / maxDuration : 0;

  // Calculate actual widths
  const dnsWidth = dnsTime * scale;
  const connectWidth = (connectTime - tlsTime) * scale;
  const tlsWidth = tlsTime * scale;
  const waitingWidth = waitingTime * scale;
  const downloadWidth = downloadTime * scale;
  const totalWidth = dnsWidth + connectWidth + tlsWidth + waitingWidth + downloadWidth;

  return (
    <div className="relative h-2 bg-slate-800 rounded overflow-hidden w-full">
      <div className="absolute h-full flex left-0" style={{ width: `${Math.min(totalWidth, 100)}%` }}>
        {dnsTime > 0 && (
          <div
            className="h-full bg-cyan-500"
            style={{ width: `${(dnsTime / entry.duration) * 100}%` }}
            title={`DNS: ${formatTiming(dnsTime)}`}
          />
        )}
        {connectTime > 0 && (
          <div
            className="h-full bg-amber-500"
            style={{ width: `${((connectTime - tlsTime) / entry.duration) * 100}%` }}
            title={`Connect: ${formatTiming(connectTime - tlsTime)}`}
          />
        )}
        {tlsTime > 0 && (
          <div
            className="h-full bg-purple-500"
            style={{ width: `${(tlsTime / entry.duration) * 100}%` }}
            title={`TLS: ${formatTiming(tlsTime)}`}
          />
        )}
        {waitingTime > 0 && (
          <div
            className="h-full bg-blue-500"
            style={{ width: `${(waitingTime / entry.duration) * 100}%` }}
            title={`Waiting (TTFB): ${formatTiming(waitingTime)}`}
          />
        )}
        {downloadTime > 0 && (
          <div
            className="h-full bg-emerald-500"
            style={{ width: `${(downloadTime / entry.duration) * 100}%` }}
            title={`Download: ${formatTiming(downloadTime)}`}
          />
        )}
        {dnsTime === 0 && connectTime === 0 && waitingTime === 0 && downloadTime === 0 && entry.duration > 0 && (
          <div
            className="h-full bg-slate-500 w-full"
            title={`Total: ${formatTiming(entry.duration)}`}
          />
        )}
      </div>
    </div>
  );
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

const RequestBadges = ({ entry }: { entry: RequestLogEntry }) => {
  const badges: { label: string; color: string; bg: string }[] = [];

  // Check if cached (transferSize === 0 or very small compared to decoded)
  const isCached = entry.isCached ||
    (entry.transferSize === 0 && (entry.decodedBodySize ?? 0) > 0);
  if (isCached) {
    badges.push({ label: 'cached', color: 'text-cyan-400', bg: 'bg-cyan-500/20' });
  }

  // Check for redirect
  if (entry.isRedirect || (entry.responseStatus && entry.responseStatus >= 300 && entry.responseStatus < 400)) {
    badges.push({ label: 'redirect', color: 'text-amber-400', bg: 'bg-amber-500/20' });
  }

  // Check for error
  if (entry.responseStatus && entry.responseStatus >= 400) {
    badges.push({ label: 'error', color: 'text-red-400', bg: 'bg-red-500/20' });
  }

  // Check for slow (> 1000ms)
  if (entry.duration > 1000) {
    badges.push({ label: 'slow', color: 'text-orange-400', bg: 'bg-orange-500/20' });
  }

  if (badges.length === 0) return null;

  return (
    <div className="flex gap-1 mt-1">
      {badges.map((badge) => (
        <span
          key={badge.label}
          className={`text-[8px] px-1 rounded ${badge.color} ${badge.bg}`}
        >
          {badge.label}
        </span>
      ))}
    </div>
  );
};

const DetailsDrawer = ({
  entry,
  activeTab,
  onTabChange,
  onClose
}: {
  entry: RequestLogEntry;
  activeTab: DetailsTab;
  onTabChange: (tab: DetailsTab) => void;
  onClose: () => void;
}) => {
  const dnsTime = (entry.domainLookupEnd ?? 0) - (entry.domainLookupStart ?? 0);
  const connectTime = (entry.connectEnd ?? 0) - (entry.connectStart ?? 0);
  const tlsTime = entry.secureConnectionStart
    ? (entry.connectEnd ?? 0) - entry.secureConnectionStart
    : 0;
  const waitingTime = (entry.responseStart ?? 0) - (entry.requestStart ?? 0);
  const downloadTime = (entry.responseEnd ?? 0) - (entry.responseStart ?? 0);
  const maxTime = Math.max(dnsTime, connectTime, tlsTime, waitingTime, downloadTime, 1);

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

  const tabs: { key: DetailsTab; label: string }[] = [
    { key: 'timing', label: 'Timing' },
    { key: 'headers', label: 'Headers' },
    { key: 'initiator', label: 'Initiator' }
  ];

  return (
    <div className="border-t border-slate-700 mt-2 pt-2">
      {/* Tabs */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex gap-1">
          {tabs.map((tab) => (
            <button
              key={tab.key}
              type="button"
              onClick={() => onTabChange(tab.key)}
              className={`px-2 py-1 text-[10px] rounded transition-colors ${
                activeTab === tab.key
                  ? 'bg-blue-500/20 text-blue-300'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
        <button
          type="button"
          onClick={onClose}
          className="text-[10px] text-slate-500 hover:text-slate-300 px-1"
        >
          ✕
        </button>
      </div>

      {/* Timing Tab */}
      {activeTab === 'timing' && (
        <div className="space-y-3">
          {/* Waterfall Legend */}
          <div className="flex flex-wrap gap-2 text-[9px]">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded bg-cyan-500" />
              <span className="text-slate-400">DNS</span>
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded bg-amber-500" />
              <span className="text-slate-400">Connect</span>
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded bg-purple-500" />
              <span className="text-slate-400">TLS</span>
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded bg-blue-500" />
              <span className="text-slate-400">Waiting</span>
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded bg-emerald-500" />
              <span className="text-slate-400">Download</span>
            </span>
          </div>

          {/* Timing Waterfall */}
          <div className="space-y-1.5">
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
              <TimingBar label="TTFB" value={waitingTime} max={maxTime} color="bg-blue-500" />
            )}
            {downloadTime > 0 && (
              <TimingBar label="Download" value={downloadTime} max={maxTime} color="bg-emerald-500" />
            )}
            {dnsTime === 0 && connectTime === 0 && waitingTime === 0 && downloadTime === 0 && (
              <div className="text-[10px] text-slate-500 italic">No timing data (cached or cross-origin)</div>
            )}
          </div>

          {/* Summary */}
          <div className="grid grid-cols-2 gap-2 text-[10px] pt-2 border-t border-slate-700">
            <div>
              <span className="text-slate-500">Total: </span>
              <span className="text-slate-300">{entry.duration.toFixed(1)}ms</span>
            </div>
            {entry.ttfb !== undefined && entry.ttfb > 0 && (
              <div>
                <span className="text-slate-500">TTFB: </span>
                <span className="text-slate-300">{entry.ttfb.toFixed(1)}ms</span>
              </div>
            )}
            <div>
              <span className="text-slate-500">Transfer: </span>
              <span className="text-slate-300">{formatBytes(entry.transferSize)}</span>
            </div>
            {entry.decodedBodySize !== undefined && entry.decodedBodySize > 0 && (
              <div>
                <span className="text-slate-500">Decoded: </span>
                <span className="text-slate-300">{formatBytes(entry.decodedBodySize)}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Headers Tab */}
      {activeTab === 'headers' && (
        <div className="space-y-2">
          <div className="text-[10px] text-slate-500 italic">
            Note: Full headers unavailable in MV3. Use DevTools Network tab for complete header inspection.
          </div>
          {urlInfo && (
            <div className="space-y-1">
              <div className="text-[9px] uppercase tracking-widest text-slate-500">Request Details</div>
              <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[10px]">
                <span className="text-slate-500">Protocol</span>
                <span className="text-slate-300">{entry.nextHopProtocol || urlInfo.protocol}</span>
                <span className="text-slate-500">Host</span>
                <span className="text-slate-300 truncate">{urlInfo.host}</span>
                <span className="text-slate-500">Path</span>
                <span className="text-slate-300 truncate">{urlInfo.pathname}</span>
                {urlInfo.search && (
                  <>
                    <span className="text-slate-500">Query</span>
                    <span className="text-slate-300 truncate">{urlInfo.search}</span>
                  </>
                )}
                {entry.responseStatus !== undefined && entry.responseStatus > 0 && (
                  <>
                    <span className="text-slate-500">Status</span>
                    <span className={getStatusColor(entry.responseStatus)}>{entry.responseStatus}</span>
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Initiator Tab */}
      {activeTab === 'initiator' && (
        <div className="space-y-2">
          <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[10px]">
            <span className="text-slate-500">Type</span>
            <span className={getInitiatorColor(entry.initiatorType)}>{entry.initiatorType}</span>
            {entry.initiatorUrl && (
              <>
                <span className="text-slate-500">Source</span>
                <span className="text-slate-300 truncate" title={entry.initiatorUrl}>
                  {entry.initiatorUrl}
                </span>
              </>
            )}
            {entry.initiatorLine !== undefined && (
              <>
                <span className="text-slate-500">Line</span>
                <span className="text-slate-300">{entry.initiatorLine}</span>
              </>
            )}
          </div>
          {!entry.initiatorUrl && (
            <div className="text-[10px] text-slate-500 italic">
              Initiator details unavailable. Use DevTools for full call stack.
            </div>
          )}
        </div>
      )}
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
  const [localTab, setLocalTab] = useState<DetailsTab>('timing');

  const entries = data?.entries ?? [];
  const filterCategory = data?.filterCategory ?? 'all';
  const page = data?.page ?? 0;
  const selectedEntryIndex = data?.selectedEntryIndex;

  // Calculate max duration for waterfall scaling
  const maxDuration = useMemo(() => {
    if (entries.length === 0) return 0;
    return Math.max(...entries.map(e => e.duration ?? 0));
  }, [entries]);

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
    onChange({ ...data, filterCategory: category, page: 0, selectedEntryIndex: undefined });
  };

  const handlePageChange = (newPage: number) => {
    onChange({ ...data, page: newPage, selectedEntryIndex: undefined });
  };

  const handleClear = async () => {
    await onClear();
    onChange({ entries: [], filterCategory: 'all', page: 0, selectedEntryIndex: undefined });
  };

  const handleSelectEntry = (index: number) => {
    const newIndex = selectedEntryIndex === index ? undefined : index;
    onChange({ ...data, selectedEntryIndex: newIndex });
    if (newIndex !== undefined) {
      setLocalTab('timing');
    }
  };

  const handleTabChange = (tab: DetailsTab) => {
    setLocalTab(tab);
  };

  const handleCloseDetails = () => {
    onChange({ ...data, selectedEntryIndex: undefined });
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

  const selectedEntry = selectedEntryIndex !== undefined
    ? filteredEntries[selectedEntryIndex]
    : undefined;

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
            const isSelected = selectedEntryIndex === globalIndex;
            return (
              <div
                key={`${entry.name}-${entry.startTime}-${globalIndex}`}
                className={`rounded border transition-colors ${
                  isSelected
                    ? 'border-blue-500/50 bg-slate-800/80'
                    : 'border-slate-700 bg-slate-800/50 hover:border-slate-600'
                }`}
              >
                <div
                  role="button"
                  tabIndex={0}
                  onClick={() => handleSelectEntry(globalIndex)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      handleSelectEntry(globalIndex);
                    }
                  }}
                  className="w-full p-2 text-left cursor-pointer"
                >
                  {/* Compact Summary Row */}
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
                          <span className={`text-[9px] px-1 rounded ${getStatusColor(entry.responseStatus)} ${getStatusBgColor(entry.responseStatus)}`}>
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
                      <RequestBadges entry={entry} />
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
                        {isSelected ? '▼' : '▶'}
                      </span>
                    </div>
                  </div>

                  {/* Mini Waterfall */}
                  <div className="mt-2">
                    <WaterfallBar entry={entry} maxDuration={maxDuration} />
                  </div>
                </div>

                {/* Details Drawer */}
                {isSelected && selectedEntry && (
                  <div className="px-2 pb-2">
                    <DetailsDrawer
                      entry={selectedEntry}
                      activeTab={localTab}
                      onTabChange={handleTabChange}
                      onClose={handleCloseDetails}
                    />
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
            Prev
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
            Next
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
