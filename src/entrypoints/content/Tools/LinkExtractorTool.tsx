import React, { useState } from 'react';
import type {
  LinkExtractorData,
  ExtractedLink,
  LinkSource
} from './tool-types';

const ITEMS_PER_PAGE = 25;

const SOURCE_BADGES: Record<LinkSource, { label: string; color: string }> = {
  anchor: { label: 'A', color: 'bg-blue-500/20 text-blue-300' },
  onclick: { label: 'JS', color: 'bg-amber-500/20 text-amber-300' },
  script: { label: 'SC', color: 'bg-purple-500/20 text-purple-300' },
  router: { label: 'RT', color: 'bg-emerald-500/20 text-emerald-300' },
  form: { label: 'FM', color: 'bg-rose-500/20 text-rose-300' },
  meta: { label: 'MT', color: 'bg-cyan-500/20 text-cyan-300' },
  sitemap: { label: 'SM', color: 'bg-orange-500/20 text-orange-300' },
};

const SOURCE_FILTERS: { value: LinkSource | 'all'; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'anchor', label: 'Anchors' },
  { value: 'onclick', label: 'OnClick' },
  { value: 'script', label: 'Scripts' },
  { value: 'router', label: 'Router' },
  { value: 'form', label: 'Forms' },
  { value: 'meta', label: 'Meta' },
];

const LinkExtractorToolComponent = ({
  data,
  onChange,
  onRefresh
}: {
  data: LinkExtractorData | undefined;
  onChange: (next: LinkExtractorData) => void;
  onRefresh: () => Promise<void>;
}) => {
  const internal = data?.internal ?? [];
  const external = data?.external ?? [];
  const filterText = data?.filterText ?? '';
  const filterSource = data?.filterSource ?? 'all';
  const showContext = data?.showContext ?? false;
  const [activeTab, setActiveTab] = useState<'internal' | 'external'>('internal');
  const [page, setPage] = useState(0);

  const activeLinks = activeTab === 'internal' ? internal : external;

  // Apply filters
  const filteredLinks = activeLinks.filter(link => {
    const matchesText = !filterText ||
      link.url.toLowerCase().includes(filterText.toLowerCase()) ||
      (link.context?.toLowerCase().includes(filterText.toLowerCase())) ||
      (link.text?.toLowerCase().includes(filterText.toLowerCase()));
    const matchesSource = filterSource === 'all' || link.source === filterSource;
    return matchesText && matchesSource;
  });

  const totalPages = Math.ceil(filteredLinks.length / ITEMS_PER_PAGE);
  const paginatedLinks = filteredLinks.slice(
    page * ITEMS_PER_PAGE,
    (page + 1) * ITEMS_PER_PAGE
  );

  const handleSaveJSON = () => {
    const json = JSON.stringify({ internal, external }, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `links-${window.location.hostname}-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleSaveCSV = () => {
    const header = 'type,url,source,context,text\n';
    const rows = [
      ...internal.map((l) => `internal,"${l.url}","${l.source}","${l.context ?? ''}","${l.text ?? ''}"`),
      ...external.map((l) => `external,"${l.url}","${l.source}","${l.context ?? ''}","${l.text ?? ''}"`)
    ].join('\n');
    const csv = header + rows;
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `links-${window.location.hostname}-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleSavePlainText = () => {
    const text = `# Internal Links (${internal.length})\n${internal.map(l => l.url).join('\n')}\n\n# External Links (${external.length})\n${external.map(l => l.url).join('\n')}`;
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `links-${window.location.hostname}-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getSourceBadge = (source: LinkSource) => {
    const badge = SOURCE_BADGES[source] || { label: '?', color: 'bg-slate-500/20 text-slate-300' };
    return badge;
  };

  const updateFilter = (key: 'filterText' | 'filterSource' | 'showContext', value: string | boolean) => {
    setPage(0);
    onChange({ ...data, [key]: value });
  };

  // Get source statistics
  const getSourceStats = (links: ExtractedLink[]) => {
    const stats: Partial<Record<LinkSource, number>> = {};
    for (const link of links) {
      stats[link.source] = (stats[link.source] || 0) + 1;
    }
    return stats;
  };

  const sourceStats = getSourceStats(activeLinks);

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <div className="text-xs text-slate-200">Link Extractor</div>
        <div className="flex gap-1">
          <button
            type="button"
            onClick={() => updateFilter('showContext', !showContext)}
            className={`rounded px-2 py-1 text-[9px] border transition-colors ${
              showContext
                ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-300'
                : 'bg-slate-800 border-slate-700 text-slate-400'
            }`}
          >
            Context
          </button>
          <button
            type="button"
            onClick={onRefresh}
            className="rounded bg-slate-800 px-2 py-1 text-[9px] text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="text-[9px] text-slate-500 mb-2">
        {internal.length + external.length} total links ({internal.length} internal, {external.length} external)
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-2">
        <button
          type="button"
          onClick={() => { setActiveTab('internal'); setPage(0); }}
          className={`flex-1 rounded px-2 py-1 text-[10px] border transition-colors ${
            activeTab === 'internal'
              ? 'bg-emerald-500/10 border-emerald-500/50 text-emerald-300'
              : 'bg-slate-800 border-slate-700 text-slate-400'
          }`}
        >
          Internal ({internal.length})
        </button>
        <button
          type="button"
          onClick={() => { setActiveTab('external'); setPage(0); }}
          className={`flex-1 rounded px-2 py-1 text-[10px] border transition-colors ${
            activeTab === 'external'
              ? 'bg-amber-500/10 border-amber-500/50 text-amber-300'
              : 'bg-slate-800 border-slate-700 text-slate-400'
          }`}
        >
          External ({external.length})
        </button>
      </div>

      {/* Search Filter */}
      <input
        type="text"
        value={filterText}
        onChange={(e) => updateFilter('filterText', e.target.value)}
        placeholder="Filter links..."
        className="w-full rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1.5 mb-2 border border-slate-700 focus:outline-none focus:border-blue-500"
      />

      {/* Source Filter */}
      <div className="flex flex-wrap gap-1 mb-2">
        {SOURCE_FILTERS.map((sf) => {
          const count = sf.value === 'all' ? activeLinks.length : (sourceStats[sf.value as LinkSource] || 0);
          return (
            <button
              key={sf.value}
              type="button"
              onClick={() => updateFilter('filterSource', sf.value)}
              className={`rounded px-1.5 py-0.5 text-[10px] border transition-colors ${
                filterSource === sf.value
                  ? 'bg-blue-500/20 border-blue-500/50 text-blue-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400'
              }`}
            >
              {sf.label} {count > 0 && `(${count})`}
            </button>
          );
        })}
      </div>

      {/* Links List */}
      <div className="flex-1 overflow-y-auto space-y-px min-h-0 mb-1">
        {paginatedLinks.length === 0 ? (
          <div className="text-[11px] text-slate-500 text-center py-2">
            No {activeTab} links found.
          </div>
        ) : (
          paginatedLinks.map((link, idx) => {
            const badge = getSourceBadge(link.source);
            return (
              <div
                key={`${link.url}-${idx}`}
                className="flex items-center gap-1 px-1 py-0.5 hover:bg-slate-800/50 rounded transition-colors"
              >
                <span
                  className={`rounded px-1 text-[9px] font-mono shrink-0 ${badge.color}`}
                  title={link.source}
                >
                  {badge.label}
                </span>
                <a
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={`flex-1 text-[11px] truncate hover:underline ${
                    activeTab === 'internal' ? 'text-emerald-300' : 'text-amber-300'
                  }`}
                  title={`${link.url}${showContext && link.text ? ` - "${link.text}"` : ''}`}
                >
                  {link.url}
                </a>
                {showContext && link.text && (
                  <span className="text-[10px] text-slate-500 truncate max-w-[120px]" title={link.text}>
                    {link.text}
                  </span>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mb-2 pt-2 border-t border-slate-700">
          <button
            type="button"
            onClick={() => setPage(Math.max(0, page - 1))}
            disabled={page === 0}
            className="text-[9px] text-slate-400 hover:text-slate-200 disabled:opacity-30"
          >
            Prev
          </button>
          <span className="text-[9px] text-slate-500">
            {page + 1} / {totalPages} ({filteredLinks.length} links)
          </span>
          <button
            type="button"
            onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
            disabled={page >= totalPages - 1}
            className="text-[9px] text-slate-400 hover:text-slate-200 disabled:opacity-30"
          >
            Next
          </button>
        </div>
      )}

      {/* Export Buttons */}
      <div className="flex gap-1">
        <button
          type="button"
          onClick={handleSavePlainText}
          className="flex-1 rounded bg-slate-800 px-2 py-1 text-[9px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          TXT
        </button>
        <button
          type="button"
          onClick={handleSaveCSV}
          className="flex-1 rounded bg-slate-800 px-2 py-1 text-[9px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          CSV
        </button>
        <button
          type="button"
          onClick={handleSaveJSON}
          className="flex-1 rounded bg-slate-800 px-2 py-1 text-[9px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          JSON
        </button>
      </div>
    </div>
  );
};

export class LinkExtractorTool {
  static Component = LinkExtractorToolComponent;
}
