import React, { useState } from 'react';
import type {
  LinkExtractorData
} from './tool-types';

const ITEMS_PER_PAGE = 12;

const LinkExtractorToolComponent = ({
  data,
  onRefresh
}: {
  data: LinkExtractorData | undefined;
  onRefresh: () => Promise<void>;
}) => {
  const internal = data?.internal ?? [];
  const external = data?.external ?? [];
  const [activeTab, setActiveTab] = useState<'internal' | 'external'>('internal');
  const [page, setPage] = useState(0);

  const activeLinks = activeTab === 'internal' ? internal : external;
  const totalPages = Math.ceil(activeLinks.length / ITEMS_PER_PAGE);
  const paginatedLinks = activeLinks.slice(
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
    const csv = 'type,url\n' +
      internal.map((l) => `internal,"${l}"`).join('\n') + '\n' +
      external.map((l) => `external,"${l}"`).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `links-${window.location.hostname}-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleSavePlainText = () => {
    const text = `# Internal Links (${internal.length})\n${internal.join('\n')}\n\n# External Links (${external.length})\n${external.join('\n')}`;
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `links-${window.location.hostname}-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-2">
        <div className="text-xs text-slate-200">Link Extractor</div>
        <button
          type="button"
          onClick={onRefresh}
          className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Refresh
        </button>
      </div>

      <div className="text-[10px] text-slate-500 mb-2">
        {internal.length + external.length} total links on {window.location.hostname}
      </div>

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

      <div className="flex-1 overflow-y-auto space-y-1 min-h-0 mb-2">
        {paginatedLinks.length === 0 ? (
          <div className="text-[11px] text-slate-500 text-center py-4">
            No {activeTab} links found.
          </div>
        ) : (
          paginatedLinks.map((link, idx) => (
            <a
              key={`${link}-${idx}`}
              href={link}
              target="_blank"
              rel="noopener noreferrer"
              className={`block rounded border px-2 py-1 text-[10px] truncate hover:bg-slate-700/50 transition-colors ${
                activeTab === 'internal'
                  ? 'border-slate-700 bg-slate-800/50 text-emerald-300'
                  : 'border-slate-700 bg-slate-800/50 text-amber-300'
              }`}
              title={link}
            >
              {link}
            </a>
          ))
        )}
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between mb-2 pt-2 border-t border-slate-700">
          <button
            type="button"
            onClick={() => setPage(Math.max(0, page - 1))}
            disabled={page === 0}
            className="text-[10px] text-slate-400 hover:text-slate-200 disabled:opacity-30"
          >
            ← Prev
          </button>
          <span className="text-[10px] text-slate-500">
            {page + 1} / {totalPages}
          </span>
          <button
            type="button"
            onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
            disabled={page >= totalPages - 1}
            className="text-[10px] text-slate-400 hover:text-slate-200 disabled:opacity-30"
          >
            Next →
          </button>
        </div>
      )}

      <div className="flex gap-1">
        <button
          type="button"
          onClick={handleSavePlainText}
          className="flex-1 rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Save TXT
        </button>
        <button
          type="button"
          onClick={handleSaveCSV}
          className="flex-1 rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Save CSV
        </button>
        <button
          type="button"
          onClick={handleSaveJSON}
          className="flex-1 rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Save JSON
        </button>
      </div>
    </div>
  );
};
export class LinkExtractorTool {
  static Component = LinkExtractorToolComponent;
}
