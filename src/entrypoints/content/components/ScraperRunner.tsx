import React from 'react';
import type { ScraperDefinition } from '../../../shared/scraper';
import { buildCsvFromResults } from '../../../shared/scraper';

type ScraperRunnerProps = {
  scraper: ScraperDefinition;
  results: Record<string, string | string[]> | null;
  onRerun: () => Promise<void>;
  onClose: () => Promise<void>;
};

export const ScraperRunner: React.FC<ScraperRunnerProps> = ({
  scraper,
  results,
  onRerun,
  onClose
}) => {
  return (
    <div
      className="fixed inset-0 z-[95] flex items-start justify-center bg-slate-950/70 backdrop-blur-sm"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <div
        className="mt-12 w-full max-w-2xl max-h-[85vh] rounded-2xl border border-slate-700/80 bg-gradient-to-b from-slate-900 via-slate-900 to-slate-950 shadow-[0_24px_60px_rgba(0,0,0,0.55)] flex flex-col"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
          <div>
            <div className="text-xs text-slate-200">Run Scraper</div>
            <div className="text-[11px] text-slate-500">
              {scraper.name}
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 transition-colors"
          >
            ×
          </button>
        </div>
        <div className="space-y-4 px-5 py-4">
          <div className="flex items-center justify-between">
            <div className="text-[11px] text-slate-500">
              {results ? 'Results ready.' : 'No results yet.'}
            </div>
            <button
              type="button"
              onClick={onRerun}
              className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
            >
              Run Again
            </button>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto px-5 pb-4">
          {results ? (
            <div className="rounded border border-slate-800 bg-slate-900/60 p-3 space-y-2 text-[11px] text-slate-300">
              {Object.entries(results).map(([key, value]) => (
                <div key={key}>
                  <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                    {key}
                  </div>
                  <div className="break-words">
                    {Array.isArray(value) ? value.join(', ') : value}
                  </div>
                </div>
              ))}
            </div>
          ) : null}
        </div>
        <div className="flex items-center justify-end gap-2 border-t border-slate-800 px-5 py-4">
          <button
            type="button"
            onClick={() =>
              navigator.clipboard.writeText(
                JSON.stringify(results ?? {}, null, 2)
              )
            }
            className="rounded bg-slate-800 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Copy JSON
          </button>
          <button
            type="button"
            onClick={() =>
              navigator.clipboard.writeText(
                buildCsvFromResults(results ?? {})
              )
            }
            className="rounded bg-slate-800 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Copy CSV
          </button>
        </div>
      </div>
    </div>
  );
};
