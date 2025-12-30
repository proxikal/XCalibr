import React from 'react';
import type {
  LinkExtractorData
} from './tool-types';

const LinkExtractorToolComponent = ({
  data,
  onRefresh
}: {
  data: LinkExtractorData | undefined;
  onRefresh: () => Promise<void>;
}) => {
  const internal = data?.internal ?? [];
  const external = data?.external ?? [];

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">Link Extractor</div>
        <button
          type="button"
          onClick={onRefresh}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Refresh
        </button>
      </div>
      <div className="text-[11px] text-slate-500">
        {internal.length} internal • {external.length} external
      </div>
      <div className="space-y-2 max-h-40 overflow-y-auto no-scrollbar">
        {internal.map((link) => (
          <div key={link} className="text-[11px] text-slate-300 break-words">
            {link}
          </div>
        ))}
        {external.map((link) => (
          <div key={link} className="text-[11px] text-slate-400 break-words">
            {link}
          </div>
        ))}
      </div>
      <div className="flex gap-2">
        <button
          type="button"
          onClick={() =>
            navigator.clipboard.writeText(
              JSON.stringify({ internal, external }, null, 2)
            )
          }
          className="flex-1 rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
        >
          Copy JSON
        </button>
        <button
          type="button"
          onClick={() => {
            const csv = [...internal, ...external].join('\n');
            navigator.clipboard.writeText(csv);
          }}
          className="flex-1 rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
        >
          Copy CSV
        </button>
      </div>
    </div>
  );
};
export class LinkExtractorTool {
  static Component = LinkExtractorToolComponent;
}
