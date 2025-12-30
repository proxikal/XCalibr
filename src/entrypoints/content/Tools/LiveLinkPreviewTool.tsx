import React from 'react';
import type {
  LiveLinkPreviewData
} from './tool-types';

const LiveLinkPreviewToolComponent = ({
  data,
  onChange
}: {
  data: LiveLinkPreviewData | undefined;
  onChange: (next: LiveLinkPreviewData) => void;
}) => {
  const isActive = data?.isActive ?? false;
  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Live Link Preview</div>
      <div className="text-[11px] text-slate-500">
        Hover over links to preview destinations. Only active when toggled on.
      </div>
      <button
        type="button"
        onClick={() => onChange({ isActive: !isActive })}
        className={`w-full rounded px-2 py-1.5 text-xs border transition-colors ${
          isActive
            ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-200'
            : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
        }`}
      >
        {isActive ? 'Active' : 'Inactive'}
      </button>
    </div>
  );
};
export class LiveLinkPreviewTool {
  static Component = LiveLinkPreviewToolComponent;
}
