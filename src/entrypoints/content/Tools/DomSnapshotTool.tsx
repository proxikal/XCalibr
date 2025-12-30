import React from 'react';
import type {
  DomSnapshotData
} from './tool-types';

const DomSnapshotToolComponent = ({
  data,
  onCapture
}: {
  data: DomSnapshotData | undefined;
  onCapture: () => Promise<void>;
}) => {
  const html = data?.html ?? '';
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">DOM Snapshot</div>
        <button
          type="button"
          onClick={onCapture}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Capture
        </button>
      </div>
      <textarea
        value={html}
        readOnly
        rows={6}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none"
        placeholder="Snapshot will appear here..."
      />
      <button
        type="button"
        onClick={() => navigator.clipboard.writeText(html)}
        disabled={!html}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Copy HTML
      </button>
    </div>
  );
};
export class DomSnapshotTool {
  static Component = DomSnapshotToolComponent;
}
