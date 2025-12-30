import React from 'react';
import type {
  ResponsivePreviewData
} from './tool-types';

const ResponsivePreviewToolComponent = ({
  data,
  onChange
}: {
  data: ResponsivePreviewData | undefined;
  onChange: (next: ResponsivePreviewData) => void;
}) => {
  const width = data?.width ?? '375';
  const height = data?.height ?? '812';
  const status = data?.status ?? '';

  const handleOpen = () => {
    const w = Number(width);
    const h = Number(height);
    if (!Number.isFinite(w) || !Number.isFinite(h)) {
      onChange({ width, height, status: 'Invalid size.' });
      return;
    }
    window.open(window.location.href, '_blank', `width=${w},height=${h}`);
    onChange({ width, height, status: 'Opened preview window.' });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Responsive Preview</div>
      <div className="flex gap-2">
        <input
          type="text"
          value={width}
          onChange={(event) => onChange({ width: event.target.value, height, status })}
          className="w-1/2 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
          placeholder="Width"
        />
        <input
          type="text"
          value={height}
          onChange={(event) => onChange({ width, height: event.target.value, status })}
          className="w-1/2 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
          placeholder="Height"
        />
      </div>
      <button
        type="button"
        onClick={handleOpen}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Open Preview Window
      </button>
      {status ? <div className="text-[11px] text-slate-500">{status}</div> : null}
    </div>
  );
};
export class ResponsivePreviewTool {
  static Component = ResponsivePreviewToolComponent;
}
