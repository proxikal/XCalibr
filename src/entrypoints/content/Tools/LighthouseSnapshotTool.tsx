import React from 'react';
import type {
  LighthouseSnapshotData
} from './tool-types';

const LighthouseSnapshotToolComponent = ({
  data,
  onCapture
}: {
  data: LighthouseSnapshotData | undefined;
  onCapture: () => void;
}) => {
  const metrics = data?.metrics ?? [];
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">Lighthouse Snapshot</div>
        <button
          type="button"
          onClick={onCapture}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Capture
        </button>
      </div>
      <div className="space-y-1 text-[11px] text-slate-300">
        {metrics.length === 0 ? (
          <div className="text-slate-500">No snapshot yet.</div>
        ) : (
          metrics.map((metric) => (
            <div key={metric.label} className="flex items-center justify-between">
              <span className="text-slate-400">{metric.label}</span>
              <span>{metric.value}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
export class LighthouseSnapshotTool {
  static Component = LighthouseSnapshotToolComponent;
}
