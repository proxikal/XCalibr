import React from 'react';
import type {
  RequestLogData
} from './tool-types';

const RequestLogToolComponent = ({
  data,
  onClear
}: {
  data: RequestLogData | undefined;
  onClear: () => Promise<void>;
}) => {
  const entries = data?.entries ?? [];
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">Request Log</div>
        <button
          type="button"
          onClick={onClear}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Clear
        </button>
      </div>
      {entries.length === 0 ? (
        <div className="text-[11px] text-slate-500">
          No requests captured yet.
        </div>
      ) : (
        <div className="max-h-40 overflow-y-auto no-scrollbar space-y-1">
          {entries.map((entry, index) => (
            <div
              key={`${entry.name}-${entry.startTime}-${index}`}
              className="rounded border border-slate-800 bg-slate-800/60 px-2 py-1 text-[11px] text-slate-300"
            >
              <div className="break-words">{entry.name}</div>
              <div className="text-[10px] text-slate-500">
                {entry.initiatorType} • {entry.duration.toFixed(1)}ms
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
export class RequestLogTool {
  static Component = RequestLogToolComponent;
}
