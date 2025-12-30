import React from 'react';
import type {
  DebuggerData
} from './tool-types';

const DebuggerToolComponent = ({
  data,
  onClear
}: {
  data: DebuggerData | undefined;
  onClear: () => void;
}) => {
  const entries = data?.entries ?? [];
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">Debugger</div>
        <button
          type="button"
          onClick={onClear}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Clear
        </button>
      </div>
      {entries.length === 0 ? (
        <div className="text-[11px] text-slate-500">No errors captured.</div>
      ) : (
        <div className="max-h-40 overflow-y-auto no-scrollbar space-y-2 text-[11px] text-slate-300">
          {entries.map((entry, index) => (
            <div key={`${entry.time}-${index}`} className="rounded border border-slate-800 bg-slate-900/60 px-2 py-1">
              <div className="text-[10px] text-slate-500">
                {new Date(entry.time).toLocaleTimeString()} • {entry.source}
              </div>
              <div className="break-words">{entry.message}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
export class DebuggerTool {
  static Component = DebuggerToolComponent;
}
