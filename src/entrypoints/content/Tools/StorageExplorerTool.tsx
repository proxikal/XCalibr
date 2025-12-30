import React from 'react';
import type {
  StorageExplorerData
} from './tool-types';

const StorageExplorerToolComponent = ({
  data,
  onRefresh
}: {
  data: StorageExplorerData | undefined;
  onRefresh: () => void;
}) => {
  const local = data?.local ?? [];
  const session = data?.session ?? [];
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">Storage Explorer</div>
        <button
          type="button"
          onClick={onRefresh}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Refresh
        </button>
      </div>
      <div className="text-[11px] text-slate-500">Local Storage</div>
      <div className="max-h-24 overflow-y-auto no-scrollbar space-y-1 text-[11px] text-slate-300">
        {local.length === 0 ? 'No entries.' : null}
        {local.map((entry) => (
          <div key={`local-${entry.key}`} className="break-words">
            {entry.key}: {entry.value}
          </div>
        ))}
      </div>
      <div className="text-[11px] text-slate-500">Session Storage</div>
      <div className="max-h-24 overflow-y-auto no-scrollbar space-y-1 text-[11px] text-slate-300">
        {session.length === 0 ? 'No entries.' : null}
        {session.map((entry) => (
          <div key={`session-${entry.key}`} className="break-words">
            {entry.key}: {entry.value}
          </div>
        ))}
      </div>
    </div>
  );
};
export class StorageExplorerTool {
  static Component = StorageExplorerToolComponent;
}
