import React, { useState } from 'react';
import type {
  RobotsViewerData
} from './tool-types';

const RobotsViewerToolComponent = ({
  data,
  onRefresh
}: {
  data: RobotsViewerData | undefined;
  onRefresh: () => Promise<void>;
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const handleRefresh = async () => {
    setIsLoading(true);
    await onRefresh();
    setIsLoading(false);
  };
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs text-slate-200">Robots.txt Viewer</div>
          <div className="text-[11px] text-slate-500">{data?.url ?? ''}</div>
        </div>
        <button
          type="button"
          onClick={handleRefresh}
          disabled={isLoading}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          {isLoading ? 'Loading...' : 'Fetch'}
        </button>
      </div>
      {data?.error ? (
        <div className="rounded border border-rose-500/30 bg-rose-500/10 px-2 py-1 text-[11px] text-rose-200">
          {data.error}
        </div>
      ) : null}
      <textarea
        value={data?.content ?? ''}
        readOnly
        rows={8}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none"
        placeholder="robots.txt will appear here..."
      />
    </div>
  );
};
export class RobotsViewerTool {
  static Component = RobotsViewerToolComponent;
}
