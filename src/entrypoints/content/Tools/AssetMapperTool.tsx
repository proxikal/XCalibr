import React from 'react';
import type {
  AssetMapperData
} from './tool-types';

const AssetMapperToolComponent = ({
  data,
  onRefresh
}: {
  data: AssetMapperData | undefined;
  onRefresh: () => Promise<void>;
}) => {
  const images = data?.images ?? [];
  const scripts = data?.scripts ?? [];
  const styles = data?.styles ?? [];

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">Asset Mapper</div>
        <button
          type="button"
          onClick={onRefresh}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Refresh
        </button>
      </div>
      <div className="text-[11px] text-slate-500">
        {images.length} images • {scripts.length} scripts • {styles.length} styles
      </div>
      <div className="space-y-2 max-h-40 overflow-y-auto no-scrollbar text-[11px] text-slate-300">
        {images.map((asset) => (
          <div key={`img-${asset}`} className="break-words">
            {asset}
          </div>
        ))}
        {scripts.map((asset) => (
          <div key={`script-${asset}`} className="break-words text-slate-400">
            {asset}
          </div>
        ))}
        {styles.map((asset) => (
          <div key={`style-${asset}`} className="break-words text-slate-500">
            {asset}
          </div>
        ))}
      </div>
    </div>
  );
};
export class AssetMapperTool {
  static Component = AssetMapperToolComponent;
}
