import React, { useState } from 'react';
import type {
  AssetMapperData
} from './tool-types';

const ITEMS_PER_PAGE = 10;

type AssetTab = 'images' | 'scripts' | 'styles';

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
  const [activeTab, setActiveTab] = useState<AssetTab>('images');
  const [pages, setPages] = useState({ images: 0, scripts: 0, styles: 0 });

  const assets = { images, scripts, styles };
  const activeAssets = assets[activeTab];
  const currentPage = pages[activeTab];
  const totalPages = Math.ceil(activeAssets.length / ITEMS_PER_PAGE);
  const paginatedAssets = activeAssets.slice(
    currentPage * ITEMS_PER_PAGE,
    (currentPage + 1) * ITEMS_PER_PAGE
  );

  const setPage = (page: number) => {
    setPages((prev) => ({ ...prev, [activeTab]: page }));
  };

  const getTabIcon = (tab: AssetTab) => {
    switch (tab) {
      case 'images': return '🖼';
      case 'scripts': return '📜';
      case 'styles': return '🎨';
    }
  };

  const getTabStyle = (tab: AssetTab) => {
    const isActive = activeTab === tab;
    switch (tab) {
      case 'images':
        return isActive
          ? 'bg-emerald-500/10 border-emerald-500/50 text-emerald-300'
          : 'bg-slate-800 border-slate-700 text-slate-400';
      case 'scripts':
        return isActive
          ? 'bg-amber-500/10 border-amber-500/50 text-amber-300'
          : 'bg-slate-800 border-slate-700 text-slate-400';
      case 'styles':
        return isActive
          ? 'bg-purple-500/10 border-purple-500/50 text-purple-300'
          : 'bg-slate-800 border-slate-700 text-slate-400';
    }
  };

  const handleSavePlainText = () => {
    const text = `# Images (${images.length})\n${images.join('\n')}\n\n# Scripts (${scripts.length})\n${scripts.join('\n')}\n\n# Styles (${styles.length})\n${styles.join('\n')}`;
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `assets-${window.location.hostname}-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleSaveJSON = () => {
    const json = JSON.stringify({ images, scripts, styles }, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `assets-${window.location.hostname}-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-2">
        <div className="text-xs text-slate-200">Asset Mapper</div>
        <button
          type="button"
          onClick={onRefresh}
          className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Refresh
        </button>
      </div>

      <div className="text-[10px] text-slate-500 mb-2">
        {images.length + scripts.length + styles.length} total assets
      </div>

      <div className="flex gap-1 mb-2">
        {(['images', 'scripts', 'styles'] as const).map((tab) => (
          <button
            key={tab}
            type="button"
            onClick={() => setActiveTab(tab)}
            className={`flex-1 rounded px-2 py-1 text-[10px] border transition-colors ${getTabStyle(tab)}`}
          >
            {getTabIcon(tab)} {tab.charAt(0).toUpperCase() + tab.slice(1)} ({assets[tab].length})
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto space-y-1 min-h-0 mb-2">
        {paginatedAssets.length === 0 ? (
          <div className="text-[11px] text-slate-500 text-center py-4">
            No {activeTab} found.
          </div>
        ) : (
          paginatedAssets.map((asset, idx) => (
            <a
              key={`${asset}-${idx}`}
              href={asset}
              target="_blank"
              rel="noopener noreferrer"
              className="block rounded border border-slate-700 bg-slate-800/50 px-2 py-1.5 text-[10px] truncate text-slate-300 hover:bg-slate-700/50 hover:text-slate-100 transition-colors"
              title={asset}
            >
              <span className="mr-2">{getTabIcon(activeTab)}</span>
              {asset}
            </a>
          ))
        )}
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between mb-2 pt-2 border-t border-slate-700">
          <button
            type="button"
            onClick={() => setPage(Math.max(0, currentPage - 1))}
            disabled={currentPage === 0}
            className="text-[10px] text-slate-400 hover:text-slate-200 disabled:opacity-30"
          >
            ← Prev
          </button>
          <span className="text-[10px] text-slate-500">
            {currentPage + 1} / {totalPages}
          </span>
          <button
            type="button"
            onClick={() => setPage(Math.min(totalPages - 1, currentPage + 1))}
            disabled={currentPage >= totalPages - 1}
            className="text-[10px] text-slate-400 hover:text-slate-200 disabled:opacity-30"
          >
            Next →
          </button>
        </div>
      )}

      <div className="flex gap-2">
        <button
          type="button"
          onClick={handleSavePlainText}
          className="flex-1 rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Save as Text
        </button>
        <button
          type="button"
          onClick={handleSaveJSON}
          className="flex-1 rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Save as JSON
        </button>
      </div>
    </div>
  );
};
export class AssetMapperTool {
  static Component = AssetMapperToolComponent;
}
