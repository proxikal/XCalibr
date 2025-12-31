import React, { useState, useMemo } from 'react';
import type {
  AssetMapperData,
  AssetEntry
} from './tool-types';

const ITEMS_PER_PAGE = 10;

type AssetType = AssetEntry['type'] | 'all';

const ASSET_TYPE_CONFIG: Record<AssetType, { icon: string; color: string; label: string }> = {
  all: { icon: '📋', color: 'text-slate-300', label: 'All' },
  image: { icon: '🖼', color: 'text-emerald-400', label: 'Images' },
  script: { icon: '📜', color: 'text-amber-400', label: 'Scripts' },
  style: { icon: '🎨', color: 'text-purple-400', label: 'Styles' },
  preload: { icon: '⚡', color: 'text-blue-400', label: 'Preload' },
  prefetch: { icon: '📥', color: 'text-cyan-400', label: 'Prefetch' },
  'inline-script': { icon: '📝', color: 'text-orange-400', label: 'Inline' },
  'css-background': { icon: '🎭', color: 'text-pink-400', label: 'CSS BG' }
};

const formatSize = (bytes: number | undefined): string => {
  if (bytes === undefined) return '-';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
};

const AssetMapperToolComponent = ({
  data,
  onChange,
  onRefresh
}: {
  data: AssetMapperData | undefined;
  onChange?: (next: AssetMapperData) => void;
  onRefresh: () => Promise<void>;
}) => {
  const assets = data?.assets ?? [];
  const filterType = (data?.filterType ?? 'all') as AssetType;
  const filterOrigin = data?.filterOrigin ?? '';
  const groupByOrigin = data?.groupByOrigin ?? false;
  const [page, setPage] = useState(0);
  const [expandedOrigin, setExpandedOrigin] = useState<string | null>(null);

  // Get unique origins
  const origins = useMemo(() => {
    const originSet = new Set<string>();
    assets.forEach((a) => originSet.add(a.origin));
    return Array.from(originSet).sort();
  }, [assets]);

  // Get type counts
  const typeCounts = useMemo(() => {
    const counts: Record<string, number> = { all: assets.length };
    assets.forEach((a) => {
      counts[a.type] = (counts[a.type] || 0) + 1;
    });
    return counts;
  }, [assets]);

  // Filter assets
  const filteredAssets = useMemo(() => {
    let result = assets;
    if (filterType !== 'all') {
      result = result.filter((a) => a.type === filterType);
    }
    if (filterOrigin) {
      result = result.filter((a) => a.origin === filterOrigin);
    }
    return result;
  }, [assets, filterType, filterOrigin]);

  // Group by origin
  const groupedAssets = useMemo(() => {
    const groups: Record<string, AssetEntry[]> = {};
    filteredAssets.forEach((a) => {
      if (!groups[a.origin]) groups[a.origin] = [];
      groups[a.origin].push(a);
    });
    return groups;
  }, [filteredAssets]);

  // Paginate
  const totalPages = Math.ceil(filteredAssets.length / ITEMS_PER_PAGE);
  const paginatedAssets = filteredAssets.slice(
    page * ITEMS_PER_PAGE,
    (page + 1) * ITEMS_PER_PAGE
  );

  const handleTypeFilter = (type: AssetType) => {
    onChange?.({ ...data, filterType: type === 'all' ? undefined : type });
    setPage(0);
  };

  const handleOriginFilter = (origin: string) => {
    onChange?.({ ...data, filterOrigin: origin || undefined });
    setPage(0);
  };

  const handleGroupToggle = () => {
    onChange?.({ ...data, groupByOrigin: !groupByOrigin });
  };

  const handleSavePlainText = () => {
    const text = Object.entries(groupedAssets)
      .map(([origin, items]) =>
        `# ${origin} (${items.length})\n${items.map((a) => `  [${a.type}] ${a.url}`).join('\n')}`
      )
      .join('\n\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `assets-${window.location.hostname}-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleSaveJSON = () => {
    const json = JSON.stringify(filteredAssets, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `assets-${window.location.hostname}-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const renderAssetRow = (asset: AssetEntry, idx: number) => {
    const config = ASSET_TYPE_CONFIG[asset.type];
    const displayUrl = asset.url.startsWith('inline-script-')
      ? asset.url.replace(/^inline-script-\d+:/, 'Inline: ').slice(0, 60)
      : asset.url;

    return (
      <div
        key={`${asset.url}-${idx}`}
        className="rounded border border-slate-700 bg-slate-800/50 px-2 py-1.5 hover:bg-slate-700/50 transition-colors"
      >
        <div className="flex items-center gap-2">
          <span className={`text-[10px] ${config.color}`}>{config.icon}</span>
          <span className={`text-[9px] px-1 rounded ${config.color} bg-slate-700/50`}>
            {asset.type}
          </span>
          {asset.size !== undefined && (
            <span className="text-[9px] text-slate-500">{formatSize(asset.size)}</span>
          )}
        </div>
        <a
          href={asset.url.startsWith('inline-script-') ? undefined : asset.url}
          target="_blank"
          rel="noopener noreferrer"
          className={`block text-[10px] truncate mt-1 ${
            asset.url.startsWith('inline-script-') ? 'text-slate-400' : 'text-slate-300 hover:text-slate-100'
          }`}
          title={asset.url}
        >
          {displayUrl}
        </a>
        {asset.sourceElement && (
          <div className="text-[9px] text-slate-500 mt-0.5">{asset.sourceElement}</div>
        )}
      </div>
    );
  };

  const renderGroupedView = () => (
    <div className="space-y-2">
      {Object.entries(groupedAssets).map(([origin, items]) => (
        <div key={origin} className="rounded border border-slate-700 overflow-hidden">
          <button
            type="button"
            onClick={() => setExpandedOrigin(expandedOrigin === origin ? null : origin)}
            className="w-full flex items-center justify-between px-2 py-1.5 bg-slate-800 hover:bg-slate-700/80 transition-colors text-left"
          >
            <div className="flex items-center gap-2">
              <span className="text-[9px] text-slate-400">
                {expandedOrigin === origin ? '▼' : '▶'}
              </span>
              <span className="text-[10px] text-slate-300 truncate max-w-[280px]" title={origin}>
                {origin}
              </span>
            </div>
            <span className="text-[9px] text-slate-500">{items.length} assets</span>
          </button>
          {expandedOrigin === origin && (
            <div className="p-2 space-y-1 bg-slate-800/30">
              {items.map((asset, idx) => renderAssetRow(asset, idx))}
            </div>
          )}
        </div>
      ))}
    </div>
  );

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
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

      {/* Stats */}
      <div className="text-[10px] text-slate-500 mb-2">
        {filteredAssets.length} assets
        {filterType !== 'all' && ` (${filterType})`}
        {filterOrigin && ` from ${new URL(filterOrigin).hostname}`}
        {filteredAssets.length !== assets.length && ` of ${assets.length} total`}
      </div>

      {/* Type Filter */}
      <div className="mb-2 flex-shrink-0">
        <div className="text-[9px] uppercase tracking-widest text-slate-500 mb-1">Filter by Type</div>
        <div className="flex flex-wrap gap-1">
          {(Object.keys(ASSET_TYPE_CONFIG) as AssetType[]).map((type) => {
            const config = ASSET_TYPE_CONFIG[type];
            const count = typeCounts[type] || 0;
            if (type !== 'all' && count === 0) return null;
            return (
              <button
                key={type}
                type="button"
                onClick={() => handleTypeFilter(type)}
                className={`rounded px-2 py-1 text-[10px] border transition-colors ${
                  filterType === type
                    ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                    : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                }`}
              >
                <span className="mr-1">{config.icon}</span>
                {config.label} ({count})
              </button>
            );
          })}
        </div>
      </div>

      {/* Origin Filter */}
      {origins.length > 1 && (
        <div className="mb-2 flex-shrink-0">
          <div className="text-[9px] uppercase tracking-widest text-slate-500 mb-1">Filter by Origin</div>
          <select
            value={filterOrigin}
            onChange={(e) => handleOriginFilter(e.target.value)}
            className="w-full rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
          >
            <option value="">All Origins ({origins.length})</option>
            {origins.map((origin) => (
              <option key={origin} value={origin}>
                {new URL(origin).hostname} ({groupedAssets[origin]?.length || 0})
              </option>
            ))}
          </select>
        </div>
      )}

      {/* Group Toggle */}
      <div className="mb-2 flex-shrink-0">
        <label className="flex items-center gap-2 text-[10px] text-slate-400 cursor-pointer">
          <input
            type="checkbox"
            checked={groupByOrigin}
            onChange={handleGroupToggle}
            className="rounded border-slate-700 bg-slate-800"
          />
          Group by origin
        </label>
      </div>

      {/* Asset List */}
      <div className="flex-1 overflow-y-auto space-y-1 min-h-0 mb-2">
        {filteredAssets.length === 0 ? (
          <div className="text-[11px] text-slate-500 text-center py-4">
            No assets found. Click Refresh to scan the page.
          </div>
        ) : groupByOrigin ? (
          renderGroupedView()
        ) : (
          paginatedAssets.map((asset, idx) => renderAssetRow(asset, idx))
        )}
      </div>

      {/* Pagination (only in flat view) */}
      {!groupByOrigin && totalPages > 1 && (
        <div className="flex items-center justify-between mb-2 pt-2 border-t border-slate-700">
          <button
            type="button"
            onClick={() => setPage(Math.max(0, page - 1))}
            disabled={page === 0}
            className="text-[10px] text-slate-400 hover:text-slate-200 disabled:opacity-30"
          >
            Prev
          </button>
          <span className="text-[10px] text-slate-500">
            {page + 1} / {totalPages}
          </span>
          <button
            type="button"
            onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
            disabled={page >= totalPages - 1}
            className="text-[10px] text-slate-400 hover:text-slate-200 disabled:opacity-30"
          >
            Next
          </button>
        </div>
      )}

      {/* Export Buttons */}
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
