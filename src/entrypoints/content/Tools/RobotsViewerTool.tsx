import React, { useState, useMemo } from 'react';
import type {
  RobotsViewerData
} from './tool-types';

type ParsedLine = {
  type: 'user-agent' | 'allow' | 'disallow' | 'sitemap' | 'crawl-delay' | 'comment' | 'other';
  directive?: string;
  value: string;
  raw: string;
};

const parseRobotsTxt = (content: string): ParsedLine[] => {
  const lines = content.split('\n');
  return lines.map((line) => {
    const trimmed = line.trim();
    if (!trimmed) return { type: 'other', value: '', raw: line };
    if (trimmed.startsWith('#')) {
      return { type: 'comment', value: trimmed.slice(1).trim(), raw: line };
    }
    const colonIndex = trimmed.indexOf(':');
    if (colonIndex === -1) return { type: 'other', value: trimmed, raw: line };

    const directive = trimmed.slice(0, colonIndex).toLowerCase().trim();
    const value = trimmed.slice(colonIndex + 1).trim();

    if (directive === 'user-agent') return { type: 'user-agent', directive, value, raw: line };
    if (directive === 'allow') return { type: 'allow', directive, value, raw: line };
    if (directive === 'disallow') return { type: 'disallow', directive, value, raw: line };
    if (directive === 'sitemap') return { type: 'sitemap', directive, value, raw: line };
    if (directive === 'crawl-delay') return { type: 'crawl-delay', directive, value, raw: line };
    return { type: 'other', directive, value, raw: line };
  });
};

const RobotsViewerToolComponent = ({
  data,
  onRefresh
}: {
  data: RobotsViewerData | undefined;
  onRefresh: () => Promise<void>;
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const [viewMode, setViewMode] = useState<'parsed' | 'raw'>('parsed');
  const content = data?.content ?? '';

  const parsedLines = useMemo(() => parseRobotsTxt(content), [content]);
  const stats = useMemo(() => {
    const userAgents = parsedLines.filter((l) => l.type === 'user-agent').length;
    const allows = parsedLines.filter((l) => l.type === 'allow').length;
    const disallows = parsedLines.filter((l) => l.type === 'disallow').length;
    const sitemaps = parsedLines.filter((l) => l.type === 'sitemap').length;
    return { userAgents, allows, disallows, sitemaps };
  }, [parsedLines]);

  const handleRefresh = async () => {
    setIsLoading(true);
    await onRefresh();
    setIsLoading(false);
  };

  const handleSavePlainText = () => {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `robots-${new URL(data?.url ?? window.location.href).hostname}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleSaveJSON = () => {
    const exportData = {
      url: data?.url,
      fetchedAt: data?.updatedAt ? new Date(data.updatedAt).toISOString() : null,
      rules: parsedLines
        .filter((l) => l.type !== 'comment' && l.type !== 'other' && l.value)
        .map((l) => ({ type: l.type, value: l.value }))
    };
    const json = JSON.stringify(exportData, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `robots-${new URL(data?.url ?? window.location.href).hostname}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getLineIcon = (type: ParsedLine['type']) => {
    switch (type) {
      case 'user-agent': return '🤖';
      case 'allow': return '✓';
      case 'disallow': return '✗';
      case 'sitemap': return '🗺';
      case 'crawl-delay': return '⏱';
      case 'comment': return '#';
      default: return '·';
    }
  };

  const getLineStyle = (type: ParsedLine['type']) => {
    switch (type) {
      case 'user-agent': return 'border-blue-500/30 bg-blue-500/10 text-blue-300';
      case 'allow': return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300';
      case 'disallow': return 'border-rose-500/30 bg-rose-500/10 text-rose-300';
      case 'sitemap': return 'border-amber-500/30 bg-amber-500/10 text-amber-300';
      case 'crawl-delay': return 'border-purple-500/30 bg-purple-500/10 text-purple-300';
      case 'comment': return 'border-slate-700 bg-slate-800/50 text-slate-500 italic';
      default: return 'border-slate-700 bg-slate-800/30 text-slate-400';
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-2">
        <div className="text-xs text-slate-200">Robots.txt Viewer</div>
        <button
          type="button"
          onClick={handleRefresh}
          disabled={isLoading}
          className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          {isLoading ? 'Loading...' : 'Fetch'}
        </button>
      </div>

      <div className="text-[10px] text-slate-500 mb-2 truncate">
        {data?.url ?? 'Click Fetch to load robots.txt'}
      </div>

      {data?.error ? (
        <div className="rounded border border-rose-500/30 bg-rose-500/10 px-2 py-1 text-[11px] text-rose-200 mb-2">
          {data.error}
        </div>
      ) : null}

      {content && (
        <>
          <div className="flex gap-2 mb-2 text-[9px] text-slate-500">
            <span>🤖 {stats.userAgents}</span>
            <span>✓ {stats.allows}</span>
            <span>✗ {stats.disallows}</span>
            <span>🗺 {stats.sitemaps}</span>
          </div>

          <div className="flex gap-1 mb-2">
            <button
              type="button"
              onClick={() => setViewMode('parsed')}
              className={`flex-1 rounded px-2 py-1 text-[10px] border transition-colors ${
                viewMode === 'parsed'
                  ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400'
              }`}
            >
              Parsed
            </button>
            <button
              type="button"
              onClick={() => setViewMode('raw')}
              className={`flex-1 rounded px-2 py-1 text-[10px] border transition-colors ${
                viewMode === 'raw'
                  ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400'
              }`}
            >
              Raw
            </button>
          </div>
        </>
      )}

      <div className="flex-1 overflow-y-auto min-h-0 mb-2">
        {!content ? (
          <div className="text-[11px] text-slate-500 text-center py-4">
            No robots.txt loaded yet.
          </div>
        ) : viewMode === 'raw' ? (
          <pre className="text-[10px] text-slate-300 font-mono whitespace-pre-wrap break-all bg-slate-800/50 rounded p-2 border border-slate-700">
            {content}
          </pre>
        ) : (
          <div className="space-y-1">
            {parsedLines.filter((l) => l.value || l.type === 'comment').map((line, idx) => (
              <div
                key={idx}
                className={`rounded border px-2 py-1 text-[10px] ${getLineStyle(line.type)}`}
              >
                <span className="mr-2">{getLineIcon(line.type)}</span>
                {line.directive && <span className="text-slate-400 mr-1">{line.directive}:</span>}
                <span className="break-all">{line.value}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {content && (
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
      )}
    </div>
  );
};
export class RobotsViewerTool {
  static Component = RobotsViewerToolComponent;
}
