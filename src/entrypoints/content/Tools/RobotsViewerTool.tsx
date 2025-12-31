import React, { useState, useMemo } from 'react';
import type {
  RobotsViewerData,
  RobotsUserAgentGroup
} from './tool-types';

const HIGH_RISK_PATTERNS = [
  /admin/i,
  /backup/i,
  /\.git/i,
  /\.svn/i,
  /\.env/i,
  /config/i,
  /database/i,
  /db\//i,
  /debug/i,
  /dump/i,
  /export/i,
  /internal/i,
  /log/i,
  /password/i,
  /private/i,
  /secret/i,
  /staging/i,
  /test/i,
  /upload/i,
  /wp-admin/i,
  /phpinfo/i,
  /phpmyadmin/i,
  /cpanel/i,
  /\.bak/i,
  /\.sql/i,
  /\.old/i,
  /\.zip/i,
  /\.tar/i,
  /api\/v/i,
  /graphql/i,
];

const isHighRiskPath = (path: string): boolean => {
  return HIGH_RISK_PATTERNS.some(pattern => pattern.test(path));
};

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

const groupByUserAgent = (parsedLines: ParsedLine[]): RobotsUserAgentGroup[] => {
  const groups: RobotsUserAgentGroup[] = [];
  let currentGroup: RobotsUserAgentGroup | null = null;

  parsedLines.forEach(line => {
    if (line.type === 'user-agent') {
      if (currentGroup) {
        groups.push(currentGroup);
      }
      currentGroup = {
        userAgent: line.value || '*',
        rules: [],
        crawlDelay: undefined
      };
    } else if (currentGroup) {
      if (line.type === 'allow' || line.type === 'disallow') {
        currentGroup.rules.push({
          type: line.type,
          path: line.value,
          isHighRisk: isHighRiskPath(line.value)
        });
      } else if (line.type === 'crawl-delay') {
        currentGroup.crawlDelay = parseInt(line.value, 10) || undefined;
      }
    }
  });

  if (currentGroup) {
    groups.push(currentGroup);
  }

  return groups;
};

const RobotsViewerToolComponent = ({
  data,
  onChange,
  onRefresh
}: {
  data: RobotsViewerData | undefined;
  onChange: (next: RobotsViewerData) => void;
  onRefresh: () => Promise<void>;
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const [viewMode, setViewMode] = useState<'grouped' | 'raw'>('grouped');
  const content = data?.content ?? '';
  const selectedUserAgent = data?.selectedUserAgent;

  const parsedLines = useMemo(() => parseRobotsTxt(content), [content]);
  const userAgentGroups = useMemo(() => groupByUserAgent(parsedLines), [parsedLines]);
  const sitemaps = useMemo(() =>
    parsedLines.filter(l => l.type === 'sitemap').map(l => l.value),
    [parsedLines]
  );

  const highRiskPaths = useMemo(() => {
    const paths: string[] = [];
    userAgentGroups.forEach(group => {
      group.rules.forEach(rule => {
        if (rule.isHighRisk && !paths.includes(rule.path)) {
          paths.push(rule.path);
        }
      });
    });
    return paths;
  }, [userAgentGroups]);

  const stats = useMemo(() => {
    const userAgents = userAgentGroups.length;
    const allows = parsedLines.filter((l) => l.type === 'allow').length;
    const disallows = parsedLines.filter((l) => l.type === 'disallow').length;
    return { userAgents, allows, disallows, sitemaps: sitemaps.length, highRisk: highRiskPaths.length };
  }, [parsedLines, userAgentGroups, sitemaps, highRiskPaths]);

  const selectedGroup = useMemo(() =>
    userAgentGroups.find(g => g.userAgent === selectedUserAgent) || userAgentGroups[0],
    [userAgentGroups, selectedUserAgent]
  );

  const handleRefresh = async () => {
    setIsLoading(true);
    await onRefresh();
    setIsLoading(false);
  };

  const handleSelectUserAgent = (ua: string) => {
    onChange({ ...data, selectedUserAgent: ua });
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
      httpStatus: data?.httpStatus,
      lastModified: data?.lastModified,
      cacheControl: data?.cacheControl,
      fetchedAt: data?.updatedAt ? new Date(data.updatedAt).toISOString() : null,
      sitemaps,
      userAgentGroups: userAgentGroups.map(g => ({
        userAgent: g.userAgent,
        crawlDelay: g.crawlDelay,
        rules: g.rules.map(r => ({
          type: r.type,
          path: r.path,
          isHighRisk: r.isHighRisk
        }))
      })),
      highRiskPaths
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

  return (
    <div className="flex flex-col h-full p-1">
      {/* Header */}
      <div className="flex items-center justify-between mb-3 flex-shrink-0">
        <div className="text-sm text-slate-200 font-medium">Robots.txt Viewer</div>
        <button
          type="button"
          onClick={handleRefresh}
          disabled={isLoading}
          className="rounded bg-blue-600 px-3 py-1.5 text-[11px] text-white hover:bg-blue-500 transition-colors disabled:opacity-50"
        >
          {isLoading ? 'Loading...' : 'Fetch'}
        </button>
      </div>

      {/* URL display */}
      <div className="text-[11px] text-slate-500 mb-2 truncate flex-shrink-0" title={data?.url}>
        {data?.url ?? 'Click Fetch to load robots.txt'}
      </div>

      {/* HTTP info */}
      {data?.httpStatus && (
        <div className="text-[11px] text-slate-500 mb-2 flex gap-4 flex-shrink-0">
          <span>Status: <span className={data.httpStatus === 200 ? 'text-emerald-400' : 'text-amber-400'}>{data.httpStatus}</span></span>
          {data.lastModified && <span>Modified: {data.lastModified}</span>}
          {data.cacheControl && <span title={data.cacheControl}>Cached</span>}
        </div>
      )}

      {data?.redirectedFrom && (
        <div className="text-[11px] text-blue-400 mb-2 truncate flex-shrink-0">
          Redirected from: {data.redirectedFrom}
        </div>
      )}

      {data?.error && (
        <div className="rounded border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-[12px] text-rose-200 mb-3 flex-shrink-0">
          {data.error}
        </div>
      )}

      {/* Stats bar */}
      {content && (
        <div className="flex items-center gap-4 mb-3 pb-3 border-b border-slate-700 flex-shrink-0">
          <div className="flex items-center gap-4 text-[12px]">
            <span className="flex items-center gap-1.5">
              <span className="text-base">🤖</span>
              <span className="text-slate-400">{stats.userAgents}</span>
            </span>
            <span className="flex items-center gap-1.5 text-emerald-400">
              <span className="text-base">✓</span>
              <span>{stats.allows}</span>
            </span>
            <span className="flex items-center gap-1.5 text-rose-400">
              <span className="text-base">✗</span>
              <span>{stats.disallows}</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="text-base">🗺</span>
              <span className="text-slate-400">{stats.sitemaps}</span>
            </span>
            {stats.highRisk > 0 && (
              <span className="flex items-center gap-1.5 text-amber-400" title="High-risk paths detected">
                <span className="text-base">⚠</span>
                <span>{stats.highRisk}</span>
              </span>
            )}
          </div>
        </div>
      )}

      {/* View mode tabs */}
      {content && (
        <div className="flex gap-2 mb-3 flex-shrink-0">
          <button
            type="button"
            onClick={() => setViewMode('grouped')}
            className={`flex-1 rounded px-3 py-1.5 text-[11px] border transition-colors ${
              viewMode === 'grouped'
                ? 'bg-blue-500/20 border-blue-500/50 text-blue-300'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600'
            }`}
          >
            Grouped View
          </button>
          <button
            type="button"
            onClick={() => setViewMode('raw')}
            className={`flex-1 rounded px-3 py-1.5 text-[11px] border transition-colors ${
              viewMode === 'raw'
                ? 'bg-blue-500/20 border-blue-500/50 text-blue-300'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600'
            }`}
          >
            Raw View
          </button>
        </div>
      )}

      {/* Main content area */}
      <div className="flex-1 overflow-hidden min-h-0 mb-3">
        {!content ? (
          <div className="flex flex-col items-center justify-center h-full text-center py-8">
            <div className="text-4xl mb-3 opacity-50">🤖</div>
            <div className="text-[12px] text-slate-500">No robots.txt loaded yet.</div>
            <div className="text-[11px] text-slate-600 mt-1">Click Fetch to load the file.</div>
          </div>
        ) : viewMode === 'raw' ? (
          <pre className="h-full overflow-y-auto text-[11px] text-slate-300 font-mono whitespace-pre-wrap break-all bg-slate-800/50 rounded-lg p-3 border border-slate-700">
            {content}
          </pre>
        ) : (
          <div className="flex h-full gap-3">
            {/* User-Agent Sidebar */}
            <div className="w-36 flex-shrink-0 overflow-y-auto border-r border-slate-700 pr-3">
              <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-2 font-medium">User Agents</div>
              <div className="space-y-1.5">
                {userAgentGroups.map((group, idx) => (
                  <button
                    key={`${group.userAgent}-${idx}`}
                    type="button"
                    onClick={() => handleSelectUserAgent(group.userAgent)}
                    className={`w-full text-left rounded-md px-2 py-1.5 text-[11px] border transition-colors ${
                      selectedGroup?.userAgent === group.userAgent
                        ? 'bg-blue-500/20 border-blue-500/50 text-blue-300'
                        : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600'
                    }`}
                    title={group.userAgent}
                  >
                    <div className="flex items-center gap-1.5">
                      <span className="text-sm">🤖</span>
                      <span className="truncate flex-1">{group.userAgent}</span>
                    </div>
                    <div className="text-[10px] text-slate-600 mt-0.5 ml-5">
                      {group.rules.length} rules
                    </div>
                  </button>
                ))}
              </div>

              {sitemaps.length > 0 && (
                <>
                  <div className="text-[10px] uppercase tracking-widest text-slate-500 mt-4 mb-2 font-medium">Sitemaps</div>
                  <div className="space-y-1.5">
                    {sitemaps.map((sitemap, idx) => (
                      <a
                        key={idx}
                        href={sitemap}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1.5 w-full text-left rounded-md px-2 py-1.5 text-[11px] bg-amber-500/10 border border-amber-500/30 text-amber-300 hover:bg-amber-500/20 transition-colors"
                        title={sitemap}
                      >
                        <span className="text-sm">🗺</span>
                        <span className="truncate">{sitemap.split('/').pop() || sitemap}</span>
                      </a>
                    ))}
                  </div>
                </>
              )}
            </div>

            {/* Rules Panel */}
            <div className="flex-1 overflow-y-auto">
              {selectedGroup ? (
                <div className="space-y-2">
                  <div className="flex items-center gap-3 mb-3 pb-2 border-b border-slate-700/50">
                    <span className="text-lg">🤖</span>
                    <span className="text-[13px] text-slate-200 font-medium">{selectedGroup.userAgent}</span>
                    {selectedGroup.crawlDelay && (
                      <span className="text-[11px] text-purple-300 bg-purple-500/20 rounded-md px-2 py-1 flex items-center gap-1">
                        <span className="text-sm">⏱</span>
                        {selectedGroup.crawlDelay}s delay
                      </span>
                    )}
                  </div>
                  {selectedGroup.rules.length === 0 ? (
                    <div className="text-[12px] text-slate-500 text-center py-4">No rules defined for this user-agent</div>
                  ) : (
                    selectedGroup.rules.map((rule, idx) => (
                      <div
                        key={idx}
                        className={`rounded-md border px-3 py-2 ${
                          rule.isHighRisk
                            ? 'border-amber-500/50 bg-amber-500/10'
                            : rule.type === 'allow'
                              ? 'border-emerald-500/30 bg-emerald-500/10'
                              : 'border-rose-500/30 bg-rose-500/10'
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          <span className={`text-base ${rule.type === 'allow' ? 'text-emerald-400' : 'text-rose-400'}`}>
                            {getLineIcon(rule.type)}
                          </span>
                          <span className={`font-mono text-[12px] break-all flex-1 ${
                            rule.isHighRisk ? 'text-amber-300' : rule.type === 'allow' ? 'text-emerald-300' : 'text-rose-300'
                          }`}>
                            {rule.path || '/'}
                          </span>
                          {rule.isHighRisk && (
                            <span className="text-[9px] bg-amber-500/30 text-amber-200 rounded px-1.5 py-0.5 flex-shrink-0 uppercase tracking-wide font-medium">
                              High Risk
                            </span>
                          )}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              ) : (
                <div className="text-[12px] text-slate-500 text-center py-8">
                  Select a user-agent to view rules
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* High risk warning */}
      {highRiskPaths.length > 0 && viewMode === 'grouped' && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 mb-3 flex-shrink-0">
          <div className="flex items-center gap-2 text-[11px] uppercase tracking-widest text-amber-300 mb-2 font-medium">
            <span className="text-base">⚠</span>
            High-Risk Disallowed Paths
          </div>
          <div className="text-[11px] text-amber-200/80 space-y-1">
            {highRiskPaths.slice(0, 5).map((path, idx) => (
              <div key={idx} className="font-mono truncate" title={path}>{path}</div>
            ))}
            {highRiskPaths.length > 5 && (
              <div className="text-amber-400/60">+{highRiskPaths.length - 5} more...</div>
            )}
          </div>
        </div>
      )}

      {/* Export buttons */}
      {content && (
        <div className="flex gap-2 flex-shrink-0">
          <button
            type="button"
            onClick={handleSavePlainText}
            className="flex-1 rounded-md bg-slate-800 px-3 py-2 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Save as Text
          </button>
          <button
            type="button"
            onClick={handleSaveJSON}
            className="flex-1 rounded-md bg-slate-800 px-3 py-2 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
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
