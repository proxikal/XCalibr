import React, { useState, useMemo } from 'react';
import type {
  TechFingerprintData,
  TechFinding,
  TechConfidence,
  TechSignal
} from './tool-types';

type CategoryFilter = TechFinding['category'] | 'all';

const TechFingerprintToolComponent = ({
  data,
  onChange,
  onRefresh
}: {
  data: TechFingerprintData | undefined;
  onChange: (next: TechFingerprintData) => void;
  onRefresh: () => Promise<void>;
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>('all');
  const [copiedSignal, setCopiedSignal] = useState<string | null>(null);

  const findings = data?.findings ?? [];
  const expandedFinding = data?.expandedFinding;

  const handleRefresh = async () => {
    setIsLoading(true);
    await onRefresh();
    setIsLoading(false);
  };

  const filteredFindings = useMemo(() => {
    if (categoryFilter === 'all') return findings;
    return findings.filter(f => f.category === categoryFilter);
  }, [findings, categoryFilter]);

  const categoryStats = useMemo(() => {
    const stats: Record<string, number> = {};
    findings.forEach(f => {
      stats[f.category] = (stats[f.category] || 0) + 1;
    });
    return stats;
  }, [findings]);

  const confidenceStats = useMemo(() => {
    const high = findings.filter(f => f.confidence === 'high').length;
    const medium = findings.filter(f => f.confidence === 'medium').length;
    const low = findings.filter(f => f.confidence === 'low').length;
    return { high, medium, low };
  }, [findings]);

  const toggleExpanded = (label: string) => {
    onChange({
      ...data,
      expandedFinding: expandedFinding === label ? undefined : label
    });
  };

  const handleCopySignal = (signal: TechSignal, idx: number) => {
    const textToCopy = signal.source
      ? `${signal.evidence}\n${signal.source}`
      : signal.evidence;
    navigator.clipboard.writeText(textToCopy);
    setCopiedSignal(`${idx}`);
    setTimeout(() => setCopiedSignal(null), 1500);
  };

  const handleCopyAllSignals = (finding: TechFinding) => {
    const text = finding.signals
      .map(s => s.source ? `[${s.type}] ${s.evidence}\n  Source: ${s.source}` : `[${s.type}] ${s.evidence}`)
      .join('\n\n');
    const fullText = `${finding.value}${finding.version ? ` v${finding.version}` : ''}\nCategory: ${finding.category}\nConfidence: ${finding.confidence}\n\nSignals:\n${text}`;
    navigator.clipboard.writeText(fullText);
    setCopiedSignal('all');
    setTimeout(() => setCopiedSignal(null), 1500);
  };

  const getConfidenceStyle = (confidence: TechConfidence) => {
    switch (confidence) {
      case 'high': return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
      case 'medium': return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'low': return 'bg-slate-600/20 text-slate-400 border-slate-600/40';
    }
  };

  const getConfidenceMeter = (confidence: TechConfidence) => {
    const bars = confidence === 'high' ? 3 : confidence === 'medium' ? 2 : 1;
    return (
      <div className="flex gap-0.5" title={`${confidence} confidence`}>
        {[1, 2, 3].map(i => (
          <div
            key={i}
            className={`w-1.5 h-3 rounded-sm ${
              i <= bars
                ? confidence === 'high' ? 'bg-emerald-400' : confidence === 'medium' ? 'bg-amber-400' : 'bg-slate-500'
                : 'bg-slate-700'
            }`}
          />
        ))}
      </div>
    );
  };

  const getCategoryStyle = (category: TechFinding['category']) => {
    switch (category) {
      case 'framework': return 'border-blue-500/40 bg-blue-500/10';
      case 'library': return 'border-purple-500/40 bg-purple-500/10';
      case 'server': return 'border-emerald-500/40 bg-emerald-500/10';
      case 'cdn': return 'border-cyan-500/40 bg-cyan-500/10';
      case 'cms': return 'border-amber-500/40 bg-amber-500/10';
      case 'analytics': return 'border-pink-500/40 bg-pink-500/10';
      default: return 'border-slate-700 bg-slate-800/50';
    }
  };

  const getCategoryIcon = (category: TechFinding['category']) => {
    switch (category) {
      case 'framework': return '⚛';
      case 'library': return '📦';
      case 'server': return '🖥';
      case 'cdn': return '🌐';
      case 'cms': return '📝';
      case 'analytics': return '📊';
      default: return '•';
    }
  };

  const getSignalIcon = (type: TechSignal['type']) => {
    switch (type) {
      case 'meta': return '🏷';
      case 'script': return '📜';
      case 'header': return '📋';
      case 'global': return '🌍';
      case 'selector': return '🎯';
      case 'cookie': return '🍪';
      case 'favicon': return '🖼';
      case 'comment': return '💬';
      default: return '•';
    }
  };

  const handleExport = () => {
    const exportData = {
      url: data?.url,
      findings: findings.map(f => ({
        name: f.label,
        value: f.value,
        version: f.version,
        confidence: f.confidence,
        category: f.category,
        signals: f.signals.map(s => ({
          type: s.type,
          evidence: s.evidence,
          source: s.source
        }))
      })),
      scannedAt: data?.updatedAt ? new Date(data.updatedAt).toISOString() : null
    };
    const json = JSON.stringify(exportData, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `fingerprint-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-full p-1">
      {/* Header */}
      <div className="flex items-center justify-between mb-3 flex-shrink-0">
        <div className="flex-1 min-w-0">
          <div className="text-sm text-slate-200 font-medium">Tech Fingerprint</div>
          <div className="text-[10px] text-slate-500 truncate" title={data?.url}>
            {data?.url ?? 'No URL scanned'}
          </div>
        </div>
        <div className="flex gap-2 flex-shrink-0">
          <button
            type="button"
            onClick={handleExport}
            disabled={findings.length === 0}
            className="rounded bg-slate-800 px-3 py-1.5 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors disabled:opacity-50"
          >
            Export
          </button>
          <button
            type="button"
            onClick={handleRefresh}
            disabled={isLoading}
            className="rounded bg-blue-600 px-3 py-1.5 text-[10px] text-white hover:bg-blue-500 transition-colors disabled:opacity-50"
          >
            {isLoading ? 'Scanning...' : 'Scan'}
          </button>
        </div>
      </div>

      {/* Stats bar */}
      {findings.length > 0 && (
        <div className="flex items-center gap-4 mb-3 pb-3 border-b border-slate-700 flex-shrink-0">
          <div className="flex items-center gap-3 text-[10px]">
            <span className="flex items-center gap-1 text-emerald-400" title="High confidence">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              {confidenceStats.high} high
            </span>
            <span className="flex items-center gap-1 text-amber-400" title="Medium confidence">
              <span className="w-2 h-2 rounded-full bg-amber-400"></span>
              {confidenceStats.medium} med
            </span>
            <span className="flex items-center gap-1 text-slate-500" title="Low confidence">
              <span className="w-2 h-2 rounded-full bg-slate-500"></span>
              {confidenceStats.low} low
            </span>
          </div>
          <span className="text-[10px] text-slate-600 ml-auto">{findings.length} detected</span>
        </div>
      )}

      {/* Category filters */}
      {findings.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mb-3 flex-shrink-0">
          <button
            type="button"
            onClick={() => setCategoryFilter('all')}
            className={`rounded px-2 py-1 text-[10px] border transition-colors ${
              categoryFilter === 'all'
                ? 'bg-blue-500/20 border-blue-500/50 text-blue-300'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600'
            }`}
          >
            All ({findings.length})
          </button>
          {Object.entries(categoryStats).map(([cat, count]) => (
            <button
              key={cat}
              type="button"
              onClick={() => setCategoryFilter(cat as CategoryFilter)}
              className={`rounded px-2 py-1 text-[10px] border transition-colors ${
                categoryFilter === cat
                  ? 'bg-blue-500/20 border-blue-500/50 text-blue-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600'
              }`}
            >
              {getCategoryIcon(cat as TechFinding['category'])} {cat} ({count})
            </button>
          ))}
        </div>
      )}

      {/* Findings list */}
      <div className="flex-1 overflow-y-auto space-y-2 min-h-0">
        {filteredFindings.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center py-8">
            <div className="text-3xl mb-2 opacity-50">🔍</div>
            <div className="text-[11px] text-slate-500">
              {findings.length === 0 ? 'No technologies detected yet.' : 'No findings in this category.'}
            </div>
            {findings.length === 0 && (
              <div className="text-[10px] text-slate-600 mt-1">Click Scan to analyze this page.</div>
            )}
          </div>
        ) : (
          filteredFindings.map((finding) => (
            <div
              key={finding.label + finding.value}
              className={`rounded-lg border p-3 transition-colors ${getCategoryStyle(finding.category)}`}
            >
              {/* Finding header */}
              <div
                className="flex items-center gap-3 cursor-pointer"
                onClick={() => toggleExpanded(finding.label + finding.value)}
              >
                <span className="text-base">{getCategoryIcon(finding.category)}</span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-semibold text-slate-200">
                      {finding.value}
                    </span>
                    {finding.version && (
                      <span className="text-[10px] text-slate-400 font-mono bg-slate-800/50 px-1.5 py-0.5 rounded">
                        v{finding.version}
                      </span>
                    )}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">{finding.label}</div>
                </div>
                <div className="flex items-center gap-3 flex-shrink-0">
                  {getConfidenceMeter(finding.confidence)}
                  <span className="text-[10px] text-slate-600">
                    {expandedFinding === finding.label + finding.value ? '▼' : '▶'}
                  </span>
                </div>
              </div>

              {/* Expanded signals */}
              {expandedFinding === finding.label + finding.value && (
                <div className="mt-3 pt-3 border-t border-current/20">
                  <div className="flex items-center justify-between mb-2">
                    <div className="text-[9px] uppercase tracking-widest text-slate-500">
                      Signals ({finding.signals.length})
                    </div>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleCopyAllSignals(finding);
                      }}
                      className="text-[9px] text-slate-500 hover:text-slate-300 transition-colors px-2 py-0.5 rounded bg-slate-800/50 hover:bg-slate-800"
                    >
                      {copiedSignal === 'all' ? '✓ Copied!' : '⧉ Copy all'}
                    </button>
                  </div>
                  <div className="space-y-2">
                    {finding.signals.map((signal, idx) => (
                      <div
                        key={idx}
                        onClick={(e) => {
                          e.stopPropagation();
                          handleCopySignal(signal, idx);
                        }}
                        className="flex items-start gap-2 text-[10px] bg-slate-900/40 rounded-md px-2.5 py-2 cursor-pointer hover:bg-slate-900/60 transition-colors group"
                        title="Click to copy"
                      >
                        <span className="flex-shrink-0 mt-0.5" title={signal.type}>
                          {getSignalIcon(signal.type)}
                        </span>
                        <div className="flex-1 min-w-0">
                          <div className="text-slate-300 break-all font-mono text-[9px] leading-relaxed">
                            {signal.evidence}
                          </div>
                          {signal.source && (
                            <div className="text-slate-600 truncate mt-1 text-[9px]" title={signal.source}>
                              📍 {signal.source}
                            </div>
                          )}
                        </div>
                        <span className="text-[9px] text-slate-600 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0">
                          {copiedSignal === `${idx}` ? '✓' : '⧉'}
                        </span>
                      </div>
                    ))}
                  </div>
                  <div className={`mt-3 inline-block rounded px-2 py-1 text-[9px] uppercase tracking-wider border ${getConfidenceStyle(finding.confidence)}`}>
                    {finding.confidence} confidence
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Footer */}
      {data?.updatedAt && (
        <div className="text-[10px] text-slate-600 mt-3 pt-2 border-t border-slate-800 flex-shrink-0">
          Last scan: {new Date(data.updatedAt).toLocaleTimeString()}
        </div>
      )}
    </div>
  );
};
export class TechFingerprintTool {
  static Component = TechFingerprintToolComponent;
}
