import React from 'react';
import type { ReverseIpLookupData } from './tool-types';

const ReverseIpLookupToolComponent = ({
  data,
  onChange,
  onLookup
}: {
  data: ReverseIpLookupData | undefined;
  onChange: (next: ReverseIpLookupData) => void;
  onLookup: (ip: string) => Promise<void>;
}) => {
  const ip = data?.ip ?? '';
  const domains = data?.domains ?? [];
  const search = data?.search ?? '';
  const error = data?.error;
  const loading = data?.loading ?? false;

  const filteredDomains = search.trim()
    ? domains.filter(d => d.toLowerCase().includes(search.toLowerCase()))
    : domains;

  const handleLookup = async () => {
    if (!ip.trim()) return;
    onChange({ ...data, loading: true, error: undefined, domains: [] });
    await onLookup(ip.trim());
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleLookup();
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-400">
        Enter an IP address to find domains hosted on it
      </div>

      <div className="flex gap-2">
        <input
          type="text"
          value={ip}
          onChange={(e) => onChange({ ...data, ip: e.target.value })}
          onKeyDown={handleKeyDown}
          className="flex-1 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
          placeholder="Enter IP address (e.g., 93.184.216.34)"
        />
        <button
          type="button"
          onClick={handleLookup}
          disabled={loading || !ip.trim()}
          className="rounded bg-blue-600 px-3 py-1.5 text-xs text-white hover:bg-blue-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? 'Loading...' : 'Lookup'}
        </button>
      </div>

      {error && (
        <div className="text-red-400 text-xs bg-red-500/10 border border-red-500/30 rounded px-2 py-1.5">
          {error}
        </div>
      )}

      {domains.length > 0 && (
        <>
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={search}
              onChange={(e) => onChange({ ...data, search: e.target.value })}
              className="flex-1 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
              placeholder="Filter domains..."
            />
            <span className="text-[10px] text-slate-500">
              {filteredDomains.length} of {domains.length} domain{domains.length !== 1 ? 's' : ''}
            </span>
          </div>

          <div className="space-y-1 max-h-64 overflow-y-auto">
            {filteredDomains.map((domain, i) => (
              <div
                key={i}
                className="bg-slate-800/50 rounded px-2 py-1 border border-slate-700 text-xs font-mono text-cyan-400 flex items-center justify-between group"
              >
                <span className="truncate">{domain}</span>
                <a
                  href={`https://${domain}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-slate-500 hover:text-blue-400 opacity-0 group-hover:opacity-100 transition-opacity"
                  title="Open in new tab"
                >
                  ↗
                </a>
              </div>
            ))}
          </div>

          <button
            type="button"
            onClick={() => {
              const text = filteredDomains.join('\n');
              navigator.clipboard.writeText(text);
            }}
            className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
          >
            Copy Domains ({filteredDomains.length})
          </button>
        </>
      )}

      {!domains.length && !error && !loading && (
        <div className="text-xs text-slate-500 text-center py-4">
          Enter an IP address and click Lookup to find hosted domains
        </div>
      )}
    </div>
  );
};

export class ReverseIpLookupTool {
  static Component = ReverseIpLookupToolComponent;
}
