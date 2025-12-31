import React from 'react';
import type { DnsRecordViewerData } from './tool-types';

type DnsRecordType = 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT' | 'NS' | 'SOA';
type FilterType = DnsRecordType | 'ALL';

const RECORD_TYPE_COLORS: Record<DnsRecordType, string> = {
  A: 'text-emerald-400',
  AAAA: 'text-cyan-400',
  CNAME: 'text-amber-400',
  MX: 'text-purple-400',
  TXT: 'text-slate-400',
  NS: 'text-blue-400',
  SOA: 'text-rose-400'
};

const formatTtl = (ttl: number): string => {
  if (ttl >= 86400) {
    const days = Math.floor(ttl / 86400);
    return `${days}d`;
  }
  if (ttl >= 3600) {
    const hours = Math.floor(ttl / 3600);
    return `${hours}h`;
  }
  if (ttl >= 60) {
    const minutes = Math.floor(ttl / 60);
    return `${minutes}m`;
  }
  return `${ttl}s`;
};

const FILTER_OPTIONS: FilterType[] = ['ALL', 'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA'];

const DnsRecordViewerToolComponent = ({
  data,
  onChange,
  onLookup
}: {
  data: DnsRecordViewerData | undefined;
  onChange: (next: DnsRecordViewerData) => void;
  onLookup: (domain: string) => Promise<void>;
}) => {
  const domain = data?.domain ?? '';
  const records = data?.records ?? [];
  const filter = data?.filter ?? 'ALL';
  const error = data?.error;
  const loading = data?.loading ?? false;

  const filteredRecords = filter === 'ALL'
    ? records
    : records.filter(r => r.type === filter);

  const handleLookup = async () => {
    if (!domain.trim()) return;
    onChange({ ...data, loading: true, error: undefined, records: [] });
    await onLookup(domain.trim());
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleLookup();
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-400">
        Enter a domain to fetch DNS records
      </div>

      <div className="flex gap-2">
        <input
          type="text"
          value={domain}
          onChange={(e) => onChange({ ...data, domain: e.target.value })}
          onKeyDown={handleKeyDown}
          className="flex-1 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-blue-500"
          placeholder="Enter domain (e.g., example.com)"
        />
        <button
          type="button"
          onClick={handleLookup}
          disabled={loading || !domain.trim()}
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

      {records.length > 0 && (
        <>
          <div className="flex gap-1 flex-wrap">
            {FILTER_OPTIONS.map((opt) => (
              <button
                key={opt}
                type="button"
                onClick={() => onChange({ ...data, filter: opt })}
                className={`px-2 py-0.5 text-[10px] rounded transition-colors ${
                  filter === opt
                    ? 'bg-blue-600 text-white'
                    : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                }`}
              >
                {opt}
              </button>
            ))}
          </div>

          <div className="space-y-1 max-h-64 overflow-y-auto">
            {filteredRecords.map((record, i) => (
              <div
                key={i}
                className="bg-slate-800/50 rounded px-2 py-1.5 border border-slate-700 text-xs"
              >
                <div className="flex items-center gap-2">
                  <span className={`font-mono font-semibold ${RECORD_TYPE_COLORS[record.type as DnsRecordType] || 'text-slate-400'}`}>
                    {record.type}
                  </span>
                  <span className="text-slate-500 text-[10px]">{record.name}</span>
                  {record.ttl !== undefined && (
                    <span className="text-slate-600 text-[10px] ml-auto">
                      TTL: {formatTtl(record.ttl)}
                    </span>
                  )}
                </div>
                <div className="text-slate-300 font-mono text-[11px] mt-0.5 break-all">
                  {record.priority !== undefined && (
                    <span className="text-purple-400 mr-1">[{record.priority}]</span>
                  )}
                  {record.value}
                </div>
              </div>
            ))}
          </div>

          <div className="text-[10px] text-slate-500">
            Showing {filteredRecords.length} of {records.length} records
          </div>

          <button
            type="button"
            onClick={() => {
              const text = filteredRecords
                .map(r => `${r.type}\t${r.name}\t${r.value}${r.priority !== undefined ? `\t(priority: ${r.priority})` : ''}${r.ttl !== undefined ? `\tTTL: ${r.ttl}` : ''}`)
                .join('\n');
              navigator.clipboard.writeText(text);
            }}
            className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
          >
            Copy Records
          </button>
        </>
      )}

      {!records.length && !error && !loading && (
        <div className="text-xs text-slate-500 text-center py-4">
          Enter a domain and click Lookup to fetch DNS records
        </div>
      )}
    </div>
  );
};

export class DnsRecordViewerTool {
  static Component = DnsRecordViewerToolComponent;
}
