import React from 'react';
import type { WhoisLookupData } from './tool-types';

const WhoisLookupToolComponent = ({
  data,
  onChange,
  onLookup
}: {
  data: WhoisLookupData | undefined;
  onChange: (next: WhoisLookupData) => void;
  onLookup: (domain: string) => Promise<void>;
}) => {
  const domain = data?.domain ?? '';
  const result = data?.result;
  const error = data?.error;
  const loading = data?.loading ?? false;

  const handleLookup = async () => {
    if (!domain.trim()) return;
    onChange({ ...data, loading: true, error: undefined, result: undefined });
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
        Enter a domain name to fetch WHOIS/RDAP data
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

      {result && (
        <div className="space-y-2">
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="bg-slate-800/50 rounded px-2 py-1.5 border border-slate-700">
              <span className="text-slate-500">Domain:</span>
              <span className="text-slate-200 ml-1">{result.domain}</span>
            </div>
            <div className="bg-slate-800/50 rounded px-2 py-1.5 border border-slate-700">
              <span className="text-slate-500">Status:</span>
              <span className="text-emerald-400 ml-1">{result.status}</span>
            </div>
          </div>

          {result.registrar && (
            <div className="bg-slate-800/50 rounded px-2 py-1.5 border border-slate-700 text-xs">
              <span className="text-slate-500">Registrar:</span>
              <span className="text-slate-200 ml-1">{result.registrar}</span>
            </div>
          )}

          {result.registrant && (
            <div className="bg-slate-800/50 rounded px-2 py-1.5 border border-slate-700 text-xs">
              <span className="text-slate-500">Registrant:</span>
              <span className="text-slate-200 ml-1">{result.registrant}</span>
            </div>
          )}

          <div className="grid grid-cols-3 gap-2 text-xs">
            {result.createdDate && (
              <div className="bg-slate-800/50 rounded px-2 py-1.5 border border-slate-700">
                <div className="text-slate-500">Created</div>
                <div className="text-slate-200">{result.createdDate}</div>
              </div>
            )}
            {result.expiresDate && (
              <div className="bg-slate-800/50 rounded px-2 py-1.5 border border-slate-700">
                <div className="text-slate-500">Expires</div>
                <div className="text-amber-400">{result.expiresDate}</div>
              </div>
            )}
            {result.updatedDate && (
              <div className="bg-slate-800/50 rounded px-2 py-1.5 border border-slate-700">
                <div className="text-slate-500">Updated</div>
                <div className="text-slate-200">{result.updatedDate}</div>
              </div>
            )}
          </div>

          {result.nameservers && result.nameservers.length > 0 && (
            <div className="bg-slate-800/50 rounded px-2 py-1.5 border border-slate-700 text-xs">
              <div className="text-slate-500 mb-1">Nameservers:</div>
              <div className="space-y-0.5">
                {result.nameservers.map((ns, i) => (
                  <div key={i} className="text-cyan-400 font-mono text-[11px]">
                    {ns}
                  </div>
                ))}
              </div>
            </div>
          )}

          <button
            type="button"
            onClick={() => {
              const text = [
                `Domain: ${result.domain}`,
                `Status: ${result.status}`,
                result.registrar ? `Registrar: ${result.registrar}` : '',
                result.registrant ? `Registrant: ${result.registrant}` : '',
                result.createdDate ? `Created: ${result.createdDate}` : '',
                result.expiresDate ? `Expires: ${result.expiresDate}` : '',
                result.updatedDate ? `Updated: ${result.updatedDate}` : '',
                result.nameservers?.length ? `Nameservers:\n  ${result.nameservers.join('\n  ')}` : ''
              ].filter(Boolean).join('\n');
              navigator.clipboard.writeText(text);
            }}
            className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
          >
            Copy Results
          </button>
        </div>
      )}

      {!result && !error && !loading && (
        <div className="text-xs text-slate-500 text-center py-4">
          Enter a domain and click Lookup to fetch WHOIS data
        </div>
      )}
    </div>
  );
};

export class WhoisLookupTool {
  static Component = WhoisLookupToolComponent;
}
