import React from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSearch, faExclamationTriangle, faCheckCircle, faCopy, faCheck } from '@fortawesome/free-solid-svg-icons';
import { useState } from 'react';

export type TakeoverResult = {
  subdomain: string;
  cname?: string;
  vulnerable: boolean;
  service?: string;
  fingerprint?: string;
  error?: string;
};

export type SubdomainTakeoverCheckerData = {
  subdomains?: string;
  results?: TakeoverResult[];
  isChecking?: boolean;
  checkedAt?: number;
};

type Props = {
  data: SubdomainTakeoverCheckerData | undefined;
  onChange: (data: SubdomainTakeoverCheckerData) => void;
};

// Known vulnerable CNAME fingerprints
const VULNERABLE_FINGERPRINTS: { service: string; cnames: string[]; fingerprints: string[] }[] = [
  {
    service: 'AWS S3',
    cnames: ['.s3.amazonaws.com', '.s3-website'],
    fingerprints: ['NoSuchBucket', 'The specified bucket does not exist']
  },
  {
    service: 'GitHub Pages',
    cnames: ['.github.io', '.githubusercontent.com'],
    fingerprints: ["There isn't a GitHub Pages site here", '404']
  },
  {
    service: 'Heroku',
    cnames: ['.herokuapp.com', '.herokussl.com'],
    fingerprints: ['No such app', 'herokucdn.com/error-pages']
  },
  {
    service: 'Shopify',
    cnames: ['.myshopify.com'],
    fingerprints: ['Sorry, this shop is currently unavailable']
  },
  {
    service: 'Tumblr',
    cnames: ['.tumblr.com'],
    fingerprints: ["There's nothing here", 'Whatever you were looking for']
  },
  {
    service: 'WordPress.com',
    cnames: ['.wordpress.com'],
    fingerprints: ["doesn't exist"]
  },
  {
    service: 'Ghost',
    cnames: ['.ghost.io'],
    fingerprints: ['The thing you were looking for is no longer here']
  },
  {
    service: 'Pantheon',
    cnames: ['.pantheonsite.io'],
    fingerprints: ['The gods are wise']
  },
  {
    service: 'Zendesk',
    cnames: ['.zendesk.com'],
    fingerprints: ['Help Center Closed']
  },
  {
    service: 'Azure',
    cnames: ['.azurewebsites.net', '.cloudapp.azure.com', '.azure-api.net'],
    fingerprints: ['404 Web Site not found', 'Web App - Pair missing']
  },
  {
    service: 'Fastly',
    cnames: ['.fastly.net', '.fastlylb.net'],
    fingerprints: ['Fastly error: unknown domain']
  },
  {
    service: 'Surge.sh',
    cnames: ['.surge.sh'],
    fingerprints: ['project not found']
  },
  {
    service: 'Unbounce',
    cnames: ['.unbouncepages.com'],
    fingerprints: ['The requested URL was not found']
  },
  {
    service: 'Bitbucket',
    cnames: ['.bitbucket.io'],
    fingerprints: ['Repository not found']
  },
];

const SubdomainTakeoverChecker: React.FC<Props> = ({ data, onChange }) => {
  const subdomains = data?.subdomains ?? '';
  const results = data?.results ?? [];
  const isChecking = data?.isChecking ?? false;
  const checkedAt = data?.checkedAt;
  const [copied, setCopied] = useState<string | null>(null);

  const checkTakeover = async () => {
    const subdomainList = subdomains
      .split('\n')
      .map(s => s.trim())
      .filter(s => s.length > 0);

    if (subdomainList.length === 0) return;

    onChange({ ...data, isChecking: true, results: [] });

    const newResults: TakeoverResult[] = [];

    for (const subdomain of subdomainList) {
      try {
        // Use DNS lookup via background script
        const dnsResponse = await chrome.runtime.sendMessage({
          type: 'xcalibr-dns-lookup',
          payload: { domain: subdomain, type: 'CNAME' }
        });

        const cname = dnsResponse?.records?.[0] || null;
        let vulnerable = false;
        let service: string | undefined;
        let fingerprint: string | undefined;

        if (cname) {
          // Check against known vulnerable fingerprints
          for (const fp of VULNERABLE_FINGERPRINTS) {
            for (const cnamePattern of fp.cnames) {
              if (cname.toLowerCase().includes(cnamePattern.toLowerCase())) {
                // Found a potentially vulnerable CNAME
                service = fp.service;

                // Try to fetch the subdomain to check fingerprint
                try {
                  const fetchResponse = await chrome.runtime.sendMessage({
                    type: 'xcalibr-fetch',
                    payload: { url: `https://${subdomain}` }
                  });

                  const body = fetchResponse?.body || '';
                  for (const fpText of fp.fingerprints) {
                    if (body.includes(fpText)) {
                      vulnerable = true;
                      fingerprint = fpText;
                      break;
                    }
                  }
                } catch {
                  // If fetch fails, mark as potentially vulnerable
                  vulnerable = true;
                  fingerprint = 'Connection failed - may be vulnerable';
                }
                break;
              }
            }
            if (service) break;
          }
        }

        newResults.push({
          subdomain,
          cname: cname || undefined,
          vulnerable,
          service,
          fingerprint
        });
      } catch (e) {
        newResults.push({
          subdomain,
          vulnerable: false,
          error: e instanceof Error ? e.message : 'Check failed'
        });
      }

      // Update results incrementally
      onChange({ ...data, results: [...newResults], isChecking: true });
    }

    onChange({
      ...data,
      results: newResults,
      isChecking: false,
      checkedAt: Date.now()
    });
  };

  const useCurrentDomain = () => {
    const hostname = window.location.hostname;
    onChange({ ...data, subdomains: hostname });
  };

  const copyResult = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(text);
    setTimeout(() => setCopied(null), 2000);
  };

  const vulnerableCount = results.filter(r => r.vulnerable).length;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Subdomain Takeover Checker</div>
        <div className="flex gap-2">
          <button
            onClick={useCurrentDomain}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Current Domain
          </button>
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Checks subdomains for potential takeover by analyzing CNAME records against known vulnerable services.
      </div>

      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
        <div className="text-[10px] text-slate-500 mb-1">Subdomains (one per line)</div>
        <textarea
          value={subdomains}
          onChange={(e) => onChange({ ...data, subdomains: e.target.value })}
          placeholder="subdomain1.example.com&#10;subdomain2.example.com&#10;..."
          rows={3}
          className="w-full rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono resize-none"
        />
      </div>

      <button
        onClick={checkTakeover}
        disabled={!subdomains.trim() || isChecking}
        className="w-full rounded bg-red-600/20 border border-red-500/30 px-2 py-1.5 text-[11px] text-red-300 hover:bg-red-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faSearch} className={`w-3 h-3 ${isChecking ? 'animate-spin' : ''}`} />
        {isChecking ? 'Checking...' : 'Check for Takeover'}
      </button>

      {results.length > 0 && (
        <div className="mb-2">
          <div className="flex items-center justify-between text-[10px] mb-2">
            <span className="text-slate-300 font-medium">Results:</span>
            <span className={vulnerableCount > 0 ? 'text-red-400' : 'text-green-400'}>
              {vulnerableCount} / {results.length} potentially vulnerable
            </span>
          </div>
        </div>
      )}

      <div className="flex-1 overflow-y-auto space-y-2 min-h-0">
        {results.length > 0 ? (
          results.map((r, i) => (
            <div
              key={i}
              className={`rounded border p-2 text-[10px] ${
                r.vulnerable
                  ? 'bg-red-900/30 border-red-500/50'
                  : r.error
                  ? 'bg-yellow-900/20 border-yellow-600/50'
                  : 'bg-green-900/20 border-green-700/50'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-slate-300 font-medium">{r.subdomain}</span>
                <div className="flex items-center gap-2">
                  {r.vulnerable ? (
                    <span className="text-red-400 flex items-center gap-1">
                      <FontAwesomeIcon icon={faExclamationTriangle} className="w-2.5 h-2.5" />
                      Vulnerable
                    </span>
                  ) : r.error ? (
                    <span className="text-yellow-400">Error</span>
                  ) : (
                    <span className="text-green-400 flex items-center gap-1">
                      <FontAwesomeIcon icon={faCheckCircle} className="w-2.5 h-2.5" />
                      Safe
                    </span>
                  )}
                </div>
              </div>

              {r.cname && (
                <div className="mt-1 text-slate-500 flex items-center gap-1">
                  <span>CNAME: {r.cname}</span>
                  <button
                    onClick={() => copyResult(r.cname!)}
                    className="text-[9px] text-slate-500 hover:text-slate-300 p-0.5"
                  >
                    <FontAwesomeIcon icon={copied === r.cname ? faCheck : faCopy} className="w-2.5 h-2.5" />
                  </button>
                </div>
              )}

              {r.service && (
                <div className="mt-1 text-yellow-500">Service: {r.service}</div>
              )}

              {r.fingerprint && (
                <div className="mt-1 text-red-400 text-[9px]">"{r.fingerprint}"</div>
              )}

              {r.error && (
                <div className="mt-1 text-yellow-500 text-[9px]">{r.error}</div>
              )}
            </div>
          ))
        ) : (
          <div className="text-[11px] text-slate-500 text-center py-4">
            Enter subdomains and click "Check for Takeover" to scan.
          </div>
        )}
      </div>

      {checkedAt && (
        <div className="text-[10px] text-slate-500 text-center mt-3 pt-2 border-t border-slate-700">
          Checked at {new Date(checkedAt).toLocaleTimeString()}
        </div>
      )}

      <div className="text-[10px] text-slate-500 border-t border-slate-700 pt-2 mt-2">
        <strong>Note:</strong> This tool checks for common subdomain takeover scenarios.
        A vulnerable result means the CNAME points to an unclaimed resource.
      </div>
    </div>
  );
};

export class SubdomainTakeoverCheckerTool {
  static Component = SubdomainTakeoverChecker;
}
