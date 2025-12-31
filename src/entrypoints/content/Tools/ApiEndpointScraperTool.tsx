import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSearch, faCopy, faCheck, faFilter, faDownload } from '@fortawesome/free-solid-svg-icons';

export type ApiEndpoint = {
  url: string;
  method?: string;
  source: 'script' | 'fetch' | 'xhr' | 'inline' | 'attribute';
};

export type ApiEndpointScraperData = {
  endpoints?: ApiEndpoint[];
  filter?: string;
  showMethods?: boolean;
  scannedAt?: number;
};

type Props = {
  data: ApiEndpointScraperData | undefined;
  onChange: (data: ApiEndpointScraperData) => void;
};

const API_PATTERNS = [
  /['"`](\/api\/[^'"`\s]+)['"`]/g,
  /['"`](\/v\d+\/[^'"`\s]+)['"`]/g,
  /['"`](https?:\/\/[^'"`\s]*\/api\/[^'"`\s]+)['"`]/g,
  /['"`](https?:\/\/api\.[^'"`\s]+)['"`]/g,
  /['"`](\/graphql[^'"`\s]*)['"`]/g,
  /['"`](\/rest\/[^'"`\s]+)['"`]/g,
  /['"`](\/ws\/[^'"`\s]+)['"`]/g,
  /['"`](\/socket\.io[^'"`\s]*)['"`]/g,
  /fetch\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /\.get\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /\.post\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /\.put\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /\.delete\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /\.patch\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /XMLHttpRequest.*?\.open\s*\(\s*['"`]\w+['"`]\s*,\s*['"`]([^'"`]+)['"`]/g,
  /axios\s*\.\w+\s*\(\s*['"`]([^'"`]+)['"`]/g,
];

const METHOD_PATTERNS: { pattern: RegExp; method: string }[] = [
  { pattern: /\.get\s*\(/i, method: 'GET' },
  { pattern: /\.post\s*\(/i, method: 'POST' },
  { pattern: /\.put\s*\(/i, method: 'PUT' },
  { pattern: /\.delete\s*\(/i, method: 'DELETE' },
  { pattern: /\.patch\s*\(/i, method: 'PATCH' },
];

const ApiEndpointScraper: React.FC<Props> = ({ data, onChange }) => {
  const endpoints = data?.endpoints ?? [];
  const filter = data?.filter ?? '';
  const scannedAt = data?.scannedAt;
  const [copied, setCopied] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);

  const extractEndpoints = (text: string, source: ApiEndpoint['source']): ApiEndpoint[] => {
    const found: ApiEndpoint[] = [];
    const seen = new Set<string>();

    for (const pattern of API_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(text)) !== null) {
        const url = match[1];
        if (url && !seen.has(url) && (url.startsWith('/') || url.startsWith('http'))) {
          seen.add(url);

          // Try to detect method
          let method: string | undefined;
          for (const mp of METHOD_PATTERNS) {
            if (mp.pattern.test(text.slice(Math.max(0, match.index - 50), match.index + 100))) {
              method = mp.method;
              break;
            }
          }

          found.push({ url, method, source });
        }
      }
    }

    return found;
  };

  const scanPage = async () => {
    setScanning(true);
    const allEndpoints: ApiEndpoint[] = [];

    // Scan inline scripts
    const scripts = document.querySelectorAll('script:not([src])');
    scripts.forEach(script => {
      const content = script.textContent || '';
      allEndpoints.push(...extractEndpoints(content, 'inline'));
    });

    // Scan external scripts
    const externalScripts = document.querySelectorAll('script[src]');
    for (const script of externalScripts) {
      const src = script.getAttribute('src');
      if (src) {
        try {
          const response = await fetch(src);
          const content = await response.text();
          allEndpoints.push(...extractEndpoints(content, 'script'));
        } catch {
          // Skip failed fetches
        }
      }
    }

    // Scan data attributes
    const elementsWithData = document.querySelectorAll('[data-url], [data-api], [data-endpoint], [data-action]');
    elementsWithData.forEach(el => {
      const attrs = ['data-url', 'data-api', 'data-endpoint', 'data-action'];
      attrs.forEach(attr => {
        const value = el.getAttribute(attr);
        if (value && (value.startsWith('/') || value.startsWith('http'))) {
          allEndpoints.push({ url: value, source: 'attribute' });
        }
      });
    });

    // Scan form actions
    const forms = document.querySelectorAll('form[action]');
    forms.forEach(form => {
      const action = form.getAttribute('action');
      const method = form.getAttribute('method')?.toUpperCase() || 'GET';
      if (action) {
        allEndpoints.push({ url: action, method, source: 'attribute' });
      }
    });

    // Deduplicate
    const seen = new Set<string>();
    const unique = allEndpoints.filter(ep => {
      const key = `${ep.method || ''}:${ep.url}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    onChange({
      ...data,
      endpoints: unique,
      scannedAt: Date.now()
    });
    setScanning(false);
  };

  const filteredEndpoints = endpoints.filter(ep =>
    ep.url.toLowerCase().includes(filter.toLowerCase())
  );

  const copyUrl = (url: string) => {
    navigator.clipboard.writeText(url);
    setCopied(url);
    setTimeout(() => setCopied(null), 2000);
  };

  const exportEndpoints = () => {
    const content = filteredEndpoints.map(ep =>
      `${ep.method || 'GET'} ${ep.url}`
    ).join('\n');
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'api-endpoints.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">API Endpoint Scraper</div>
        <div className="flex gap-2">
          {endpoints.length > 0 && (
            <button
              onClick={exportEndpoints}
              className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
              title="Export endpoints"
            >
              <FontAwesomeIcon icon={faDownload} className="w-2.5 h-2.5" />
            </button>
          )}
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Extracts API endpoints from page scripts, inline code, and data attributes.
      </div>

      <button
        onClick={scanPage}
        disabled={scanning}
        className="w-full rounded bg-blue-600/20 border border-blue-500/30 px-2 py-1.5 text-[11px] text-blue-300 hover:bg-blue-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faSearch} className={`w-3 h-3 ${scanning ? 'animate-spin' : ''}`} />
        {scanning ? 'Scanning...' : 'Scan Page for Endpoints'}
      </button>

      {endpoints.length > 0 && (
        <>
          <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
            <div className="relative">
              <FontAwesomeIcon icon={faFilter} className="absolute left-2 top-1/2 -translate-y-1/2 text-slate-500 w-2.5 h-2.5" />
              <input
                type="text"
                value={filter}
                onChange={(e) => onChange({ ...data, filter: e.target.value })}
                placeholder="Filter endpoints..."
                className="w-full rounded bg-slate-800 text-slate-200 text-[11px] pl-7 pr-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <div className="text-[10px] text-slate-400 mb-2">
            Found {filteredEndpoints.length} of {endpoints.length} endpoints
            {scannedAt && ` (scanned ${new Date(scannedAt).toLocaleTimeString()})`}
          </div>

          <div className="flex-1 overflow-y-auto space-y-2 min-h-0">
            {filteredEndpoints.map((ep, i) => (
              <div
                key={i}
                className="rounded border border-slate-700 bg-slate-800/50 p-2 flex items-center gap-2"
              >
                {ep.method && (
                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-medium ${
                    ep.method === 'GET' ? 'bg-green-600/30 text-green-300' :
                    ep.method === 'POST' ? 'bg-blue-600/30 text-blue-300' :
                    ep.method === 'PUT' ? 'bg-yellow-600/30 text-yellow-300' :
                    ep.method === 'DELETE' ? 'bg-red-600/30 text-red-300' :
                    'bg-purple-600/30 text-purple-300'
                  }`}>
                    {ep.method}
                  </span>
                )}
                <span className="flex-1 text-slate-300 truncate text-[11px]" title={ep.url}>
                  {ep.url}
                </span>
                <span className="text-slate-500 text-[9px]">{ep.source}</span>
                <button
                  onClick={() => copyUrl(ep.url)}
                  className="text-[9px] text-slate-500 hover:text-slate-300"
                  title="Copy URL"
                >
                  <FontAwesomeIcon icon={copied === ep.url ? faCheck : faCopy} className="w-2.5 h-2.5" />
                </button>
              </div>
            ))}
          </div>
        </>
      )}

      {endpoints.length === 0 && scannedAt && (
        <div className="text-[11px] text-slate-500 text-center py-4">
          No API endpoints found on this page.
        </div>
      )}

      {endpoints.length === 0 && !scannedAt && (
        <div className="text-[11px] text-slate-500 text-center py-4">
          Click scan to find API endpoints on this page.
        </div>
      )}
    </div>
  );
};

export class ApiEndpointScraperTool {
  static Component = ApiEndpointScraper;
}
