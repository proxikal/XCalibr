import React, { useState } from 'react';

export type DirectoryResult = {
  path: string;
  status: number;
  size?: number;
};

export type DirectoryBusterData = {
  baseUrl?: string;
  customPaths?: string;
  results?: DirectoryResult[];
  isRunning?: boolean;
  progress?: number;
  delay?: number;
};

type Props = {
  data: DirectoryBusterData | undefined;
  onChange: (data: DirectoryBusterData) => void;
};

const DEFAULT_PATHS = [
  '/admin', '/administrator', '/login', '/wp-admin', '/wp-login.php',
  '/backup', '/backups', '/db', '/database', '/sql',
  '/.git', '/.env', '/config', '/config.php', '/config.json',
  '/api', '/api/v1', '/api/v2', '/graphql', '/swagger',
  '/test', '/debug', '/dev', '/staging', '/beta',
  '/uploads', '/files', '/static', '/assets', '/media',
  '/phpmyadmin', '/cpanel', '/webmail', '/controlpanel',
  '/.htaccess', '/.htpasswd', '/robots.txt', '/sitemap.xml',
  '/server-status', '/server-info', '/.well-known'
];

const DirectoryBuster: React.FC<Props> = ({ data, onChange }) => {
  const baseUrl = data?.baseUrl ?? '';
  const customPaths = data?.customPaths ?? '';
  const results = data?.results ?? [];
  const isRunning = data?.isRunning ?? false;
  const progress = data?.progress ?? 0;
  const delay = data?.delay ?? 100;
  const [abortController, setAbortController] = useState<AbortController | null>(null);

  const handleScan = async () => {
    if (!baseUrl.trim()) return;

    const controller = new AbortController();
    setAbortController(controller);
    onChange({ ...data, isRunning: true, results: [], progress: 0 });

    // Combine default and custom paths
    const paths = [...DEFAULT_PATHS];
    if (customPaths.trim()) {
      const custom = customPaths.split('\n').map(p => p.trim()).filter(p => p.startsWith('/'));
      paths.push(...custom);
    }

    const foundResults: DirectoryResult[] = [];
    const base = baseUrl.replace(/\/$/, '');

    for (let i = 0; i < paths.length; i++) {
      if (controller.signal.aborted) break;

      const path = paths[i];
      const url = base + path;

      try {
        const response = await chrome.runtime.sendMessage({
          type: 'xcalibr-http-request',
          payload: { url, method: 'GET' }
        });

        if (response?.status && response.status !== 404) {
          foundResults.push({
            path,
            status: response.status,
            size: response.body?.length || 0
          });
        }

        onChange({
          ...data,
          isRunning: true,
          results: [...foundResults],
          progress: Math.round(((i + 1) / paths.length) * 100)
        });

        // Rate limiting
        await new Promise(r => setTimeout(r, delay));
      } catch {
        // Skip failed requests
      }
    }

    onChange({
      ...data,
      isRunning: false,
      results: foundResults,
      progress: 100
    });
    setAbortController(null);
  };

  const handleStop = () => {
    abortController?.abort();
    onChange({ ...data, isRunning: false });
  };

  const handleUseCurrentDomain = () => {
    const url = new URL(window.location.href);
    onChange({ ...data, baseUrl: url.origin });
  };

  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return 'text-green-400 bg-green-900/20';
    if (status >= 300 && status < 400) return 'text-blue-400 bg-blue-900/20';
    if (status === 401 || status === 403) return 'text-yellow-400 bg-yellow-900/20';
    return 'text-gray-400 bg-gray-900/20';
  };

  return (
    <div className="space-y-4">
      <div className="text-xs text-gray-400">
        Discovers hidden directories and files using common path wordlist.
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Base URL</label>
        <div className="flex gap-2">
          <input
            type="url"
            value={baseUrl}
            onChange={(e) => onChange({ ...data, baseUrl: e.target.value })}
            placeholder="https://example.com"
            className="flex-1 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          />
          <button
            onClick={handleUseCurrentDomain}
            className="px-3 py-2 bg-gray-600 hover:bg-gray-500 text-white rounded text-xs"
          >
            Current
          </button>
        </div>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Custom Paths (one per line)</label>
        <textarea
          value={customPaths}
          onChange={(e) => onChange({ ...data, customPaths: e.target.value })}
          placeholder="/secret&#10;/hidden&#10;/private"
          className="w-full h-16 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
        />
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Delay between requests (ms)</label>
        <input
          type="number"
          value={delay}
          onChange={(e) => onChange({ ...data, delay: parseInt(e.target.value) || 100 })}
          min={50}
          max={2000}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
        />
      </div>

      <div className="flex gap-2">
        {isRunning ? (
          <button
            onClick={handleStop}
            className="flex-1 py-2 bg-yellow-600 hover:bg-yellow-500 text-white rounded text-sm"
          >
            Stop ({progress}%)
          </button>
        ) : (
          <button
            onClick={handleScan}
            disabled={!baseUrl.trim()}
            className="flex-1 py-2 bg-red-600 hover:bg-red-500 disabled:bg-gray-600 text-white rounded text-sm"
          >
            Start Directory Scan
          </button>
        )}
      </div>

      {isRunning && (
        <div className="w-full bg-gray-700 rounded-full h-2">
          <div
            className="bg-red-500 h-2 rounded-full transition-all"
            style={{ width: `${progress}%` }}
          />
        </div>
      )}

      {results.length > 0 && (
        <div className="space-y-2">
          <div className="text-xs text-gray-400">
            Found {results.length} paths
          </div>
          <div className="max-h-40 overflow-y-auto space-y-1">
            {results.map((result, i) => (
              <div key={i} className={`flex justify-between items-center text-xs px-2 py-1 rounded ${getStatusColor(result.status)}`}>
                <span className="font-mono truncate">{result.path}</span>
                <span>{result.status}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="text-xs text-gray-500">
        <strong>Warning:</strong> Only use on authorized targets. Includes {DEFAULT_PATHS.length} common paths.
      </div>
    </div>
  );
};

export class DirectoryBusterTool {
  static Component = DirectoryBuster;
}
