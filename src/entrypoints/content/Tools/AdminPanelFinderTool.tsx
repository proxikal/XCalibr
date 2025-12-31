import React, { useState, useRef } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSearch, faCheckCircle, faTimesCircle, faExternalLinkAlt, faStop } from '@fortawesome/free-solid-svg-icons';

export type AdminPanelFinderData = {
  baseUrl?: string;
  results?: AdminPathResult[];
  isRunning?: boolean;
  progress?: number;
  scannedAt?: number;
  customPaths?: string;
  delay?: number;
};

type AdminPathResult = {
  path: string;
  status: number;
  exists: boolean;
  redirectUrl?: string;
};

type Props = {
  data: AdminPanelFinderData | undefined;
  onChange: (data: AdminPanelFinderData) => void;
};

const DEFAULT_ADMIN_PATHS = [
  '/admin',
  '/administrator',
  '/admin.php',
  '/admin.html',
  '/login',
  '/login.php',
  '/wp-admin',
  '/wp-login.php',
  '/cpanel',
  '/phpmyadmin',
  '/pma',
  '/adminer',
  '/dashboard',
  '/panel',
  '/controlpanel',
  '/backend',
  '/manage',
  '/management',
  '/manager',
  '/cms',
  '/admin/login',
  '/admin/index.php',
  '/user/login',
  '/auth/login',
  '/secure',
  '/portal',
  '/webadmin',
  '/siteadmin',
  '/moderator',
  '/supervisor'
];

const AdminPanelFinder: React.FC<Props> = ({ data, onChange }) => {
  const baseUrl = data?.baseUrl ?? '';
  const results = data?.results ?? [];
  const isRunning = data?.isRunning ?? false;
  const progress = data?.progress ?? 0;
  const scannedAt = data?.scannedAt;
  const customPaths = data?.customPaths ?? '';
  const delay = data?.delay ?? 100;

  const [showCustom, setShowCustom] = useState(false);
  const abortRef = useRef(false);

  const handleUseCurrentDomain = () => {
    const url = new URL(window.location.href);
    onChange({ ...data, baseUrl: url.origin });
  };

  const handleScan = async () => {
    if (!baseUrl.trim()) return;

    abortRef.current = false;
    onChange({ ...data, isRunning: true, results: [], progress: 0 });

    const paths = customPaths.trim()
      ? customPaths.split('\n').map(p => p.trim()).filter(Boolean)
      : DEFAULT_ADMIN_PATHS;

    const foundResults: AdminPathResult[] = [];

    for (let i = 0; i < paths.length; i++) {
      if (abortRef.current) break;

      const path = paths[i];
      const fullUrl = baseUrl.replace(/\/$/, '') + (path.startsWith('/') ? path : '/' + path);

      try {
        const response = await fetch(fullUrl, {
          method: 'GET',
          mode: 'no-cors',
          credentials: 'omit'
        });

        // With no-cors we can't read status, so try with cors
        try {
          const corsResponse = await fetch(fullUrl, {
            method: 'HEAD',
            credentials: 'omit'
          });

          const exists = corsResponse.status >= 200 && corsResponse.status < 400;
          foundResults.push({
            path,
            status: corsResponse.status,
            exists,
            redirectUrl: corsResponse.redirected ? corsResponse.url : undefined
          });
        } catch {
          // CORS blocked but page might exist
          foundResults.push({
            path,
            status: 0,
            exists: false
          });
        }
      } catch {
        foundResults.push({
          path,
          status: 0,
          exists: false
        });
      }

      onChange({
        ...data,
        isRunning: true,
        results: [...foundResults],
        progress: Math.round(((i + 1) / paths.length) * 100)
      });

      if (delay > 0) {
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    onChange({
      ...data,
      isRunning: false,
      results: foundResults,
      progress: 100,
      scannedAt: Date.now()
    });
  };

  const handleStop = () => {
    abortRef.current = true;
    onChange({ ...data, isRunning: false });
  };

  const foundPanels = results.filter(r => r.exists);
  const notFoundCount = results.filter(r => !r.exists).length;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Admin Panel Finder</div>
        <div className="flex gap-2">
          <button
            onClick={handleUseCurrentDomain}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Current Domain
          </button>
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Checks for common admin panel paths on the target domain.
      </div>

      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
        <label className="text-[10px] text-slate-500 mb-1 block">Target URL</label>
        <input
          type="url"
          value={baseUrl}
          onChange={(e) => onChange({ ...data, baseUrl: e.target.value })}
          placeholder="https://example.com"
          className="w-full rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        />
      </div>

      <div className="flex gap-2 mb-3">
        <button
          onClick={() => setShowCustom(!showCustom)}
          className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors border border-slate-700"
        >
          {showCustom ? 'Hide' : 'Show'} Custom Paths
        </button>
        <div className="flex items-center gap-2">
          <label className="text-[10px] text-slate-500">Delay (ms):</label>
          <input
            type="number"
            value={delay}
            onChange={(e) => onChange({ ...data, delay: parseInt(e.target.value) || 0 })}
            className="w-16 rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
            min={0}
            max={5000}
          />
        </div>
      </div>

      {showCustom && (
        <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
          <label className="text-[10px] text-slate-500 mb-1 block">Custom Paths (one per line)</label>
          <textarea
            value={customPaths}
            onChange={(e) => onChange({ ...data, customPaths: e.target.value })}
            placeholder={DEFAULT_ADMIN_PATHS.slice(0, 5).join('\n')}
            className="w-full rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500 h-24 font-mono"
          />
        </div>
      )}

      <div className="flex gap-2 mb-3">
        {!isRunning ? (
          <button
            onClick={handleScan}
            disabled={!baseUrl.trim()}
            className="flex-1 w-full rounded bg-purple-600/20 border border-purple-500/30 px-2 py-1.5 text-[11px] text-purple-300 hover:bg-purple-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
          >
            <FontAwesomeIcon icon={faSearch} className="w-3 h-3" />
            Scan for Admin Panels
          </button>
        ) : (
          <button
            onClick={handleStop}
            className="flex-1 w-full rounded bg-red-600/20 border border-red-500/30 px-2 py-1.5 text-[11px] text-red-300 hover:bg-red-600/30 transition-colors flex items-center justify-center gap-2"
          >
            <FontAwesomeIcon icon={faStop} className="w-3 h-3" />
            Stop Scan
          </button>
        )}
      </div>

      {isRunning && (
        <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
          <div className="flex justify-between text-[10px] text-slate-400 mb-1">
            <span>Scanning...</span>
            <span>{progress}%</span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-1.5">
            <div
              className="bg-purple-500 h-1.5 rounded-full transition-all"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      {results.length > 0 && (
        <div className="flex-1 overflow-y-auto space-y-2 min-h-0">
          <div className="flex gap-4 text-[10px]">
            <span className="text-green-400">
              <FontAwesomeIcon icon={faCheckCircle} className="w-3 h-3 mr-1" />
              Found: {foundPanels.length}
            </span>
            <span className="text-slate-400">
              <FontAwesomeIcon icon={faTimesCircle} className="w-3 h-3 mr-1" />
              Not Found: {notFoundCount}
            </span>
          </div>

          {foundPanels.length > 0 && (
            <div className="space-y-2">
              {foundPanels.map((result, index) => (
                <div key={index} className="rounded border border-green-700 bg-green-900/20 p-2">
                  <div className="flex items-center justify-between">
                    <span className="text-green-400 font-medium text-[11px]">{result.path}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-slate-400 text-[10px]">Status: {result.status}</span>
                      <a
                        href={baseUrl.replace(/\/$/, '') + result.path}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-[9px] text-slate-500 hover:text-slate-300"
                      >
                        <FontAwesomeIcon icon={faExternalLinkAlt} className="w-2.5 h-2.5" />
                      </a>
                    </div>
                  </div>
                  {result.redirectUrl && (
                    <div className="text-slate-500 mt-1 break-all text-[10px]">
                      Redirects to: {result.redirectUrl}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {scannedAt && (
            <div className="text-[10px] text-slate-500">
              Last scanned: {new Date(scannedAt).toLocaleTimeString()}
            </div>
          )}
        </div>
      )}

      {results.length === 0 && !isRunning && (
        <div className="text-[11px] text-slate-500 text-center py-4">
          Enter a target URL and scan for admin panels.
        </div>
      )}

      <div className="text-[10px] text-slate-500 border-t border-slate-700 pt-3 mt-3">
        Scans {customPaths.trim() ? 'custom paths' : `${DEFAULT_ADMIN_PATHS.length} common admin paths`} for accessible login/admin panels.
      </div>
    </div>
  );
};

export class AdminPanelFinderTool {
  static Component = AdminPanelFinder;
}
