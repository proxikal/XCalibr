import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSearch, faCodeBranch, faExclamationTriangle, faCheckCircle, faExternalLinkAlt, faDownload, faFilter } from '@fortawesome/free-solid-svg-icons';

export type VcsType = 'git' | 'svn' | 'hg' | 'bzr';

export type VcsCheckResult = {
  path: string;
  status: number;
  accessible: boolean;
  contentType?: string;
  vcsType: VcsType;
  category: string;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
};

export type GitExposureCheckerData = {
  checked?: boolean;
  exposed?: boolean;
  results?: VcsCheckResult[];
  domain?: string;
  scannedAt?: number;
  error?: string;
  filterVcs?: VcsType | 'all';
};

type Props = {
  data: GitExposureCheckerData | undefined;
  onChange: (data: GitExposureCheckerData) => void;
};

type VcsPath = {
  path: string;
  vcsType: VcsType;
  category: string;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
};

// Comprehensive VCS paths to check
const VCS_PATHS: VcsPath[] = [
  // === Git - Critical ===
  { path: '/.git/HEAD', vcsType: 'git', category: 'Core', riskLevel: 'critical' },
  { path: '/.git/config', vcsType: 'git', category: 'Core', riskLevel: 'critical' },
  { path: '/.git/index', vcsType: 'git', category: 'Core', riskLevel: 'critical' },
  { path: '/.git/packed-refs', vcsType: 'git', category: 'Core', riskLevel: 'critical' },
  { path: '/.git/objects/info/packs', vcsType: 'git', category: 'Objects', riskLevel: 'critical' },

  // === Git - High ===
  { path: '/.git/logs/HEAD', vcsType: 'git', category: 'Logs', riskLevel: 'high' },
  { path: '/.git/logs/refs/heads/master', vcsType: 'git', category: 'Logs', riskLevel: 'high' },
  { path: '/.git/logs/refs/heads/main', vcsType: 'git', category: 'Logs', riskLevel: 'high' },
  { path: '/.git/logs/refs/heads/develop', vcsType: 'git', category: 'Logs', riskLevel: 'high' },
  { path: '/.git/refs/heads/master', vcsType: 'git', category: 'Refs', riskLevel: 'high' },
  { path: '/.git/refs/heads/main', vcsType: 'git', category: 'Refs', riskLevel: 'high' },
  { path: '/.git/refs/heads/develop', vcsType: 'git', category: 'Refs', riskLevel: 'high' },
  { path: '/.git/refs/tags/', vcsType: 'git', category: 'Refs', riskLevel: 'high' },
  { path: '/.git/refs/remotes/origin/HEAD', vcsType: 'git', category: 'Refs', riskLevel: 'high' },
  { path: '/.git/COMMIT_EDITMSG', vcsType: 'git', category: 'Metadata', riskLevel: 'high' },
  { path: '/.git/FETCH_HEAD', vcsType: 'git', category: 'Metadata', riskLevel: 'high' },
  { path: '/.git/ORIG_HEAD', vcsType: 'git', category: 'Metadata', riskLevel: 'high' },

  // === Git - Medium ===
  { path: '/.git/description', vcsType: 'git', category: 'Metadata', riskLevel: 'medium' },
  { path: '/.git/info/exclude', vcsType: 'git', category: 'Info', riskLevel: 'medium' },
  { path: '/.git/info/refs', vcsType: 'git', category: 'Info', riskLevel: 'medium' },
  { path: '/.git/hooks/', vcsType: 'git', category: 'Hooks', riskLevel: 'medium' },
  { path: '/.git/hooks/pre-commit', vcsType: 'git', category: 'Hooks', riskLevel: 'medium' },
  { path: '/.git/hooks/post-commit', vcsType: 'git', category: 'Hooks', riskLevel: 'medium' },
  { path: '/.git/shallow', vcsType: 'git', category: 'Metadata', riskLevel: 'medium' },
  { path: '/.git/modules/', vcsType: 'git', category: 'Submodules', riskLevel: 'medium' },
  { path: '/.gitignore', vcsType: 'git', category: 'Config', riskLevel: 'medium' },
  { path: '/.gitattributes', vcsType: 'git', category: 'Config', riskLevel: 'medium' },
  { path: '/.gitmodules', vcsType: 'git', category: 'Config', riskLevel: 'medium' },

  // === Git - Low ===
  { path: '/.git/objects/', vcsType: 'git', category: 'Objects', riskLevel: 'low' },
  { path: '/.git/refs/', vcsType: 'git', category: 'Refs', riskLevel: 'low' },
  { path: '/.git/logs/', vcsType: 'git', category: 'Logs', riskLevel: 'low' },

  // === SVN - Critical ===
  { path: '/.svn/entries', vcsType: 'svn', category: 'Core', riskLevel: 'critical' },
  { path: '/.svn/wc.db', vcsType: 'svn', category: 'Core', riskLevel: 'critical' },
  { path: '/.svn/all-wcprops', vcsType: 'svn', category: 'Core', riskLevel: 'critical' },
  { path: '/.svn/props/', vcsType: 'svn', category: 'Props', riskLevel: 'critical' },

  // === SVN - High ===
  { path: '/.svn/pristine/', vcsType: 'svn', category: 'Pristine', riskLevel: 'high' },
  { path: '/.svn/tmp/', vcsType: 'svn', category: 'Temp', riskLevel: 'high' },
  { path: '/.svn/text-base/', vcsType: 'svn', category: 'Text Base', riskLevel: 'high' },
  { path: '/.svn/prop-base/', vcsType: 'svn', category: 'Prop Base', riskLevel: 'high' },
  { path: '/.svn/format', vcsType: 'svn', category: 'Metadata', riskLevel: 'high' },

  // === SVN - Medium ===
  { path: '/.svn/', vcsType: 'svn', category: 'Directory', riskLevel: 'medium' },
  { path: '/.svn/dir-props', vcsType: 'svn', category: 'Props', riskLevel: 'medium' },

  // === Mercurial - Critical ===
  { path: '/.hg/hgrc', vcsType: 'hg', category: 'Core', riskLevel: 'critical' },
  { path: '/.hg/store/', vcsType: 'hg', category: 'Store', riskLevel: 'critical' },
  { path: '/.hg/store/data/', vcsType: 'hg', category: 'Store', riskLevel: 'critical' },
  { path: '/.hg/dirstate', vcsType: 'hg', category: 'Core', riskLevel: 'critical' },

  // === Mercurial - High ===
  { path: '/.hg/requires', vcsType: 'hg', category: 'Metadata', riskLevel: 'high' },
  { path: '/.hg/branch', vcsType: 'hg', category: 'Metadata', riskLevel: 'high' },
  { path: '/.hg/bookmarks', vcsType: 'hg', category: 'Metadata', riskLevel: 'high' },
  { path: '/.hg/last-message.txt', vcsType: 'hg', category: 'Metadata', riskLevel: 'high' },
  { path: '/.hg/undo.dirstate', vcsType: 'hg', category: 'Undo', riskLevel: 'high' },
  { path: '/.hg/undo.branch', vcsType: 'hg', category: 'Undo', riskLevel: 'high' },

  // === Mercurial - Medium ===
  { path: '/.hg/', vcsType: 'hg', category: 'Directory', riskLevel: 'medium' },
  { path: '/.hgignore', vcsType: 'hg', category: 'Config', riskLevel: 'medium' },
  { path: '/.hgtags', vcsType: 'hg', category: 'Tags', riskLevel: 'medium' },

  // === Bazaar - Critical ===
  { path: '/.bzr/branch/branch.conf', vcsType: 'bzr', category: 'Core', riskLevel: 'critical' },
  { path: '/.bzr/repository/', vcsType: 'bzr', category: 'Repository', riskLevel: 'critical' },
  { path: '/.bzr/checkout/dirstate', vcsType: 'bzr', category: 'Checkout', riskLevel: 'critical' },

  // === Bazaar - High ===
  { path: '/.bzr/branch/', vcsType: 'bzr', category: 'Branch', riskLevel: 'high' },
  { path: '/.bzr/branch/last-revision', vcsType: 'bzr', category: 'Branch', riskLevel: 'high' },
  { path: '/.bzr/branch/format', vcsType: 'bzr', category: 'Branch', riskLevel: 'high' },
  { path: '/.bzr/repository/format', vcsType: 'bzr', category: 'Repository', riskLevel: 'high' },

  // === Bazaar - Medium ===
  { path: '/.bzr/', vcsType: 'bzr', category: 'Directory', riskLevel: 'medium' },
  { path: '/.bzrignore', vcsType: 'bzr', category: 'Config', riskLevel: 'medium' },
];

const VCS_COLORS: Record<VcsType, { bg: string; text: string; label: string }> = {
  git: { bg: 'bg-orange-900/50', text: 'text-orange-300', label: 'Git' },
  svn: { bg: 'bg-blue-900/50', text: 'text-blue-300', label: 'SVN' },
  hg: { bg: 'bg-purple-900/50', text: 'text-purple-300', label: 'Mercurial' },
  bzr: { bg: 'bg-green-900/50', text: 'text-green-300', label: 'Bazaar' }
};

const RISK_COLORS: Record<string, { bg: string; text: string }> = {
  critical: { bg: 'bg-red-900/50', text: 'text-red-400' },
  high: { bg: 'bg-orange-900/50', text: 'text-orange-400' },
  medium: { bg: 'bg-yellow-900/50', text: 'text-yellow-400' },
  low: { bg: 'bg-slate-700/50', text: 'text-slate-400' }
};

const GitExposureChecker: React.FC<Props> = ({ data, onChange }) => {
  const checked = data?.checked ?? false;
  const exposed = data?.exposed ?? false;
  const results = data?.results ?? [];
  const domain = data?.domain ?? '';
  const scannedAt = data?.scannedAt;
  const error = data?.error;
  const filterVcs = data?.filterVcs ?? 'all';
  const [scanning, setScanning] = useState(false);

  const checkVcsExposure = async () => {
    setScanning(true);
    const currentDomain = window.location.origin;

    try {
      const checkResults: VcsCheckResult[] = [];
      let anyExposed = false;

      // Check all VCS paths in parallel (batch to avoid overwhelming)
      const batchSize = 10;
      for (let i = 0; i < VCS_PATHS.length; i += batchSize) {
        const batch = VCS_PATHS.slice(i, i + batchSize);

        const checks = await Promise.allSettled(
          batch.map(async (pathConfig) => {
            try {
              // Try direct fetch first
              const response = await fetch(currentDomain + pathConfig.path, {
                method: 'GET',
                cache: 'no-cache'
              });

              const accessible = response.status === 200;
              if (accessible) anyExposed = true;

              return {
                path: pathConfig.path,
                status: response.status,
                accessible,
                contentType: response.headers.get('content-type') || undefined,
                vcsType: pathConfig.vcsType,
                category: pathConfig.category,
                riskLevel: pathConfig.riskLevel
              };
            } catch {
              // Try through background script for CORS issues
              try {
                const bgResponse = await chrome.runtime.sendMessage({
                  type: 'xcalibr-fetch-url',
                  payload: { url: currentDomain + pathConfig.path, method: 'HEAD' }
                });

                const accessible = bgResponse?.status === 200;
                if (accessible) anyExposed = true;

                return {
                  path: pathConfig.path,
                  status: bgResponse?.status || 0,
                  accessible,
                  contentType: bgResponse?.contentType,
                  vcsType: pathConfig.vcsType,
                  category: pathConfig.category,
                  riskLevel: pathConfig.riskLevel
                };
              } catch {
                return {
                  path: pathConfig.path,
                  status: 0,
                  accessible: false,
                  vcsType: pathConfig.vcsType,
                  category: pathConfig.category,
                  riskLevel: pathConfig.riskLevel
                };
              }
            }
          })
        );

        checks.forEach((result) => {
          if (result.status === 'fulfilled') {
            checkResults.push(result.value);
          }
        });
      }

      onChange({
        checked: true,
        exposed: anyExposed,
        results: checkResults,
        domain: currentDomain,
        scannedAt: Date.now(),
        error: undefined,
        filterVcs
      });
    } catch (e) {
      onChange({
        ...data,
        checked: true,
        error: e instanceof Error ? e.message : 'Check failed',
        scannedAt: Date.now()
      });
    } finally {
      setScanning(false);
    }
  };

  const filteredResults = results.filter(r =>
    filterVcs === 'all' || r.vcsType === filterVcs
  );

  const accessibleResults = filteredResults.filter(r => r.accessible);
  const inaccessibleResults = filteredResults.filter(r => !r.accessible);

  const vcsCounts = results.reduce((acc, r) => {
    if (r.accessible) {
      acc[r.vcsType] = (acc[r.vcsType] || 0) + 1;
    }
    return acc;
  }, {} as Record<string, number>);

  const exportAsJson = () => {
    const exportData = {
      domain: domain || window.location.origin,
      scannedAt: scannedAt ? new Date(scannedAt).toISOString() : null,
      exposed,
      summary: {
        totalChecked: results.length,
        totalExposed: accessibleResults.length,
        byVcs: vcsCounts,
        criticalExposures: accessibleResults.filter(r => r.riskLevel === 'critical').length,
        highExposures: accessibleResults.filter(r => r.riskLevel === 'high').length
      },
      exposedPaths: accessibleResults,
      allResults: results
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vcs-exposure-${window.location.hostname}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">VCS Exposure Checker</div>
        <div className="flex gap-1">
          {checked && accessibleResults.length > 0 && (
            <button
              onClick={exportAsJson}
              className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
              title="Export as JSON"
            >
              <FontAwesomeIcon icon={faDownload} className="w-2.5 h-2.5" />
            </button>
          )}
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Checks for exposed version control directories (.git, .svn, .hg, .bzr) that may leak source code.
      </div>

      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
        <div className="text-[10px] text-slate-500">Target Domain</div>
        <div className="text-slate-200 text-[11px] font-mono">
          {window.location.origin}
        </div>
        <div className="text-[9px] text-slate-600 mt-1">
          Checking {VCS_PATHS.length} paths across 4 VCS types
        </div>
      </div>

      <button
        onClick={checkVcsExposure}
        disabled={scanning}
        className="w-full rounded bg-red-600/20 border border-red-500/30 px-2 py-1.5 text-[11px] text-red-300 hover:bg-red-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faSearch} className="w-3 h-3" />
        {scanning ? 'Checking VCS Paths...' : 'Check VCS Exposure'}
      </button>

      {/* VCS Type Filter */}
      {checked && results.length > 0 && (
        <div className="flex items-center gap-2 mb-3 flex-wrap">
          <FontAwesomeIcon icon={faFilter} className="w-2.5 h-2.5 text-slate-500" />
          {(['all', 'git', 'svn', 'hg', 'bzr'] as const).map(vcs => {
            const count = vcs === 'all'
              ? accessibleResults.length
              : accessibleResults.filter(r => r.vcsType === vcs).length;

            return (
              <button
                key={vcs}
                onClick={() => onChange({ ...data, filterVcs: vcs })}
                className={`px-2 py-0.5 rounded text-[9px] transition-colors ${
                  filterVcs === vcs
                    ? 'bg-red-600/30 text-red-300 border border-red-500/50'
                    : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-500'
                }`}
              >
                {vcs === 'all' ? 'All' : VCS_COLORS[vcs].label}
                {count > 0 && <span className="ml-1 text-red-400">({count})</span>}
              </button>
            );
          })}
        </div>
      )}

      {error && (
        <div className="text-red-400 text-[10px] bg-red-900/20 border border-red-500/30 p-2 rounded mb-3">
          {error}
        </div>
      )}

      {scannedAt && (
        <div className="text-[10px] text-slate-500 mb-2">
          Last checked: {new Date(scannedAt).toLocaleTimeString()}
        </div>
      )}

      {checked && (
        <div className={`p-2 rounded mb-3 ${exposed ? 'bg-red-900/20 border border-red-500/30' : 'bg-green-900/20 border border-green-500/30'}`}>
          <div className={`font-medium flex items-center gap-2 text-[11px] ${exposed ? 'text-red-400' : 'text-green-400'}`}>
            <FontAwesomeIcon icon={exposed ? faExclamationTriangle : faCheckCircle} className="w-3 h-3" />
            {exposed ? 'VCS Directory Exposed!' : 'No VCS Exposure Detected'}
          </div>
          <div className="text-[10px] text-slate-300 mt-1">
            {exposed
              ? `Found ${accessibleResults.length} accessible VCS path(s). Source code may be at risk.`
              : `All ${results.length} checked paths returned non-200 status codes.`}
          </div>
          {exposed && (
            <div className="flex gap-2 mt-2 flex-wrap">
              {accessibleResults.filter(r => r.riskLevel === 'critical').length > 0 && (
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-900/50 text-red-400">
                  {accessibleResults.filter(r => r.riskLevel === 'critical').length} Critical
                </span>
              )}
              {accessibleResults.filter(r => r.riskLevel === 'high').length > 0 && (
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-orange-900/50 text-orange-400">
                  {accessibleResults.filter(r => r.riskLevel === 'high').length} High
                </span>
              )}
              {accessibleResults.filter(r => r.riskLevel === 'medium').length > 0 && (
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-yellow-900/50 text-yellow-400">
                  {accessibleResults.filter(r => r.riskLevel === 'medium').length} Medium
                </span>
              )}
            </div>
          )}
        </div>
      )}

      <div className="flex-1 overflow-y-auto space-y-2 min-h-0">
        {/* Accessible Paths (Exposed) */}
        {accessibleResults.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-red-400 text-[11px] font-medium">
              <FontAwesomeIcon icon={faExclamationTriangle} className="w-3 h-3" />
              Exposed Paths ({accessibleResults.length})
            </div>
            <div className="space-y-1">
              {accessibleResults
                .sort((a, b) => {
                  const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
                  return riskOrder[a.riskLevel] - riskOrder[b.riskLevel];
                })
                .map((result, idx) => {
                  const vcsStyle = VCS_COLORS[result.vcsType];
                  const riskStyle = RISK_COLORS[result.riskLevel];
                  return (
                    <div key={idx} className="bg-red-900/20 border border-red-500/30 rounded p-2">
                      <div className="flex justify-between items-start">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-red-400 font-mono text-[10px]">{result.path}</span>
                            <span className={`text-[8px] px-1.5 py-0.5 rounded ${vcsStyle.bg} ${vcsStyle.text}`}>
                              {vcsStyle.label}
                            </span>
                            <span className={`text-[8px] px-1.5 py-0.5 rounded ${riskStyle.bg} ${riskStyle.text}`}>
                              {result.riskLevel}
                            </span>
                          </div>
                          <div className="text-[9px] text-slate-500 mt-1">
                            Status: {result.status} | {result.category}
                            {result.contentType && ` | ${result.contentType}`}
                          </div>
                        </div>
                        <a
                          href={(domain || window.location.origin) + result.path}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[9px] text-slate-500 hover:text-red-400 p-1 flex-shrink-0"
                          title="Open"
                        >
                          <FontAwesomeIcon icon={faExternalLinkAlt} className="w-2.5 h-2.5" />
                        </a>
                      </div>
                    </div>
                  );
                })}
            </div>
          </div>
        )}

        {/* Inaccessible Paths - Collapsed */}
        {inaccessibleResults.length > 0 && checked && (
          <details className="group">
            <summary className="cursor-pointer flex items-center gap-2 text-green-400 text-[11px] font-medium">
              <FontAwesomeIcon icon={faCheckCircle} className="w-3 h-3" />
              Protected Paths ({inaccessibleResults.length})
            </summary>
            <div className="space-y-1 mt-2 max-h-40 overflow-y-auto">
              {inaccessibleResults.slice(0, 20).map((result, idx) => {
                const vcsStyle = VCS_COLORS[result.vcsType];
                return (
                  <div key={idx} className="rounded border border-slate-700 bg-slate-800/50 p-1.5 flex items-center gap-2">
                    <span className="text-slate-400 font-mono text-[9px] flex-1 truncate">{result.path}</span>
                    <span className={`text-[8px] px-1 py-0.5 rounded ${vcsStyle.bg} ${vcsStyle.text}`}>
                      {vcsStyle.label}
                    </span>
                    <span className="text-slate-600 text-[9px]">
                      ({result.status || 'blocked'})
                    </span>
                  </div>
                );
              })}
              {inaccessibleResults.length > 20 && (
                <div className="text-[9px] text-slate-500 text-center py-1">
                  ... and {inaccessibleResults.length - 20} more
                </div>
              )}
            </div>
          </details>
        )}

        {exposed && (
          <div className="bg-yellow-900/20 border border-yellow-500/30 rounded p-2 text-[10px] text-yellow-400">
            <FontAwesomeIcon icon={faExclamationTriangle} className="w-3 h-3 mr-1" />
            <strong>Recommendations:</strong>
            <ul className="mt-1 ml-4 list-disc text-slate-400">
              <li>Block access to VCS directories in your web server config</li>
              <li>Add rules to .htaccess or nginx.conf to deny access</li>
              <li>Consider using tools like git-dumper to assess full exposure</li>
              <li>Remove .git/.svn/.hg/.bzr from production deployments</li>
            </ul>
          </div>
        )}
      </div>

      <div className="text-[10px] text-slate-500 border-t border-slate-700 pt-2 mt-3">
        <div className="flex items-center gap-1">
          <FontAwesomeIcon icon={faCodeBranch} className="w-2.5 h-2.5 text-slate-600" />
          <strong>Supports:</strong>
        </div>
        <div className="text-slate-600 flex gap-2 flex-wrap mt-1">
          <span className="px-1.5 py-0.5 rounded bg-orange-900/30 text-orange-400">Git</span>
          <span className="px-1.5 py-0.5 rounded bg-blue-900/30 text-blue-400">SVN</span>
          <span className="px-1.5 py-0.5 rounded bg-purple-900/30 text-purple-400">Mercurial</span>
          <span className="px-1.5 py-0.5 rounded bg-green-900/30 text-green-400">Bazaar</span>
        </div>
      </div>
    </div>
  );
};

export class GitExposureCheckerTool {
  static Component = GitExposureChecker;
}
