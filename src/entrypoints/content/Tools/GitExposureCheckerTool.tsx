import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSearch, faCodeBranch, faExclamationTriangle, faCheckCircle, faExternalLinkAlt } from '@fortawesome/free-solid-svg-icons';

export type GitCheckResult = {
  path: string;
  status: number;
  accessible: boolean;
  contentType?: string;
};

export type GitExposureCheckerData = {
  checked?: boolean;
  exposed?: boolean;
  results?: GitCheckResult[];
  domain?: string;
  scannedAt?: number;
  error?: string;
};

type Props = {
  data: GitExposureCheckerData | undefined;
  onChange: (data: GitExposureCheckerData) => void;
};

const GIT_PATHS = [
  '/.git/HEAD',
  '/.git/config',
  '/.git/index',
  '/.git/logs/HEAD',
  '/.git/refs/heads/master',
  '/.git/refs/heads/main',
  '/.git/COMMIT_EDITMSG',
  '/.git/description',
  '/.git/info/exclude'
];

const GitExposureChecker: React.FC<Props> = ({ data, onChange }) => {
  const checked = data?.checked ?? false;
  const exposed = data?.exposed ?? false;
  const results = data?.results ?? [];
  const domain = data?.domain ?? '';
  const scannedAt = data?.scannedAt;
  const error = data?.error;
  const [scanning, setScanning] = useState(false);

  const checkGitExposure = async () => {
    setScanning(true);
    const currentDomain = window.location.origin;

    try {
      const checkResults: GitCheckResult[] = [];
      let anyExposed = false;

      // Check all git paths in parallel
      const checks = await Promise.allSettled(
        GIT_PATHS.map(async (path) => {
          try {
            const response = await fetch(currentDomain + path, {
              method: 'HEAD',
              mode: 'no-cors'
            });

            // In no-cors mode, we can't read the status, so try with cors
            try {
              const corsResponse = await fetch(currentDomain + path, {
                method: 'GET',
                cache: 'no-cache'
              });

              const accessible = corsResponse.status === 200;
              if (accessible) anyExposed = true;

              return {
                path,
                status: corsResponse.status,
                accessible,
                contentType: corsResponse.headers.get('content-type') || undefined
              };
            } catch {
              // CORS blocked, try through background script
              const bgResponse = await chrome.runtime.sendMessage({
                type: 'xcalibr-fetch-url',
                payload: { url: currentDomain + path, method: 'HEAD' }
              });

              const accessible = bgResponse?.status === 200;
              if (accessible) anyExposed = true;

              return {
                path,
                status: bgResponse?.status || 0,
                accessible,
                contentType: bgResponse?.contentType
              };
            }
          } catch (e) {
            return {
              path,
              status: 0,
              accessible: false
            };
          }
        })
      );

      checks.forEach((result) => {
        if (result.status === 'fulfilled') {
          checkResults.push(result.value);
        }
      });

      onChange({
        checked: true,
        exposed: anyExposed,
        results: checkResults,
        domain: currentDomain,
        scannedAt: Date.now(),
        error: undefined
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

  const accessibleResults = results.filter(r => r.accessible);
  const inaccessibleResults = results.filter(r => !r.accessible);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Git Exposure Checker</div>
        <div className="flex gap-2">
          <button
            onClick={checkGitExposure}
            disabled={scanning}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors flex items-center gap-1 disabled:opacity-50"
          >
            <FontAwesomeIcon icon={faSearch} className="w-3 h-3" />
            {scanning ? 'Checking...' : 'Check'}
          </button>
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Checks for exposed .git directories on the current domain which may leak source code.
      </div>

      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
        <div className="text-[10px] text-slate-500">Target Domain</div>
        <div className="text-slate-200 text-[11px] font-mono">
          {window.location.origin}
        </div>
      </div>

      <button
        onClick={checkGitExposure}
        disabled={scanning}
        className="w-full rounded bg-red-600/20 border border-red-500/30 px-2 py-1.5 text-[11px] text-red-300 hover:bg-red-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faSearch} className="w-3 h-3" />
        {scanning ? 'Checking...' : 'Check Git Exposure'}
      </button>

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
            {exposed ? 'Git Directory Exposed!' : 'No Git Exposure Detected'}
          </div>
          <div className="text-[10px] text-slate-300 mt-1">
            {exposed
              ? `Found ${accessibleResults.length} accessible git path(s). Source code may be at risk.`
              : 'All checked .git paths returned non-200 status codes.'}
          </div>
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
              {accessibleResults.map((result, idx) => (
                <div key={idx} className="bg-red-900/20 border border-red-500/30 rounded p-2 flex justify-between items-center">
                  <div>
                    <span className="text-red-400 font-mono text-[10px]">{result.path}</span>
                    <div className="text-[9px] text-slate-500">
                      Status: {result.status} {result.contentType && `| ${result.contentType}`}
                    </div>
                  </div>
                  <a
                    href={domain + result.path}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[9px] text-slate-500 hover:text-red-400 p-1"
                    title="Open"
                  >
                    <FontAwesomeIcon icon={faExternalLinkAlt} className="w-2.5 h-2.5" />
                  </a>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Inaccessible Paths */}
        {inaccessibleResults.length > 0 && checked && (
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-green-400 text-[11px] font-medium">
              <FontAwesomeIcon icon={faCheckCircle} className="w-3 h-3" />
              Protected Paths ({inaccessibleResults.length})
            </div>
            <div className="space-y-1">
              {inaccessibleResults.map((result, idx) => (
                <div key={idx} className="rounded border border-slate-700 bg-slate-800/50 p-2">
                  <span className="text-slate-400 font-mono text-[10px]">{result.path}</span>
                  <span className="text-slate-600 text-[9px] ml-2">
                    ({result.status || 'blocked'})
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {exposed && (
          <div className="bg-yellow-900/20 border border-yellow-500/30 rounded p-2 text-[10px] text-yellow-400">
            <FontAwesomeIcon icon={faExclamationTriangle} className="w-3 h-3 mr-1" />
            <strong>Recommendation:</strong> Block access to .git directories in your web server configuration.
          </div>
        )}
      </div>

      <div className="text-[10px] text-slate-500 border-t border-slate-700 pt-2 mt-3">
        <div className="flex items-center gap-1">
          <FontAwesomeIcon icon={faCodeBranch} className="w-2.5 h-2.5 text-slate-600" />
          <strong>Checks for:</strong>
        </div>
        <div className="text-slate-600">.git/HEAD, .git/config, .git/index, and other git metadata files</div>
      </div>
    </div>
  );
};

export class GitExposureCheckerTool {
  static Component = GitExposureChecker;
}
