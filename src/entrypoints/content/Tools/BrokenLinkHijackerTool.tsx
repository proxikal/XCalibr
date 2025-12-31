import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faLink, faExclamationTriangle, faCheckCircle, faSync, faExternalLinkAlt, faSkull } from '@fortawesome/free-solid-svg-icons';

export type BrokenLinkHijackerData = {
  links?: LinkCheckResult[];
  scannedAt?: number;
  isScanning?: boolean;
  progress?: { checked: number; total: number };
  error?: string;
};

export type LinkCheckResult = {
  url: string;
  domain: string;
  status: 'checking' | 'active' | 'expired' | 'error' | 'potential';
  statusCode?: number;
  message?: string;
};

type Props = {
  data: BrokenLinkHijackerData | undefined;
  onChange: (data: BrokenLinkHijackerData) => void;
};

const extractExternalLinks = (): string[] => {
  const links: string[] = [];
  const currentDomain = window.location.hostname;

  document.querySelectorAll('a[href]').forEach((anchor) => {
    const href = (anchor as HTMLAnchorElement).href;
    try {
      const url = new URL(href);
      if (url.hostname && url.hostname !== currentDomain && url.protocol.startsWith('http')) {
        if (!links.includes(href)) {
          links.push(href);
        }
      }
    } catch {
      // Invalid URL, skip
    }
  });

  return links;
};

const BrokenLinkHijacker: React.FC<Props> = ({ data, onChange }) => {
  const links = data?.links ?? [];
  const scannedAt = data?.scannedAt;
  const isScanning = data?.isScanning ?? false;
  const progress = data?.progress;
  const error = data?.error ?? '';
  const [checkOnline, setCheckOnline] = useState(false);

  const handleScan = async () => {
    onChange({ ...data, isScanning: true, error: '', links: [] });

    try {
      const externalLinks = extractExternalLinks();

      if (externalLinks.length === 0) {
        onChange({
          links: [],
          scannedAt: Date.now(),
          isScanning: false,
          error: 'No external links found on this page'
        });
        return;
      }

      const results: LinkCheckResult[] = externalLinks.map(url => {
        const domain = new URL(url).hostname;
        return {
          url,
          domain,
          status: checkOnline ? 'checking' : 'potential',
          message: checkOnline ? 'Checking...' : 'Domain status unknown - check manually'
        };
      });

      onChange({
        links: results,
        scannedAt: Date.now(),
        isScanning: false,
        progress: { checked: externalLinks.length, total: externalLinks.length }
      });

      // If online check is enabled, attempt to verify domains
      if (checkOnline) {
        for (let i = 0; i < results.length; i++) {
          try {
            const response = await chrome.runtime.sendMessage({
              type: 'xcalibr-fetch-headers',
              payload: { url: results[i].url }
            });

            results[i].status = response?.status ? 'active' : 'error';
            results[i].statusCode = response?.status;
            results[i].message = response?.status ? `HTTP ${response.status}` : 'Unable to reach';
          } catch {
            results[i].status = 'error';
            results[i].message = 'Check failed';
          }

          onChange({
            links: [...results],
            scannedAt: Date.now(),
            isScanning: i < results.length - 1,
            progress: { checked: i + 1, total: results.length }
          });
        }
      }
    } catch (e) {
      onChange({
        ...data,
        isScanning: false,
        error: e instanceof Error ? e.message : 'Failed to scan links'
      });
    }
  };

  const expiredDomainPatterns = [
    'expired', 'parked', 'forsale', 'buy this domain',
    'domain for sale', 'this domain', 'hugedomains',
    'godaddy', 'afternic', 'sedo'
  ];

  const getPotentialHijackScore = (result: LinkCheckResult): 'high' | 'medium' | 'low' => {
    if (result.status === 'expired') return 'high';
    if (result.status === 'error' || result.statusCode === 404) return 'medium';
    return 'low';
  };

  const scoreColors = {
    high: 'border-red-500/50 bg-red-900/20',
    medium: 'border-yellow-500/50 bg-yellow-900/20',
    low: 'border-slate-700 bg-slate-800/50'
  };

  const statusIcons = {
    checking: faSync,
    active: faCheckCircle,
    expired: faSkull,
    error: faExclamationTriangle,
    potential: faExternalLinkAlt
  };

  const statusColors = {
    checking: 'text-blue-400',
    active: 'text-green-400',
    expired: 'text-red-400',
    error: 'text-yellow-400',
    potential: 'text-slate-400'
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Broken Link Hijacker</div>
        <div className="flex gap-2">
          <label className="flex items-center gap-1 text-[10px] text-slate-400">
            <input
              type="checkbox"
              checked={checkOnline}
              onChange={(e) => setCheckOnline(e.target.checked)}
              className="rounded"
            />
            Verify online
          </label>
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Finds external links that could potentially be hijacked (expired domains, broken links).
      </div>

      <button
        onClick={handleScan}
        disabled={isScanning}
        className="w-full rounded bg-red-600/20 border border-red-500/30 px-2 py-1.5 text-[11px] text-red-300 hover:bg-red-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faLink} className={`w-3 h-3 ${isScanning ? 'animate-pulse' : ''}`} />
        {isScanning ? 'Scanning...' : 'Scan External Links'}
      </button>

      {progress && isScanning && (
        <div className="text-[10px] text-slate-400 mb-3">
          Checking {progress.checked} of {progress.total} links...
        </div>
      )}

      {error && (
        <div className="rounded border border-yellow-500/30 bg-yellow-900/20 p-2 mb-3 flex items-center gap-2 text-[10px] text-yellow-400">
          <FontAwesomeIcon icon={faExclamationTriangle} className="w-3 h-3" />
          {error}
        </div>
      )}

      {scannedAt && !isScanning && (
        <div className="text-[10px] text-slate-500 mb-2">
          Scanned: {new Date(scannedAt).toLocaleTimeString()} - Found {links.length} external link(s)
        </div>
      )}

      {links.length > 0 && (
        <div className="flex-1 overflow-y-auto space-y-2 min-h-0">
          {links.map((link, index) => {
            const score = getPotentialHijackScore(link);
            return (
              <div
                key={index}
                className={`rounded border p-2 ${scoreColors[score]}`}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2 text-[11px] font-medium text-slate-200 truncate max-w-[200px]">
                    <FontAwesomeIcon
                      icon={statusIcons[link.status]}
                      className={`w-3 h-3 ${statusColors[link.status]} ${link.status === 'checking' ? 'animate-spin' : ''}`}
                    />
                    {link.domain}
                  </div>
                  <span className={`text-[10px] ${statusColors[link.status]}`}>
                    {link.status.toUpperCase()}
                  </span>
                </div>
                <div className="text-[10px] text-slate-400 truncate">{link.url}</div>
                {link.message && (
                  <div className="text-[10px] text-slate-500 mt-1">{link.message}</div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {links.length === 0 && !isScanning && !error && (
        <div className="text-[11px] text-slate-500 text-center py-4">
          Click scan to find external links on this page.
        </div>
      )}

      <div className="text-[10px] text-slate-500 space-y-1 border-t border-slate-700 pt-3 mt-3">
        <div><strong>Broken Link Hijacking:</strong> Attackers register expired domains</div>
        <div><strong>Risk:</strong> Can inject malicious content via old external links</div>
        <div><strong>Check:</strong> Verify domain ownership of external resources</div>
      </div>
    </div>
  );
};

export class BrokenLinkHijackerTool {
  static Component = BrokenLinkHijacker;
}
