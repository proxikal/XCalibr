import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSearch, faFileAlt, faCheckCircle, faTimesCircle, faExternalLinkAlt, faSpinner } from '@fortawesome/free-solid-svg-icons';

export type MetafileResult = {
  file: string;
  path: string;
  status: number;
  found: boolean;
  contentPreview?: string;
  contentType?: string;
  size?: number;
};

export type MetafileScannerData = {
  results?: MetafileResult[];
  domain?: string;
  scannedAt?: number;
  scanning?: boolean;
  error?: string;
};

type Props = {
  data: MetafileScannerData | undefined;
  onChange: (data: MetafileScannerData) => void;
};

const METAFILES = [
  { file: 'robots.txt', path: '/robots.txt', description: 'Crawler directives' },
  { file: 'sitemap.xml', path: '/sitemap.xml', description: 'Site structure' },
  { file: 'sitemap_index.xml', path: '/sitemap_index.xml', description: 'Sitemap index' },
  { file: 'security.txt', path: '/.well-known/security.txt', description: 'Security contact' },
  { file: 'security.txt (alt)', path: '/security.txt', description: 'Security contact (alt)' },
  { file: 'humans.txt', path: '/humans.txt', description: 'Team credits' },
  { file: 'ads.txt', path: '/ads.txt', description: 'Ad authorization' },
  { file: 'app-ads.txt', path: '/app-ads.txt', description: 'App ad authorization' },
  { file: 'crossdomain.xml', path: '/crossdomain.xml', description: 'Flash cross-domain policy' },
  { file: 'clientaccesspolicy.xml', path: '/clientaccesspolicy.xml', description: 'Silverlight policy' },
  { file: '.well-known/openid-configuration', path: '/.well-known/openid-configuration', description: 'OpenID config' },
  { file: '.well-known/assetlinks.json', path: '/.well-known/assetlinks.json', description: 'Android app links' },
  { file: '.well-known/apple-app-site-association', path: '/.well-known/apple-app-site-association', description: 'iOS app links' },
  { file: 'browserconfig.xml', path: '/browserconfig.xml', description: 'IE/Edge config' },
  { file: 'manifest.json', path: '/manifest.json', description: 'Web app manifest' },
  { file: 'site.webmanifest', path: '/site.webmanifest', description: 'Web app manifest (alt)' },
  { file: 'favicon.ico', path: '/favicon.ico', description: 'Site icon' },
  { file: 'wp-config.php', path: '/wp-config.php', description: 'WordPress config (sensitive!)' },
  { file: 'config.php', path: '/config.php', description: 'PHP config (sensitive!)' },
  { file: '.env', path: '/.env', description: 'Environment file (sensitive!)' },
  { file: 'package.json', path: '/package.json', description: 'Node.js package info' },
  { file: 'composer.json', path: '/composer.json', description: 'PHP Composer info' }
];

const MetafileScanner: React.FC<Props> = ({ data, onChange }) => {
  const results = data?.results ?? [];
  const domain = data?.domain ?? '';
  const scannedAt = data?.scannedAt;
  const scanningState = data?.scanning ?? false;
  const error = data?.error;
  const [progress, setProgress] = useState(0);

  const scanMetafiles = async () => {
    const currentDomain = window.location.origin;
    onChange({ ...data, scanning: true, domain: currentDomain, error: undefined });
    setProgress(0);

    const scanResults: MetafileResult[] = [];

    for (let i = 0; i < METAFILES.length; i++) {
      const meta = METAFILES[i];
      const url = currentDomain + meta.path;

      try {
        // Try fetching through background script to avoid CORS
        const response = await chrome.runtime.sendMessage({
          type: 'xcalibr-fetch-url',
          payload: { url, method: 'GET' }
        });

        const found = response?.status === 200;
        let contentPreview = '';

        if (found && response?.body) {
          // Get first 200 chars as preview
          contentPreview = typeof response.body === 'string'
            ? response.body.substring(0, 200)
            : '';
        }

        scanResults.push({
          file: meta.file,
          path: meta.path,
          status: response?.status || 0,
          found,
          contentPreview: found ? contentPreview : undefined,
          contentType: response?.contentType,
          size: response?.size
        });
      } catch (e) {
        scanResults.push({
          file: meta.file,
          path: meta.path,
          status: 0,
          found: false
        });
      }

      setProgress(Math.round(((i + 1) / METAFILES.length) * 100));

      // Update results progressively
      onChange({
        ...data,
        results: [...scanResults],
        domain: currentDomain,
        scanning: true
      });
    }

    onChange({
      results: scanResults,
      domain: currentDomain,
      scannedAt: Date.now(),
      scanning: false,
      error: undefined
    });
  };

  const foundFiles = results.filter(r => r.found);
  const notFoundFiles = results.filter(r => !r.found);
  const sensitiveFiles = foundFiles.filter(r =>
    r.file.includes('config') || r.file.includes('.env') || r.file.includes('wp-config')
  );

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Metafile Scanner</div>
        <div className="flex gap-2">
          {scannedAt && !scanningState && (
            <span className="text-[10px] text-slate-500">
              {new Date(scannedAt).toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Checks for exposed metafiles like robots.txt, sitemap.xml, security.txt, and potentially sensitive configuration files.
      </div>

      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
        <div className="text-[10px] text-slate-500">Target Domain</div>
        <div className="text-slate-200 text-[11px] font-mono">
          {window.location.origin}
        </div>
      </div>

      <button
        onClick={scanMetafiles}
        disabled={scanningState}
        className="w-full rounded bg-cyan-600/20 border border-cyan-500/30 px-2 py-1.5 text-[11px] text-cyan-300 hover:bg-cyan-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        {scanningState ? (
          <>
            <FontAwesomeIcon icon={faSpinner} className="w-3 h-3 animate-spin" />
            Scanning... {progress}%
          </>
        ) : (
          <>
            <FontAwesomeIcon icon={faSearch} className="w-3 h-3" />
            Scan Metafiles
          </>
        )}
      </button>

      {scanningState && (
        <div className="w-full bg-slate-700 rounded-full h-1.5 mb-3">
          <div
            className="bg-cyan-500 h-1.5 rounded-full transition-all duration-300"
            style={{ width: `${progress}%` }}
          />
        </div>
      )}

      {error && (
        <div className="text-red-400 text-[11px] bg-red-900/20 border border-red-500/30 p-2 rounded mb-3">
          {error}
        </div>
      )}

      {/* Statistics */}
      {results.length > 0 && !scanningState && (
        <div className="grid grid-cols-3 gap-2 text-center mb-3">
          <div className="rounded border border-green-500/30 bg-green-900/20 p-2">
            <div className="text-sm text-green-400 font-bold">{foundFiles.length}</div>
            <div className="text-[10px] text-slate-500">Found</div>
          </div>
          <div className="rounded border border-slate-700 bg-slate-800/30 p-2">
            <div className="text-sm text-slate-400 font-bold">{notFoundFiles.length}</div>
            <div className="text-[10px] text-slate-500">Not Found</div>
          </div>
          <div className={`rounded border p-2 ${sensitiveFiles.length > 0 ? 'bg-red-900/20 border-red-500/30' : 'bg-slate-800/30 border-slate-700'}`}>
            <div className={`text-sm font-bold ${sensitiveFiles.length > 0 ? 'text-red-400' : 'text-slate-400'}`}>
              {sensitiveFiles.length}
            </div>
            <div className="text-[10px] text-slate-500">Sensitive</div>
          </div>
        </div>
      )}

      {/* Found Files */}
      {foundFiles.length > 0 && (
        <div className="flex-1 overflow-y-auto min-h-0 mb-3">
          <div className="flex items-center gap-2 text-green-400 text-[11px] font-medium mb-2">
            <FontAwesomeIcon icon={faCheckCircle} className="w-3 h-3" />
            Found Files ({foundFiles.length})
          </div>
          <div className="space-y-2">
            {foundFiles.map((result, idx) => (
              <div key={idx} className={`rounded border p-2 ${
                result.file.includes('config') || result.file.includes('.env')
                  ? 'bg-red-900/20 border-red-500/30'
                  : 'bg-slate-800/50 border-slate-700'
              }`}>
                <div className="flex justify-between items-center">
                  <div className="flex items-center gap-2">
                    <FontAwesomeIcon icon={faFileAlt} className={`w-2.5 h-2.5 ${
                      result.file.includes('config') || result.file.includes('.env')
                        ? 'text-red-400'
                        : 'text-green-400'
                    }`} />
                    <span className="text-slate-200 text-[11px]">{result.file}</span>
                    <span className="text-slate-500 text-[10px]">({result.status})</span>
                  </div>
                  <a
                    href={domain + result.path}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-slate-500 hover:text-cyan-400 p-1"
                    title="Open file"
                  >
                    <FontAwesomeIcon icon={faExternalLinkAlt} className="w-2.5 h-2.5" />
                  </a>
                </div>
                {result.contentType && (
                  <div className="text-slate-500 text-[10px] mt-1">
                    Type: {result.contentType}
                  </div>
                )}
                {result.contentPreview && (
                  <pre className="text-slate-400 text-[10px] mt-1 bg-slate-900/50 p-1 rounded overflow-hidden whitespace-pre-wrap">
                    {result.contentPreview.substring(0, 100)}...
                  </pre>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Not Found Files (collapsible) */}
      {notFoundFiles.length > 0 && !scanningState && (
        <details className="group mb-3">
          <summary className="flex items-center gap-2 text-slate-500 text-[11px] cursor-pointer">
            <FontAwesomeIcon icon={faTimesCircle} className="w-3 h-3" />
            Not Found ({notFoundFiles.length})
          </summary>
          <div className="mt-2 max-h-24 overflow-y-auto space-y-1">
            {notFoundFiles.map((result, idx) => (
              <div key={idx} className="flex items-center gap-2 text-slate-500 text-[10px]">
                <FontAwesomeIcon icon={faTimesCircle} className="w-2.5 h-2.5 text-slate-600" />
                {result.file}
                <span className="text-slate-600">({result.status || 'N/A'})</span>
              </div>
            ))}
          </div>
        </details>
      )}

      {scannedAt && results.length === 0 && !scanningState && (
        <div className="text-[11px] text-slate-500 text-center py-4">
          No metafiles checked yet.
        </div>
      )}

      <div className="text-[10px] text-slate-500 border-t border-slate-700 pt-2 mt-auto">
        <div><strong>Files checked:</strong></div>
        <div className="text-slate-600">robots.txt, sitemap.xml, security.txt, manifest.json, and {METAFILES.length - 4} more</div>
      </div>
    </div>
  );
};

export class MetafileScannerTool {
  static Component = MetafileScanner;
}
