import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSearch, faExclamationTriangle, faCheckCircle, faCopy, faExternalLinkAlt } from '@fortawesome/free-solid-svg-icons';

export type SourceMapDetectorData = {
  sourceMaps?: SourceMapEntry[];
  scannedAt?: number;
  isScanning?: boolean;
  error?: string;
};

type SourceMapEntry = {
  url: string;
  scriptUrl: string;
  size?: number;
  accessible?: boolean;
};

type Props = {
  data: SourceMapDetectorData | undefined;
  onChange: (data: SourceMapDetectorData) => void;
};

const SourceMapDetector: React.FC<Props> = ({ data, onChange }) => {
  const sourceMaps = data?.sourceMaps ?? [];
  const scannedAt = data?.scannedAt;
  const isScanning = data?.isScanning ?? false;
  const error = data?.error ?? '';
  const [copied, setCopied] = useState<string | null>(null);

  const handleScan = async () => {
    onChange({ ...data, isScanning: true, error: '' });

    try {
      const scripts = Array.from(document.querySelectorAll('script[src]'));
      const foundMaps: SourceMapEntry[] = [];

      for (const script of scripts) {
        const src = (script as HTMLScriptElement).src;
        if (!src) continue;

        // Check for sourceMappingURL in script content or .map extension
        const mapUrl = src + '.map';

        try {
          const response = await fetch(mapUrl, { method: 'HEAD' });
          if (response.ok) {
            foundMaps.push({
              url: mapUrl,
              scriptUrl: src,
              accessible: true
            });
          }
        } catch {
          // Source map not accessible
        }

        // Also check inline scripts for sourceMappingURL comments
        try {
          const scriptResponse = await fetch(src);
          const content = await scriptResponse.text();
          const match = content.match(/\/\/[#@]\s*sourceMappingURL=(.+?)(?:\s|$)/);
          if (match) {
            const resolvedUrl = new URL(match[1], src).href;
            if (!foundMaps.some(m => m.url === resolvedUrl)) {
              try {
                const mapResponse = await fetch(resolvedUrl, { method: 'HEAD' });
                foundMaps.push({
                  url: resolvedUrl,
                  scriptUrl: src,
                  accessible: mapResponse.ok
                });
              } catch {
                foundMaps.push({
                  url: resolvedUrl,
                  scriptUrl: src,
                  accessible: false
                });
              }
            }
          }
        } catch {
          // Could not fetch script content
        }
      }

      onChange({
        ...data,
        sourceMaps: foundMaps,
        scannedAt: Date.now(),
        isScanning: false,
        error: ''
      });
    } catch (e) {
      onChange({
        ...data,
        isScanning: false,
        error: e instanceof Error ? e.message : 'Failed to scan for source maps'
      });
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(text);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Source Map Detector</div>
        <div className="flex gap-2">
          {scannedAt && !isScanning && (
            <span className="text-[10px] text-slate-500">
              {new Date(scannedAt).toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Detects exposed JavaScript source maps on the page. Source maps can reveal original source code.
      </div>

      <button
        onClick={handleScan}
        disabled={isScanning}
        className="w-full rounded bg-orange-600/20 border border-orange-500/30 px-2 py-1.5 text-[11px] text-orange-300 hover:bg-orange-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faSearch} className="w-3 h-3" />
        {isScanning ? 'Scanning...' : 'Scan for Source Maps'}
      </button>

      {error && (
        <div className="text-red-400 text-[11px] bg-red-900/20 border border-red-500/30 p-2 rounded mb-3">
          {error}
        </div>
      )}

      {scannedAt && !isScanning && (
        <div className="flex-1 overflow-y-auto min-h-0">
          {sourceMaps.length > 0 ? (
            <div className="rounded border border-red-500/30 bg-red-900/20 p-2 mb-3">
              <div className="flex items-center gap-2 text-red-400 font-medium text-[11px] mb-1">
                <FontAwesomeIcon icon={faExclamationTriangle} className="w-3 h-3" />
                <span>{sourceMaps.length} Source Map(s) Found</span>
              </div>
              <div className="text-[10px] text-slate-400">
                Source maps expose original source code and should not be publicly accessible in production.
              </div>
            </div>
          ) : (
            <div className="rounded border border-green-500/30 bg-green-900/20 p-2 mb-3">
              <div className="flex items-center gap-2 text-green-400 font-medium text-[11px]">
                <FontAwesomeIcon icon={faCheckCircle} className="w-3 h-3" />
                <span>No Source Maps Detected</span>
              </div>
              <div className="text-[10px] text-slate-400 mt-1">
                No publicly accessible source maps were found.
              </div>
            </div>
          )}

          {sourceMaps.length > 0 && (
            <div className="space-y-2">
              {sourceMaps.map((map, index) => (
                <div key={index} className="rounded border border-slate-700 bg-slate-800/50 p-2">
                  <div className="flex items-center justify-between mb-1">
                    <span className={`font-medium text-[10px] ${map.accessible ? 'text-red-400' : 'text-yellow-400'}`}>
                      {map.accessible ? 'Accessible' : 'Referenced'}
                    </span>
                    <div className="flex gap-1">
                      <button
                        onClick={() => handleCopy(map.url)}
                        className="text-[9px] text-slate-500 hover:text-slate-300 p-1"
                        title="Copy URL"
                      >
                        <FontAwesomeIcon icon={faCopy} className="w-2.5 h-2.5" />
                      </button>
                      <a
                        href={map.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-[9px] text-slate-500 hover:text-slate-300 p-1"
                        title="Open in new tab"
                      >
                        <FontAwesomeIcon icon={faExternalLinkAlt} className="w-2.5 h-2.5" />
                      </a>
                    </div>
                  </div>
                  <div className="text-slate-300 text-[10px] break-all">{map.url}</div>
                  <div className="text-slate-500 mt-1 text-[9px] break-all">Script: {map.scriptUrl}</div>
                  {copied === map.url && (
                    <div className="text-green-400 text-[9px] mt-1">Copied!</div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="text-[10px] text-slate-500 space-y-1 border-t border-slate-700 pt-2 mt-3">
        <div><strong>Security Risk:</strong> Source maps can reveal:</div>
        <ul className="list-disc list-inside ml-2 space-y-0.5 text-slate-600">
          <li>Original unminified source code</li>
          <li>Variable and function names</li>
          <li>Comments and documentation</li>
          <li>Application structure and logic</li>
        </ul>
      </div>
    </div>
  );
};

export class SourceMapDetectorTool {
  static Component = SourceMapDetector;
}
