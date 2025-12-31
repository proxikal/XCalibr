import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faExternalLinkAlt, faPlay, faCopy, faCheck, faExclamationTriangle } from '@fortawesome/free-solid-svg-icons';

export type OpenRedirectTesterData = {
  targetUrl?: string;
  paramName?: string;
  results?: {
    payload: string;
    testUrl: string;
    vulnerable: boolean;
  }[];
  isRunning?: boolean;
};

type Props = {
  data: OpenRedirectTesterData | undefined;
  onChange: (data: OpenRedirectTesterData) => void;
};

const REDIRECT_PAYLOADS = [
  '//evil.com',
  '///evil.com',
  '////evil.com',
  '/\\evil.com',
  '\\/evil.com',
  'https://evil.com',
  'http://evil.com',
  '//evil.com/%2f..',
  '//evil.com/%2F..',
  '//%0d%0aevil.com',
  '//evil%00.com',
  '//evil.com?',
  '//evil.com#',
  'https:evil.com',
  '//google.com%40evil.com',
  '//evil.com%252f',
  'javascript:alert(1)',
  'data:text/html,<script>alert(1)</script>',
  '/%09/evil.com',
  '/%5cevil.com',
];

const OpenRedirectTester: React.FC<Props> = ({ data, onChange }) => {
  const targetUrl = data?.targetUrl ?? '';
  const paramName = data?.paramName ?? 'url';
  const results = data?.results ?? [];
  const isRunning = data?.isRunning ?? false;
  const [copied, setCopied] = useState<string | null>(null);

  const buildTestUrl = (baseUrl: string, param: string, payload: string): string => {
    try {
      const url = new URL(baseUrl);
      url.searchParams.set(param, payload);
      return url.toString();
    } catch {
      // If URL parsing fails, try simple concatenation
      const separator = baseUrl.includes('?') ? '&' : '?';
      return `${baseUrl}${separator}${param}=${encodeURIComponent(payload)}`;
    }
  };

  const runTests = async () => {
    if (!targetUrl.trim()) return;

    onChange({ ...data, isRunning: true, results: [] });

    const newResults: OpenRedirectTesterData['results'] = [];

    for (const payload of REDIRECT_PAYLOADS) {
      const testUrl = buildTestUrl(targetUrl, paramName, payload);
      // We can't actually test redirects from content script,
      // but we can generate the URLs for manual testing
      newResults.push({
        payload,
        testUrl,
        vulnerable: false // Would need actual request to determine
      });
      await new Promise(resolve => setTimeout(resolve, 50));
    }

    onChange({ ...data, isRunning: false, results: newResults });
  };

  const useCurrentUrl = () => {
    onChange({ ...data, targetUrl: window.location.href });
  };

  const copyUrl = (url: string) => {
    navigator.clipboard.writeText(url);
    setCopied(url);
    setTimeout(() => setCopied(null), 2000);
  };

  const openInNewTab = (url: string) => {
    window.open(url, '_blank', 'noopener,noreferrer');
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Open Redirect Tester</div>
        <div className="flex gap-2">
          <button
            onClick={useCurrentUrl}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Use Current URL
          </button>
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Tests URLs for open redirect vulnerabilities using common bypass payloads.
      </div>

      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
        <div className="text-[10px] text-slate-500 mb-1">Target URL</div>
        <input
          type="url"
          value={targetUrl}
          onChange={(e) => onChange({ ...data, targetUrl: e.target.value })}
          placeholder="https://example.com/redirect"
          className="w-full rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-red-500 mb-2"
        />
        <div className="text-[10px] text-slate-500 mb-1">Redirect Parameter Name</div>
        <input
          type="text"
          value={paramName}
          onChange={(e) => onChange({ ...data, paramName: e.target.value })}
          placeholder="url, redirect, next, return, etc."
          className="w-full rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-red-500"
        />
      </div>

      <button
        onClick={runTests}
        disabled={!targetUrl.trim() || isRunning}
        className="w-full rounded bg-red-600/20 border border-red-500/30 px-2 py-1.5 text-[11px] text-red-300 hover:bg-red-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faPlay} className={`w-3 h-3 ${isRunning ? 'animate-spin' : ''}`} />
        {isRunning ? 'Generating...' : 'Generate Test URLs'}
      </button>

      {results.length > 0 && (
        <div className="flex-1 overflow-y-auto min-h-0">
          <div className="text-[11px] font-medium text-slate-300 mb-2">
            Generated Test URLs ({results.length} payloads):
          </div>
          <div className="space-y-1">
            {results.map((r, i) => (
              <div
                key={i}
                className="rounded border border-slate-700 bg-slate-800/50 p-2"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-slate-400 text-[10px] truncate">{r.payload}</span>
                  <div className="flex gap-1">
                    <button
                      onClick={() => copyUrl(r.testUrl)}
                      className="text-[9px] text-slate-500 hover:text-slate-300 p-1"
                      title="Copy URL"
                    >
                      <FontAwesomeIcon icon={copied === r.testUrl ? faCheck : faCopy} className="w-2.5 h-2.5" />
                    </button>
                    <button
                      onClick={() => openInNewTab(r.testUrl)}
                      className="text-[9px] text-slate-500 hover:text-slate-300 p-1"
                      title="Open in new tab"
                    >
                      <FontAwesomeIcon icon={faExternalLinkAlt} className="w-2.5 h-2.5" />
                    </button>
                  </div>
                </div>
                <div className="text-slate-500 truncate text-[9px]">{r.testUrl}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="text-[10px] text-slate-500 space-y-1 border-t border-slate-700 pt-2 mt-3">
        <div className="flex items-start gap-1">
          <FontAwesomeIcon icon={faExclamationTriangle} className="text-yellow-500 mt-0.5 w-2.5 h-2.5" />
          <span>Open each URL manually to test. If redirected to evil.com, the endpoint is vulnerable.</span>
        </div>
        <div>Common vulnerable parameters: url, redirect, next, return, goto, dest, continue</div>
      </div>
    </div>
  );
};

export class OpenRedirectTesterTool {
  static Component = OpenRedirectTester;
}
