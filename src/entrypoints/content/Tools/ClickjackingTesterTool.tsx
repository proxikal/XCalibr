import React, { useState, useRef } from 'react';

export type ClickjackingTesterData = {
  url?: string;
  tested?: boolean;
  isVulnerable?: boolean;
  error?: string;
  opacity?: number;
};

type Props = {
  data: ClickjackingTesterData | undefined;
  onChange: (data: ClickjackingTesterData) => void;
};

const ClickjackingTester: React.FC<Props> = ({ data, onChange }) => {
  const url = data?.url ?? '';
  const tested = data?.tested ?? false;
  const isVulnerable = data?.isVulnerable ?? false;
  const error = data?.error ?? '';
  const opacity = data?.opacity ?? 50;
  const [loading, setLoading] = useState(false);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  const handleTest = async () => {
    if (!url.trim()) return;

    setLoading(true);
    onChange({ ...data, error: '', tested: false });

    try {
      // First check headers via background script
      const response = await chrome.runtime.sendMessage({
        type: 'xcalibr-fetch-headers',
        payload: { url }
      });

      const headers = response?.headers || {};
      const xFrameOptions = headers['x-frame-options']?.toLowerCase() || '';
      const csp = headers['content-security-policy'] || '';

      // Check for frame protection
      const hasXFrameProtection = xFrameOptions === 'deny' || xFrameOptions === 'sameorigin';
      const hasCSPFrameAncestors = csp.includes('frame-ancestors');

      if (hasXFrameProtection || hasCSPFrameAncestors) {
        onChange({
          ...data,
          tested: true,
          isVulnerable: false,
          error: ''
        });
      } else {
        // Headers don't block - may be vulnerable
        onChange({
          ...data,
          tested: true,
          isVulnerable: true,
          error: ''
        });
      }
    } catch (e) {
      onChange({
        ...data,
        error: e instanceof Error ? e.message : 'Failed to test URL',
        tested: false
      });
    } finally {
      setLoading(false);
    }
  };

  const handleUseCurrentPage = () => {
    onChange({ ...data, url: window.location.href, tested: false });
  };

  return (
    <div className="space-y-4">
      <div className="text-xs text-gray-400">
        Tests if a page can be embedded in an iframe (clickjacking vulnerability).
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Target URL</label>
        <div className="flex gap-2">
          <input
            type="url"
            value={url}
            onChange={(e) => onChange({ ...data, url: e.target.value, tested: false })}
            placeholder="https://example.com"
            className="flex-1 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          />
          <button
            onClick={handleUseCurrentPage}
            className="px-3 py-2 bg-gray-600 hover:bg-gray-500 text-white rounded text-xs"
          >
            Current
          </button>
        </div>
      </div>

      <button
        onClick={handleTest}
        disabled={!url.trim() || loading}
        className="w-full py-2 bg-red-600 hover:bg-red-500 disabled:bg-gray-600 text-white rounded text-sm"
      >
        {loading ? 'Testing...' : 'Test for Clickjacking'}
      </button>

      {error && (
        <div className="text-red-400 text-xs bg-red-900/20 p-2 rounded">
          {error}
        </div>
      )}

      {tested && (
        <div className={`p-3 rounded ${isVulnerable ? 'bg-red-900/30 border border-red-500' : 'bg-green-900/30 border border-green-500'}`}>
          <div className={`font-medium ${isVulnerable ? 'text-red-400' : 'text-green-400'}`}>
            {isVulnerable ? '⚠️ Potentially Vulnerable' : '✅ Protected'}
          </div>
          <div className="text-xs text-gray-300 mt-1">
            {isVulnerable
              ? 'No X-Frame-Options or CSP frame-ancestors header detected. Page may be frameable.'
              : 'X-Frame-Options or CSP frame-ancestors protection detected.'}
          </div>
        </div>
      )}

      {tested && isVulnerable && (
        <div className="space-y-2">
          <div className="flex justify-between items-center">
            <label className="text-xs text-gray-400">Frame Preview (Opacity: {opacity}%)</label>
            <input
              type="range"
              min={10}
              max={100}
              value={opacity}
              onChange={(e) => onChange({ ...data, opacity: parseInt(e.target.value) })}
              className="w-24"
            />
          </div>
          <div className="border border-gray-600 rounded overflow-hidden bg-gray-900" style={{ height: '150px' }}>
            <iframe
              ref={iframeRef}
              src={url}
              style={{ width: '100%', height: '100%', opacity: opacity / 100 }}
              sandbox="allow-scripts allow-same-origin"
              title="Clickjacking Test Frame"
            />
          </div>
          <div className="text-xs text-gray-500">
            If the frame loads, the page is vulnerable to clickjacking attacks.
          </div>
        </div>
      )}

      <div className="text-xs text-gray-500 space-y-1">
        <div><strong>X-Frame-Options:</strong> DENY or SAMEORIGIN blocks framing</div>
        <div><strong>CSP frame-ancestors:</strong> Controls which origins can embed the page</div>
      </div>
    </div>
  );
};

export class ClickjackingTesterTool {
  static Component = ClickjackingTester;
}
