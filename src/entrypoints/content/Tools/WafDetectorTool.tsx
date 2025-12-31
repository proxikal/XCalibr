import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faShieldAlt, faSearch, faCheckCircle, faTimesCircle } from '@fortawesome/free-solid-svg-icons';

export type WafSignature = {
  name: string;
  detected: boolean;
  indicators: string[];
};

export type WafDetectorData = {
  url?: string;
  signatures?: WafSignature[];
  detectedWaf?: string | null;
  isScanning?: boolean;
  scannedAt?: number;
  error?: string;
};

type Props = {
  data: WafDetectorData | undefined;
  onChange: (data: WafDetectorData) => void;
};

const WAF_SIGNATURES: { name: string; headers: string[]; cookies: string[]; bodyPatterns: string[] }[] = [
  {
    name: 'Cloudflare',
    headers: ['cf-ray', 'cf-cache-status', 'cf-request-id', 'server: cloudflare'],
    cookies: ['__cfduid', '__cf_bm', 'cf_clearance'],
    bodyPatterns: ['cloudflare', 'cf-browser-verification', 'checking your browser']
  },
  {
    name: 'AWS WAF',
    headers: ['x-amzn-requestid', 'x-amz-cf-id', 'x-amz-cf-pop'],
    cookies: ['awsalb', 'awsalbcors'],
    bodyPatterns: ['awswaf', 'aws waf']
  },
  {
    name: 'Akamai',
    headers: ['akamai-origin-hop', 'x-akamai-session-info', 'x-akamai-transformed'],
    cookies: ['akamai', '_abck', 'bm_sz'],
    bodyPatterns: ['akamai', 'ghost technology']
  },
  {
    name: 'Imperva/Incapsula',
    headers: ['x-cdn', 'x-iinfo'],
    cookies: ['visid_incap', 'incap_ses', 'nlbi_'],
    bodyPatterns: ['incapsula', 'imperva', '_incapsula_resource']
  },
  {
    name: 'Sucuri',
    headers: ['x-sucuri-id', 'x-sucuri-cache', 'server: sucuri'],
    cookies: ['sucuri_cloudproxy'],
    bodyPatterns: ['sucuri', 'sucuri cloudproxy', 'access denied - sucuri']
  },
  {
    name: 'ModSecurity',
    headers: ['server: mod_security', 'x-mod-pagespeed'],
    cookies: [],
    bodyPatterns: ['mod_security', 'modsecurity', 'not acceptable']
  },
  {
    name: 'F5 BIG-IP',
    headers: ['x-cnection', 'x-wa-info'],
    cookies: ['bigipserver', 'f5_cspm', 'ts'],
    bodyPatterns: ['f5 networks', 'big-ip']
  },
  {
    name: 'Barracuda',
    headers: ['server: barracuda'],
    cookies: ['barra_counter_session', 'bNVR'],
    bodyPatterns: ['barracuda', 'barracuda networks']
  },
  {
    name: 'Fastly',
    headers: ['x-served-by', 'x-cache', 'fastly-io-info', 'x-fastly-request-id'],
    cookies: [],
    bodyPatterns: ['fastly error']
  },
  {
    name: 'DDoS-Guard',
    headers: ['server: ddos-guard'],
    cookies: ['__ddg1', '__ddg2'],
    bodyPatterns: ['ddos-guard']
  },
];

const WafDetector: React.FC<Props> = ({ data, onChange }) => {
  const url = data?.url ?? '';
  const signatures = data?.signatures ?? [];
  const detectedWaf = data?.detectedWaf;
  const isScanning = data?.isScanning ?? false;
  const scannedAt = data?.scannedAt;
  const error = data?.error;

  const detectWaf = async () => {
    if (!url.trim()) return;

    onChange({ ...data, isScanning: true, error: '', signatures: [], detectedWaf: null });

    try {
      // Use background script to fetch headers
      const response = await chrome.runtime.sendMessage({
        type: 'xcalibr-fetch-headers',
        payload: { url }
      });

      if (response?.error) {
        onChange({ ...data, isScanning: false, error: response.error });
        return;
      }

      const headers = response?.headers || {};
      const headerStr = JSON.stringify(headers).toLowerCase();

      // Get cookies from the response
      const cookieHeader = headers['set-cookie'] || '';

      // Analyze signatures
      const detectedSignatures: WafSignature[] = [];
      let firstDetected: string | null = null;

      for (const sig of WAF_SIGNATURES) {
        const indicators: string[] = [];

        // Check headers
        for (const h of sig.headers) {
          if (headerStr.includes(h.toLowerCase())) {
            indicators.push(`Header: ${h}`);
          }
        }

        // Check cookies
        for (const c of sig.cookies) {
          if (cookieHeader.toLowerCase().includes(c.toLowerCase())) {
            indicators.push(`Cookie: ${c}`);
          }
        }

        const detected = indicators.length > 0;
        if (detected && !firstDetected) {
          firstDetected = sig.name;
        }

        detectedSignatures.push({
          name: sig.name,
          detected,
          indicators
        });
      }

      onChange({
        ...data,
        isScanning: false,
        signatures: detectedSignatures,
        detectedWaf: firstDetected,
        scannedAt: Date.now()
      });
    } catch (e) {
      onChange({
        ...data,
        isScanning: false,
        error: e instanceof Error ? e.message : 'Detection failed'
      });
    }
  };

  const useCurrentUrl = () => {
    onChange({ ...data, url: window.location.origin });
  };

  const detectedCount = signatures.filter(s => s.detected).length;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">WAF Detector</div>
        <div className="flex gap-2">
          <button
            onClick={useCurrentUrl}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Current URL
          </button>
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Detects Web Application Firewalls (WAF) by analyzing response headers and cookies.
      </div>

      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
        <div className="text-[10px] text-slate-500 mb-1">Target URL</div>
        <input
          type="url"
          value={url}
          onChange={(e) => onChange({ ...data, url: e.target.value })}
          placeholder="https://example.com"
          className="w-full rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-purple-500"
        />
      </div>

      <button
        onClick={detectWaf}
        disabled={!url.trim() || isScanning}
        className="w-full rounded bg-purple-600/20 border border-purple-500/30 px-2 py-1.5 text-[11px] text-purple-300 hover:bg-purple-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faSearch} className={`w-3 h-3 ${isScanning ? 'animate-spin' : ''}`} />
        {isScanning ? 'Detecting...' : 'Detect WAF'}
      </button>

      {error && (
        <div className="text-red-400 text-[10px] bg-red-900/20 border border-red-700/50 p-2 rounded mb-3">
          {error}
        </div>
      )}

      {detectedWaf && (
        <div className="bg-yellow-900/30 border border-yellow-500/50 rounded p-2 mb-3">
          <div className="flex items-center gap-2 text-yellow-400 font-medium text-[11px]">
            <FontAwesomeIcon icon={faShieldAlt} className="w-3 h-3" />
            WAF Detected: {detectedWaf}
          </div>
          <div className="text-[10px] text-slate-400 mt-1">
            This site appears to be protected by {detectedWaf}.
          </div>
        </div>
      )}

      {signatures.length > 0 && !detectedWaf && (
        <div className="bg-green-900/20 border border-green-700/50 rounded p-2 mb-3">
          <div className="flex items-center gap-2 text-green-400 font-medium text-[11px]">
            <FontAwesomeIcon icon={faCheckCircle} className="w-3 h-3" />
            No WAF Detected
          </div>
          <div className="text-[10px] text-slate-400 mt-1">
            No common WAF signatures found in the response.
          </div>
        </div>
      )}

      {signatures.length > 0 && (
        <div className="mb-2">
          <div className="text-[10px] font-medium text-slate-300 mb-2">
            Signature Analysis ({detectedCount}/{signatures.length} matched):
          </div>
        </div>
      )}

      <div className="flex-1 overflow-y-auto space-y-1 min-h-0">
        {signatures.length > 0 ? (
          signatures.map((sig, i) => (
            <div
              key={i}
              className={`rounded border p-2 text-[10px] ${
                sig.detected
                  ? 'bg-yellow-900/20 border-yellow-600/50'
                  : 'bg-slate-800/50 border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className={sig.detected ? 'text-yellow-400' : 'text-slate-400'}>
                  {sig.name}
                </span>
                <FontAwesomeIcon
                  icon={sig.detected ? faCheckCircle : faTimesCircle}
                  className={`w-2.5 h-2.5 ${sig.detected ? 'text-yellow-400' : 'text-slate-600'}`}
                />
              </div>
              {sig.detected && sig.indicators.length > 0 && (
                <div className="mt-1 text-slate-500 text-[9px]">
                  {sig.indicators.join(', ')}
                </div>
              )}
            </div>
          ))
        ) : (
          <div className="text-[11px] text-slate-500 text-center py-4">
            Enter a URL and click "Detect WAF" to scan.
          </div>
        )}
      </div>

      {scannedAt && (
        <div className="text-[10px] text-slate-500 text-center mt-3 pt-2 border-t border-slate-700">
          Scanned at {new Date(scannedAt).toLocaleTimeString()}
        </div>
      )}
    </div>
  );
};

export class WafDetectorTool {
  static Component = WafDetector;
}
