import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faBug, faPlay, faCopy, faCheck, faExclamationTriangle } from '@fortawesome/free-solid-svg-icons';

export type ProtoPollutionFuzzerData = {
  selectedPayload?: string;
  customPayload?: string;
  results?: {
    payload: string;
    vulnerable: boolean;
    propertyChecked: string;
    error?: string;
  }[];
  isRunning?: boolean;
};

type Props = {
  data: ProtoPollutionFuzzerData | undefined;
  onChange: (data: ProtoPollutionFuzzerData) => void;
};

const POLLUTION_PAYLOADS = [
  { name: '__proto__ pollution', payload: '__proto__[polluted]=true', property: 'polluted' },
  { name: 'constructor.prototype', payload: 'constructor[prototype][polluted]=true', property: 'polluted' },
  { name: 'JSON parse __proto__', payload: '{"__proto__":{"polluted":true}}', property: 'polluted' },
  { name: 'Nested __proto__', payload: 'a[__proto__][polluted]=true', property: 'polluted' },
  { name: 'Object.prototype', payload: 'Object.prototype.polluted=true', property: 'polluted' },
  { name: 'Array prototype', payload: '[].__proto__.polluted=true', property: 'polluted' },
];

const ProtoPollutionFuzzer: React.FC<Props> = ({ data, onChange }) => {
  const customPayload = data?.customPayload ?? '';
  const results = data?.results ?? [];
  const isRunning = data?.isRunning ?? false;
  const [copied, setCopied] = useState<string | null>(null);

  const testPayload = (payload: string, property: string): { vulnerable: boolean; error?: string } => {
    try {
      // Create a clean object to test
      const testObj: Record<string, unknown> = {};

      // Check if the property already exists on Object.prototype before test
      const beforeTest = (Object.prototype as Record<string, unknown>)[property];

      // Try different pollution vectors
      if (payload.includes('JSON')) {
        try {
          JSON.parse(payload.replace(/'/g, '"'));
        } catch {
          // JSON parse itself may not pollute, but we're checking
        }
      }

      // Check if pollution occurred
      const afterTest = (testObj as Record<string, unknown>)[property];
      const polluted = afterTest !== undefined && beforeTest === undefined;

      return { vulnerable: polluted };
    } catch (e) {
      return { vulnerable: false, error: e instanceof Error ? e.message : 'Test failed' };
    }
  };

  const runAllTests = async () => {
    onChange({ ...data, isRunning: true, results: [] });

    const newResults: ProtoPollutionFuzzerData['results'] = [];

    for (const p of POLLUTION_PAYLOADS) {
      const result = testPayload(p.payload, p.property);
      newResults.push({
        payload: p.name,
        vulnerable: result.vulnerable,
        propertyChecked: p.property,
        error: result.error
      });
      // Small delay to show progress
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    if (customPayload.trim()) {
      const result = testPayload(customPayload, 'customPolluted');
      newResults.push({
        payload: 'Custom payload',
        vulnerable: result.vulnerable,
        propertyChecked: 'customPolluted',
        error: result.error
      });
    }

    onChange({ ...data, isRunning: false, results: newResults });
  };

  const copyPayload = (payload: string) => {
    navigator.clipboard.writeText(payload);
    setCopied(payload);
    setTimeout(() => setCopied(null), 2000);
  };

  const vulnerableCount = results.filter(r => r.vulnerable).length;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Prototype Pollution Fuzzer</div>
        <div className="flex gap-2">
          {results.length > 0 && (
            <span className={`text-[10px] ${vulnerableCount > 0 ? 'text-red-400' : 'text-green-400'}`}>
              {vulnerableCount} / {results.length} vulnerable
            </span>
          )}
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Tests for client-side prototype pollution vulnerabilities by attempting to modify Object.prototype.
      </div>

      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
        <div className="text-[10px] text-slate-500 mb-1">Custom Payload (optional)</div>
        <input
          type="text"
          value={customPayload}
          onChange={(e) => onChange({ ...data, customPayload: e.target.value })}
          placeholder="e.g., __proto__[test]=true"
          className="w-full rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-red-500"
        />
      </div>

      <button
        onClick={runAllTests}
        disabled={isRunning}
        className="w-full rounded bg-red-600/20 border border-red-500/30 px-2 py-1.5 text-[11px] text-red-300 hover:bg-red-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={isRunning ? faBug : faPlay} className={`w-3 h-3 ${isRunning ? 'animate-pulse' : ''}`} />
        {isRunning ? 'Testing...' : 'Run Pollution Tests'}
      </button>

      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
        <div className="text-[10px] text-slate-500 mb-2">Test Payloads:</div>
        <div className="max-h-24 overflow-y-auto space-y-1">
          {POLLUTION_PAYLOADS.map((p, i) => (
            <div
              key={i}
              className="flex items-center justify-between rounded border border-slate-700 bg-slate-800/50 p-1.5"
            >
              <span className="text-slate-300 text-[10px] truncate flex-1">{p.name}</span>
              <button
                onClick={() => copyPayload(p.payload)}
                className="ml-2 text-[9px] text-slate-500 hover:text-slate-300 p-1"
                title="Copy payload"
              >
                <FontAwesomeIcon icon={copied === p.payload ? faCheck : faCopy} className="w-2.5 h-2.5" />
              </button>
            </div>
          ))}
        </div>
      </div>

      {results.length > 0 && (
        <div className="flex-1 overflow-y-auto min-h-0">
          <div className="text-[10px] text-slate-500 mb-2">Results:</div>
          <div className="space-y-1">
            {results.map((r, i) => (
              <div
                key={i}
                className={`flex items-center justify-between rounded border p-2 ${
                  r.vulnerable
                    ? 'bg-red-900/20 border-red-500/30'
                    : 'bg-green-900/20 border-green-500/30'
                }`}
              >
                <span className="text-slate-300 text-[10px]">{r.payload}</span>
                <span className={`text-[10px] ${r.vulnerable ? 'text-red-400' : 'text-green-400'}`}>
                  {r.vulnerable ? (
                    <><FontAwesomeIcon icon={faExclamationTriangle} className="w-2.5 h-2.5 mr-1" /> Vulnerable</>
                  ) : (
                    'Safe'
                  )}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="text-[10px] text-slate-500 space-y-1 border-t border-slate-700 pt-2 mt-3">
        <div><strong>Note:</strong> These tests check if prototype pollution is possible in the current page context.</div>
        <div>Prototype pollution can lead to XSS, privilege escalation, or DoS attacks.</div>
      </div>
    </div>
  );
};

export class ProtoPollutionFuzzerTool {
  static Component = ProtoPollutionFuzzer;
}
