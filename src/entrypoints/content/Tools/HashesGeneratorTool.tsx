import React, { useState } from 'react';
import type { HashesGeneratorData } from './tool-types';

type HashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';

const ALGORITHMS: HashAlgorithm[] = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];

const computeHash = async (
  algorithm: HashAlgorithm,
  data: string
): Promise<string> => {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest(algorithm, dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
};

const computeAllHashes = async (
  input: string
): Promise<Record<string, string>> => {
  const results: Record<string, string> = {};
  for (const algo of ALGORITHMS) {
    results[algo] = await computeHash(algo, input);
  }
  return results;
};

type Props = {
  data: HashesGeneratorData | undefined;
  onChange: (next: HashesGeneratorData) => void;
};

const HashesGeneratorToolComponent = ({ data, onChange }: Props) => {
  const input = data?.input ?? '';
  const hashes = data?.hashes ?? {};
  const loading = data?.loading ?? false;
  const error = data?.error;
  const [copiedAlgo, setCopiedAlgo] = useState<string | null>(null);

  const handleGenerate = async () => {
    onChange({ ...data, loading: true, error: undefined });
    try {
      const results = await computeAllHashes(input);
      onChange({ ...data, hashes: results, loading: false });
    } catch (err) {
      onChange({
        ...data,
        loading: false,
        error: err instanceof Error ? err.message : 'Hash generation failed'
      });
    }
  };

  const handleClear = () => {
    onChange({ ...data, hashes: {}, input: '' });
  };

  const handleCopyAll = () => {
    const allHashes = ALGORITHMS.map(
      (algo) => `${algo}: ${hashes[algo] || 'N/A'}`
    ).join('\n');
    navigator.clipboard.writeText(allHashes);
  };

  const handleCopyHash = (algo: string, hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedAlgo(algo);
    setTimeout(() => setCopiedAlgo(null), 1500);
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Hashes Generator</div>

      {/* Input area */}
      <textarea
        value={input}
        onChange={(e) => onChange({ ...data, input: e.target.value })}
        rows={4}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 transition-colors font-mono"
        placeholder="Enter text to hash"
      />

      {/* Action buttons */}
      <div className="flex gap-2">
        <button
          type="button"
          onClick={handleGenerate}
          disabled={loading}
          className="flex-1 rounded bg-emerald-600 px-2 py-1.5 text-xs text-white hover:bg-emerald-500 transition-colors disabled:opacity-50"
        >
          {loading ? 'Generating...' : 'Generate'}
        </button>
        <button
          type="button"
          onClick={handleCopyAll}
          disabled={Object.keys(hashes).length === 0}
          className="rounded bg-slate-700 px-3 py-1.5 text-xs text-white hover:bg-slate-600 transition-colors disabled:opacity-50"
        >
          Copy All
        </button>
        <button
          type="button"
          onClick={handleClear}
          className="rounded bg-slate-700 px-3 py-1.5 text-xs text-white hover:bg-slate-600 transition-colors"
        >
          Clear
        </button>
      </div>

      {/* Error display */}
      {error && (
        <div className="text-[11px] text-rose-300 bg-rose-900/20 border border-rose-800 rounded px-2 py-1.5">
          {error}
        </div>
      )}

      {/* Hash results */}
      {Object.keys(hashes).length > 0 && (
        <div className="space-y-2">
          <div className="text-[11px] text-slate-400 font-medium">Results:</div>
          {ALGORITHMS.map((algo) => {
            const hash = hashes[algo];
            if (!hash) return null;
            return (
              <div
                key={algo}
                className="bg-slate-900 border border-slate-700 rounded p-2"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[11px] font-medium text-emerald-400">
                    {algo}
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCopyHash(algo, hash)}
                    className="text-[10px] text-slate-400 hover:text-white transition-colors"
                  >
                    {copiedAlgo === algo ? 'Copied!' : 'Copy'}
                  </button>
                </div>
                <div
                  className="text-[10px] text-slate-300 font-mono break-all select-all cursor-text"
                  onClick={() => handleCopyHash(algo, hash)}
                >
                  {hash}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Algorithm info */}
      <div className="text-[10px] text-slate-500">
        <div className="font-medium mb-1">Supported algorithms:</div>
        <div className="flex flex-wrap gap-x-3">
          {ALGORITHMS.map((algo) => (
            <span key={algo}>{algo}</span>
          ))}
        </div>
      </div>
    </div>
  );
};

export class HashesGeneratorTool {
  static Component = HashesGeneratorToolComponent;
}
