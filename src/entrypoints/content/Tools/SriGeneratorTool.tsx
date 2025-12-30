import React, { useState } from 'react';
import type { SriGeneratorData, SriAlgorithm, SriResourceType } from './tool-types';

const ALGORITHMS: { id: SriAlgorithm; label: string }[] = [
  { id: 'sha256', label: 'SHA-256' },
  { id: 'sha384', label: 'SHA-384 (Recommended)' },
  { id: 'sha512', label: 'SHA-512' }
];

const RESOURCE_TYPES: { id: SriResourceType; label: string }[] = [
  { id: 'script', label: 'Script' },
  { id: 'style', label: 'Style (CSS)' }
];

const algorithmToSubtle = (algo: SriAlgorithm): string => {
  switch (algo) {
    case 'sha256':
      return 'SHA-256';
    case 'sha384':
      return 'SHA-384';
    case 'sha512':
      return 'SHA-512';
  }
};

const computeSriHash = async (content: string, algorithm: SriAlgorithm): Promise<string> => {
  const encoder = new TextEncoder();
  const data = encoder.encode(content);
  const hashBuffer = await crypto.subtle.digest(algorithmToSubtle(algorithm), data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const base64 = btoa(String.fromCharCode(...hashArray));
  return `${algorithm}-${base64}`;
};

const generateScriptTag = (
  url: string,
  hash: string,
  resourceType: SriResourceType
): string => {
  if (resourceType === 'style') {
    return `<link rel="stylesheet" href="${url}" integrity="${hash}" crossorigin="anonymous">`;
  }
  return `<script src="${url}" integrity="${hash}" crossorigin="anonymous"></script>`;
};

type Props = {
  data: SriGeneratorData | undefined;
  onChange: (next: SriGeneratorData) => void;
};

const SriGeneratorToolComponent = ({ data, onChange }: Props) => {
  const content = data?.content ?? '';
  const url = data?.url ?? '';
  const algorithm: SriAlgorithm = data?.algorithm ?? 'sha384';
  const resourceType: SriResourceType = data?.resourceType ?? 'script';
  const hash = data?.hash ?? '';
  const scriptTag = data?.scriptTag ?? '';
  const loading = data?.loading ?? false;
  const error = data?.error;
  const [copiedHash, setCopiedHash] = useState(false);
  const [copiedTag, setCopiedTag] = useState(false);

  const handleGenerate = async () => {
    if (!content.trim()) {
      onChange({ ...data, error: 'Enter content to generate hash' });
      return;
    }

    onChange({ ...data, loading: true, error: undefined });

    try {
      const sriHash = await computeSriHash(content, algorithm);
      const tag = url ? generateScriptTag(url, sriHash, resourceType) : '';
      onChange({
        ...data,
        hash: sriHash,
        scriptTag: tag,
        loading: false,
        error: undefined
      });
    } catch (err) {
      onChange({
        ...data,
        loading: false,
        error: err instanceof Error ? err.message : 'Failed to generate hash'
      });
    }
  };

  const handleCopyHash = () => {
    if (hash) {
      navigator.clipboard.writeText(hash);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 1500);
    }
  };

  const handleCopyTag = () => {
    if (scriptTag) {
      navigator.clipboard.writeText(scriptTag);
      setCopiedTag(true);
      setTimeout(() => setCopiedTag(false), 1500);
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">SRI Generator</div>

      {/* Algorithm selector */}
      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">Algorithm</div>
        <div className="flex gap-1">
          {ALGORITHMS.map((algo) => (
            <button
              key={algo.id}
              type="button"
              onClick={() => onChange({ ...data, algorithm: algo.id })}
              className={`flex-1 rounded px-2 py-1.5 text-[10px] transition-colors ${
                algorithm === algo.id
                  ? 'bg-emerald-600 text-white'
                  : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
              }`}
            >
              {algo.label}
            </button>
          ))}
        </div>
      </div>

      {/* Resource type selector */}
      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">Resource Type</div>
        <div className="flex gap-1">
          {RESOURCE_TYPES.map((type) => (
            <button
              key={type.id}
              type="button"
              onClick={() => onChange({ ...data, resourceType: type.id })}
              className={`flex-1 rounded px-2 py-1.5 text-[10px] transition-colors ${
                resourceType === type.id
                  ? 'bg-slate-600 text-white'
                  : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
              }`}
            >
              {type.label}
            </button>
          ))}
        </div>
      </div>

      {/* URL input (optional) */}
      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">Resource URL (optional)</div>
        <input
          type="text"
          value={url}
          onChange={(e) => onChange({ ...data, url: e.target.value })}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 transition-colors font-mono"
          placeholder="https://cdn.example.com/script.js"
        />
      </div>

      {/* Content input */}
      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">Content</div>
        <textarea
          value={content}
          onChange={(e) => onChange({ ...data, content: e.target.value })}
          rows={4}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 transition-colors font-mono"
          placeholder="Paste the script or stylesheet content here..."
        />
      </div>

      {/* Generate button */}
      <button
        type="button"
        onClick={handleGenerate}
        disabled={loading}
        className="w-full rounded bg-emerald-600 px-2 py-1.5 text-xs text-white hover:bg-emerald-500 transition-colors disabled:opacity-50"
      >
        {loading ? 'Generating...' : 'Generate'}
      </button>

      {/* Error display */}
      {error && (
        <div className="text-[11px] text-rose-300 bg-rose-900/20 border border-rose-800 rounded px-2 py-1.5">
          {error}
        </div>
      )}

      {/* Hash output */}
      {hash && (
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <div className="text-[11px] text-slate-400">Integrity Hash</div>
            <button
              type="button"
              onClick={handleCopyHash}
              className="text-[10px] text-slate-400 hover:text-white transition-colors"
            >
              {copiedHash ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <div
            className="bg-slate-900 border border-slate-700 rounded p-2 text-[10px] text-slate-200 font-mono break-all select-all cursor-pointer"
            onClick={handleCopyHash}
          >
            {hash}
          </div>
        </div>
      )}

      {/* Script tag output */}
      {scriptTag && (
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <div className="text-[11px] text-slate-400">
              {resourceType === 'style' ? 'Link Tag' : 'Script Tag'}
            </div>
            <button
              type="button"
              onClick={handleCopyTag}
              className="text-[10px] text-slate-400 hover:text-white transition-colors"
            >
              {copiedTag ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <div
            className="bg-slate-900 border border-slate-700 rounded p-2 text-[10px] text-emerald-300 font-mono break-all select-all cursor-pointer"
            onClick={handleCopyTag}
          >
            {scriptTag}
          </div>
        </div>
      )}

      {/* Info */}
      <div className="text-[10px] text-slate-500">
        Subresource Integrity (SRI) protects against compromised CDNs by verifying file integrity.
        SHA-384 is recommended for the best balance of security and performance.
      </div>
    </div>
  );
};

export class SriGeneratorTool {
  static Component = SriGeneratorToolComponent;
}
