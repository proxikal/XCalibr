import React, { useState } from 'react';
import type { HmacGeneratorData, HmacAlgorithm, HmacKeyFormat } from './tool-types';

const ALGORITHMS: HmacAlgorithm[] = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
const KEY_FORMATS: { id: HmacKeyFormat; label: string }[] = [
  { id: 'text', label: 'Text' },
  { id: 'hex', label: 'Hex' }
];

const hexToBytes = (hex: string): Uint8Array => {
  const cleanHex = hex.replace(/\s/g, '');
  if (!/^[0-9a-fA-F]*$/.test(cleanHex)) {
    throw new Error('Invalid hex characters');
  }
  if (cleanHex.length % 2 !== 0) {
    throw new Error('Hex string must have even length');
  }
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.slice(i, i + 2), 16);
  }
  return bytes;
};

const computeHmac = async (
  algorithm: HmacAlgorithm,
  key: Uint8Array,
  message: string
): Promise<string> => {
  const encoder = new TextEncoder();
  const messageData = encoder.encode(message);

  // Create a new ArrayBuffer from the Uint8Array to satisfy TypeScript
  const keyBuffer = new ArrayBuffer(key.length);
  const keyView = new Uint8Array(keyBuffer);
  keyView.set(key);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'HMAC', hash: algorithm },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
  const hashArray = Array.from(new Uint8Array(signature));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
};

type Props = {
  data: HmacGeneratorData | undefined;
  onChange: (next: HmacGeneratorData) => void;
};

const HmacGeneratorToolComponent = ({ data, onChange }: Props) => {
  const message = data?.message ?? '';
  const key = data?.key ?? '';
  const keyFormat: HmacKeyFormat = data?.keyFormat ?? 'text';
  const algorithm: HmacAlgorithm = data?.algorithm ?? 'SHA-256';
  const output = data?.output ?? '';
  const loading = data?.loading ?? false;
  const error = data?.error;
  const [copied, setCopied] = useState(false);

  const handleGenerate = async () => {
    if (!key) {
      onChange({ ...data, error: 'Key is required' });
      return;
    }

    onChange({ ...data, loading: true, error: undefined });

    try {
      let keyBytes: Uint8Array;
      if (keyFormat === 'hex') {
        keyBytes = hexToBytes(key);
      } else {
        const encoder = new TextEncoder();
        keyBytes = encoder.encode(key);
      }

      const result = await computeHmac(algorithm, keyBytes, message);
      onChange({ ...data, output: result, loading: false });
    } catch (err) {
      onChange({
        ...data,
        output: '',
        loading: false,
        error: err instanceof Error ? err.message : 'HMAC generation failed'
      });
    }
  };

  const handleCopy = () => {
    if (output) {
      navigator.clipboard.writeText(output);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">HMAC Generator</div>

      {/* Algorithm selector */}
      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">Algorithm</div>
        <div className="flex gap-1">
          {ALGORITHMS.map((algo) => (
            <button
              key={algo}
              type="button"
              onClick={() => onChange({ ...data, algorithm: algo })}
              className={`flex-1 rounded px-2 py-1.5 text-[11px] transition-colors ${
                algorithm === algo
                  ? 'bg-emerald-600 text-white'
                  : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
              }`}
            >
              {algo}
            </button>
          ))}
        </div>
      </div>

      {/* Message input */}
      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">Message</div>
        <textarea
          value={message}
          onChange={(e) => onChange({ ...data, message: e.target.value })}
          rows={3}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 transition-colors font-mono"
          placeholder="Enter message to authenticate"
        />
      </div>

      {/* Key input */}
      <div className="space-y-1">
        <div className="flex items-center justify-between">
          <div className="text-[11px] text-slate-400">Secret Key</div>
          <div className="flex gap-1">
            {KEY_FORMATS.map((fmt) => (
              <button
                key={fmt.id}
                type="button"
                onClick={() => onChange({ ...data, keyFormat: fmt.id })}
                className={`rounded px-2 py-0.5 text-[10px] transition-colors ${
                  keyFormat === fmt.id
                    ? 'bg-slate-600 text-white'
                    : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                }`}
              >
                {fmt.label}
              </button>
            ))}
          </div>
        </div>
        <input
          type="text"
          value={key}
          onChange={(e) => onChange({ ...data, key: e.target.value })}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 transition-colors font-mono"
          placeholder={keyFormat === 'hex' ? 'Enter key in hexadecimal' : 'Enter secret key'}
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

      {/* Output */}
      {output && (
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <div className="text-[11px] text-slate-400">HMAC Output</div>
            <button
              type="button"
              onClick={handleCopy}
              className="text-[10px] text-slate-400 hover:text-white transition-colors"
            >
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <div
            className="bg-slate-900 border border-slate-700 rounded p-2 text-[10px] text-slate-300 font-mono break-all select-all cursor-text"
            onClick={handleCopy}
          >
            {output}
          </div>
        </div>
      )}

      {/* Info */}
      <div className="text-[10px] text-slate-500">
        HMAC (Hash-based Message Authentication Code) provides both data integrity and authenticity verification.
      </div>
    </div>
  );
};

export class HmacGeneratorTool {
  static Component = HmacGeneratorToolComponent;
}
