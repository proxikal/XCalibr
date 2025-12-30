import React, { useRef } from 'react';
import type { Base64AdvancedData, Base64AdvancedMode } from './tool-types';

// Utility functions for Base64 operations
const encodeUtf8ToBase64 = (str: string): string => {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(str);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

const decodeBase64ToUtf8 = (base64: string): string => {
  // Remove whitespace and newlines
  const cleanedBase64 = base64.replace(/\s/g, '');
  const binary = atob(cleanedBase64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  const decoder = new TextDecoder();
  return decoder.decode(bytes);
};

const toUrlSafeBase64 = (base64: string): string => {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const fromUrlSafeBase64 = (urlSafe: string): string => {
  let base64 = urlSafe.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return base64;
};

const hexToBytes = (hex: string): Uint8Array => {
  // Remove 0x prefix if present
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
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

const bytesToHex = (bytes: Uint8Array): string => {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
};

const bytesToBase64 = (bytes: Uint8Array): string => {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

const base64ToBytes = (base64: string): Uint8Array => {
  const cleanedBase64 = base64.replace(/\s/g, '');
  const binary = atob(cleanedBase64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

type Props = {
  data: Base64AdvancedData | undefined;
  onChange: (next: Base64AdvancedData) => void;
};

const modes: { id: Base64AdvancedMode; label: string }[] = [
  { id: 'standard', label: 'Standard' },
  { id: 'urlSafe', label: 'URL-Safe' },
  { id: 'hex', label: 'Hex' },
  { id: 'image', label: 'Image' }
];

const Base64AdvancedToolComponent = ({ data, onChange }: Props) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const mode: Base64AdvancedMode = data?.mode ?? 'standard';
  const error = data?.error;
  const imagePreview = data?.imagePreview;

  const handleEncode = () => {
    try {
      let result = '';
      if (mode === 'standard') {
        result = encodeUtf8ToBase64(input);
      } else if (mode === 'urlSafe') {
        const base64 = encodeUtf8ToBase64(input);
        result = toUrlSafeBase64(base64);
      } else if (mode === 'hex') {
        const bytes = hexToBytes(input);
        result = bytesToBase64(bytes);
      }
      onChange({ ...data, output: result, error: undefined });
    } catch (err) {
      onChange({
        ...data,
        output: '',
        error: err instanceof Error ? err.message : 'Encoding failed'
      });
    }
  };

  const handleDecode = () => {
    try {
      let result = '';
      if (mode === 'standard') {
        result = decodeBase64ToUtf8(input);
      } else if (mode === 'urlSafe') {
        const standardBase64 = fromUrlSafeBase64(input.replace(/\s/g, ''));
        result = decodeBase64ToUtf8(standardBase64);
      } else if (mode === 'hex') {
        const bytes = base64ToBytes(input);
        result = bytesToHex(bytes);
      }
      onChange({ ...data, output: result, error: undefined });
    } catch (err) {
      onChange({
        ...data,
        output: '',
        error: err instanceof Error ? err.message : 'Decoding failed'
      });
    }
  };

  const handleModeChange = (newMode: Base64AdvancedMode) => {
    onChange({ ...data, mode: newMode, output: '', error: undefined });
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = reader.result as string;
      onChange({
        ...data,
        output: dataUrl,
        imagePreview: dataUrl,
        error: undefined
      });
    };
    reader.onerror = () => {
      onChange({
        ...data,
        output: '',
        error: 'Failed to read file'
      });
    };
    reader.readAsDataURL(file);
  };

  const handleCopy = () => {
    if (output) {
      navigator.clipboard.writeText(output);
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Base64 Advanced</div>

      {/* Mode selector */}
      <div className="flex gap-1">
        {modes.map((m) => (
          <button
            key={m.id}
            type="button"
            onClick={() => handleModeChange(m.id)}
            className={`flex-1 rounded px-2 py-1.5 text-[11px] transition-colors ${
              mode === m.id
                ? 'bg-emerald-600 text-white'
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
            }`}
          >
            {m.label}
          </button>
        ))}
      </div>

      {/* Input area */}
      {mode === 'image' ? (
        <div className="space-y-2">
          <input
            ref={fileInputRef}
            type="file"
            accept="image/*"
            onChange={handleFileChange}
            className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 transition-colors file:mr-2 file:py-1 file:px-2 file:rounded file:border-0 file:text-xs file:bg-emerald-600 file:text-white file:cursor-pointer"
          />
          {imagePreview && (
            <div className="flex justify-center p-2 bg-slate-900 rounded border border-slate-700">
              <img
                src={imagePreview}
                alt="Preview"
                className="max-w-full max-h-32 object-contain"
              />
            </div>
          )}
        </div>
      ) : (
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          rows={4}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 transition-colors font-mono"
          placeholder={
            mode === 'hex'
              ? 'Enter hex string (e.g., 48656c6c6f)'
              : 'Enter text or Base64 string'
          }
        />
      )}

      {/* Action buttons */}
      {mode !== 'image' && (
        <div className="flex gap-2">
          <button
            type="button"
            onClick={handleEncode}
            className="flex-1 rounded bg-emerald-600 px-2 py-1.5 text-xs text-white hover:bg-emerald-500 transition-colors"
          >
            Encode
          </button>
          <button
            type="button"
            onClick={handleDecode}
            className="flex-1 rounded bg-slate-700 px-2 py-1.5 text-xs text-white hover:bg-slate-600 transition-colors"
          >
            Decode
          </button>
        </div>
      )}

      {/* Error display */}
      {error && (
        <div className="text-[11px] text-rose-300 bg-rose-900/20 border border-rose-800 rounded px-2 py-1.5">
          {error}
        </div>
      )}

      {/* Output area */}
      <textarea
        value={output}
        readOnly
        rows={4}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Result will appear here"
      />

      {/* Copy button */}
      <button
        type="button"
        onClick={handleCopy}
        disabled={!output}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      >
        Copy
      </button>
    </div>
  );
};

export class Base64AdvancedTool {
  static Component = Base64AdvancedToolComponent;
}
