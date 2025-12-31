import React from 'react';
import type {
  UrlCodecData,
  UrlCodecEncodingMode
} from './tool-types';

const ENCODING_MODES: { value: UrlCodecEncodingMode; label: string; description: string }[] = [
  { value: 'rfc3986', label: 'RFC 3986', description: 'Standard URL encoding (recommended)' },
  { value: 'rfc2396', label: 'RFC 2396', description: 'Legacy URL encoding (less strict)' },
  { value: 'base64url', label: 'Base64URL', description: 'URL-safe Base64 encoding' },
  { value: 'path', label: 'Path', description: 'Path segment encoding' },
];

// RFC 3986 reserved characters that should be encoded
const RFC3986_RESERVED = /[!'()*]/g;

const encodeRfc3986 = (value: string): string => {
  return encodeURIComponent(value).replace(RFC3986_RESERVED, (c) =>
    '%' + c.charCodeAt(0).toString(16).toUpperCase()
  );
};

const decodeRfc3986 = (value: string): string => {
  return decodeURIComponent(value);
};

// RFC 2396 is less strict - doesn't encode some special chars
const encodeRfc2396 = (value: string): string => {
  return encodeURI(value).replace(/%5B/gi, '[').replace(/%5D/gi, ']');
};

const decodeRfc2396 = (value: string): string => {
  return decodeURI(value);
};

// Base64URL encoding (URL-safe base64)
const encodeBase64Url = (value: string): string => {
  const base64 = btoa(unescape(encodeURIComponent(value)));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const decodeBase64Url = (value: string): string => {
  let base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return decodeURIComponent(escape(atob(base64)));
};

// Path encoding (for URL path segments)
const encodePath = (value: string): string => {
  return value.split('/').map(segment => encodeURIComponent(segment)).join('/');
};

const decodePath = (value: string): string => {
  return value.split('/').map(segment => decodeURIComponent(segment)).join('/');
};

const getEncoder = (encodingMode: UrlCodecEncodingMode): (value: string) => string => {
  switch (encodingMode) {
    case 'rfc3986': return encodeRfc3986;
    case 'rfc2396': return encodeRfc2396;
    case 'base64url': return encodeBase64Url;
    case 'path': return encodePath;
    default: return encodeRfc3986;
  }
};

const getDecoder = (encodingMode: UrlCodecEncodingMode): (value: string) => string => {
  switch (encodingMode) {
    case 'rfc3986': return decodeRfc3986;
    case 'rfc2396': return decodeRfc2396;
    case 'base64url': return decodeBase64Url;
    case 'path': return decodePath;
    default: return decodeRfc3986;
  }
};

const toHexView = (value: string): string => {
  const bytes: string[] = [];
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code > 255) {
      // Handle multi-byte characters
      const encoded = encodeURIComponent(value[i]);
      bytes.push(...encoded.split('%').filter(Boolean).map(h => h.toUpperCase()));
    } else {
      bytes.push(code.toString(16).toUpperCase().padStart(2, '0'));
    }
  }
  return bytes.join(' ');
};

type DiffSegment = { type: 'same' | 'changed'; value: string };

const computeDiff = (input: string, output: string): DiffSegment[] => {
  const segments: DiffSegment[] = [];
  let inputIdx = 0;
  let outputIdx = 0;

  while (inputIdx < input.length && outputIdx < output.length) {
    if (input[inputIdx] === output[outputIdx]) {
      // Same character
      let sameStart = outputIdx;
      while (inputIdx < input.length && outputIdx < output.length && input[inputIdx] === output[outputIdx]) {
        inputIdx++;
        outputIdx++;
      }
      segments.push({ type: 'same', value: output.slice(sameStart, outputIdx) });
    } else {
      // Character was encoded/decoded - find the encoded sequence
      let changedStart = outputIdx;

      // For encoded sequences like %20, consume until we match again
      if (output[outputIdx] === '%') {
        // Consume the percent-encoded sequence
        while (outputIdx < output.length && (output[outputIdx] === '%' ||
          (outputIdx > changedStart && outputIdx < changedStart + 3))) {
          outputIdx++;
          if ((outputIdx - changedStart) % 3 === 0 && output[outputIdx] !== '%') break;
        }
        inputIdx++;
      } else {
        // Decoding case - input has encoded, output has plain
        outputIdx++;
        // Skip the encoded portion in conceptual input tracking
        while (inputIdx < input.length && input[inputIdx] === '%') {
          inputIdx += 3; // Skip %XX
        }
        if (inputIdx <= input.length) inputIdx = Math.min(inputIdx, input.length);
      }

      segments.push({ type: 'changed', value: output.slice(changedStart, outputIdx) });
    }
  }

  // Handle remaining output
  if (outputIdx < output.length) {
    segments.push({ type: 'changed', value: output.slice(outputIdx) });
  }

  return segments;
};

const UrlCodecToolComponent = ({
  data,
  onChange
}: {
  data: UrlCodecData | undefined;
  onChange: (next: UrlCodecData) => void;
}) => {
  const mode = data?.mode ?? 'encode';
  const encodingMode = data?.encodingMode ?? 'rfc3986';
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const showDiff = data?.showDiff ?? false;
  const showHex = data?.showHex ?? false;
  const error = data?.error;

  const processInput = (value: string, currentMode: 'encode' | 'decode', currentEncodingMode: UrlCodecEncodingMode) => {
    try {
      const processor = currentMode === 'encode'
        ? getEncoder(currentEncodingMode)
        : getDecoder(currentEncodingMode);
      const result = processor(value);
      onChange({
        mode: currentMode,
        encodingMode: currentEncodingMode,
        input: value,
        output: result,
        showDiff,
        showHex,
        error: undefined
      });
    } catch {
      onChange({
        mode: currentMode,
        encodingMode: currentEncodingMode,
        input: value,
        output: '',
        showDiff,
        showHex,
        error: `Unable to ${currentMode} input with ${currentEncodingMode} mode.`
      });
    }
  };

  const updateInput = (value: string) => {
    processInput(value, mode, encodingMode);
  };

  const toggleMode = () => {
    const nextMode = mode === 'encode' ? 'decode' : 'encode';
    processInput(input, nextMode, encodingMode);
  };

  const changeEncodingMode = (newEncodingMode: UrlCodecEncodingMode) => {
    processInput(input, mode, newEncodingMode);
  };

  const toggleDiff = () => {
    onChange({ ...data, mode, encodingMode, input, output, showDiff: !showDiff, showHex, error });
  };

  const toggleHex = () => {
    onChange({ ...data, mode, encodingMode, input, output, showDiff, showHex: !showHex, error });
  };

  const diffSegments = showDiff ? computeDiff(input, output) : [];
  const hexOutput = showHex ? toHexView(output) : '';

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">URL Encoder / Decoder</div>
        <button
          type="button"
          onClick={toggleMode}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          {mode === 'encode' ? 'Encode' : 'Decode'}
        </button>
      </div>

      {/* Encoding Mode Selector */}
      <div className="space-y-1">
        <div className="text-[10px] text-slate-400">Encoding Mode</div>
        <div className="flex flex-wrap gap-1">
          {ENCODING_MODES.map((em) => (
            <button
              key={em.value}
              type="button"
              onClick={() => changeEncodingMode(em.value)}
              title={em.description}
              className={`rounded px-2 py-1 text-[10px] border transition-colors ${
                encodingMode === em.value
                  ? 'bg-blue-500/20 border-blue-500/50 text-blue-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:bg-slate-700'
              }`}
            >
              {em.label}
            </button>
          ))}
        </div>
      </div>

      {/* Options Row */}
      <div className="flex gap-2">
        <button
          type="button"
          onClick={toggleDiff}
          className={`flex-1 rounded px-2 py-1 text-[10px] border transition-colors ${
            showDiff
              ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-300'
              : 'bg-slate-800 border-slate-700 text-slate-400 hover:bg-slate-700'
          }`}
        >
          Show Diff
        </button>
        <button
          type="button"
          onClick={toggleHex}
          className={`flex-1 rounded px-2 py-1 text-[10px] border transition-colors ${
            showHex
              ? 'bg-amber-500/20 border-amber-500/50 text-amber-300'
              : 'bg-slate-800 border-slate-700 text-slate-400 hover:bg-slate-700'
          }`}
        >
          Hex View
        </button>
      </div>

      <textarea
        value={input}
        onChange={(event) => updateInput(event.target.value)}
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors"
        placeholder="Enter text to encode/decode"
      />

      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}

      {/* Diff View */}
      {showDiff && output && !error ? (
        <div className="rounded bg-slate-900 p-2 border border-slate-800">
          <div className="text-[10px] text-slate-500 mb-1">Changes highlighted:</div>
          <div className="text-xs font-mono break-all">
            {diffSegments.map((seg, idx) => (
              <span
                key={idx}
                className={seg.type === 'changed' ? 'bg-amber-500/30 text-amber-200' : 'text-slate-300'}
              >
                {seg.value}
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {/* Regular Output */}
      <textarea
        value={output}
        readOnly
        rows={3}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none"
        placeholder="Result"
      />

      {/* Hex View */}
      {showHex && output && !error ? (
        <div className="rounded bg-slate-900 p-2 border border-slate-800">
          <div className="text-[10px] text-slate-500 mb-1">Hex bytes:</div>
          <div className="text-[10px] font-mono text-amber-300 break-all">
            {hexOutput}
          </div>
        </div>
      ) : null}

      <button
        type="button"
        onClick={() => navigator.clipboard.writeText(output)}
        disabled={!output}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Copy Result
      </button>
    </div>
  );
};

export class UrlCodecTool {
  static Component = UrlCodecToolComponent;
}
