import React from 'react';
import type { HtmlEntityEncoderData, HtmlEntityMode } from './tool-types';

// Named entity mappings
const namedEntities: Record<string, string> = {
  '<': '&lt;',
  '>': '&gt;',
  '&': '&amp;',
  '"': '&quot;',
  '\u00A0': '&nbsp;',
  '\u00A9': '&copy;',
  '\u00AE': '&reg;',
  '\u2122': '&trade;',
  '\u20AC': '&euro;',
  '\u00A3': '&pound;',
  '\u00A5': '&yen;',
  '\u00A2': '&cent;',
  '\u00A7': '&sect;',
  '\u00B0': '&deg;',
  '\u00B1': '&plusmn;',
  '\u00D7': '&times;',
  '\u00F7': '&divide;',
  '\u00B6': '&para;',
  '\u2022': '&bull;',
  '\u2026': '&hellip;',
  '\u2014': '&mdash;',
  '\u2013': '&ndash;',
  '\u2018': '&lsquo;',
  '\u2019': '&rsquo;',
  '\u201C': '&ldquo;',
  '\u201D': '&rdquo;',
  '\u00AB': '&laquo;',
  '\u00BB': '&raquo;'
};

// Reverse mapping for decoding
const reverseNamedEntities: Record<string, string> = {};
for (const [char, entity] of Object.entries(namedEntities)) {
  reverseNamedEntities[entity] = char;
}

// Characters that should always be encoded for security
const securityChars = new Set(['<', '>', '&', '"', "'"]);

const encodeToNamedEntity = (char: string): string | null => {
  return namedEntities[char] || null;
};

const encodeToDecimalEntity = (char: string): string => {
  return `&#${char.charCodeAt(0)};`;
};

const encodeToHexEntity = (char: string): string => {
  return `&#x${char.charCodeAt(0).toString(16)};`;
};

const encodeHtml = (
  input: string,
  mode: HtmlEntityMode,
  encodeAll: boolean
): string => {
  let result = '';
  for (const char of input) {
    const shouldEncode = encodeAll || securityChars.has(char);

    if (!shouldEncode) {
      result += char;
      continue;
    }

    if (mode === 'named') {
      const named = encodeToNamedEntity(char);
      if (named) {
        result += named;
      } else {
        // Fallback to decimal for chars without named entities
        result += encodeToDecimalEntity(char);
      }
    } else if (mode === 'decimal') {
      result += encodeToDecimalEntity(char);
    } else if (mode === 'hex') {
      result += encodeToHexEntity(char);
    }
  }
  return result;
};

const decodeHtml = (input: string): string => {
  // Create a temporary element to leverage browser's HTML decoding
  const doc = new DOMParser().parseFromString(input, 'text/html');
  return doc.documentElement.textContent || '';
};

type Props = {
  data: HtmlEntityEncoderData | undefined;
  onChange: (next: HtmlEntityEncoderData) => void;
};

const modes: { id: HtmlEntityMode; label: string }[] = [
  { id: 'named', label: 'Named' },
  { id: 'decimal', label: 'Decimal' },
  { id: 'hex', label: 'Hex' }
];

const HtmlEntityEncoderToolComponent = ({ data, onChange }: Props) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const mode: HtmlEntityMode = data?.mode ?? 'named';
  const encodeAll = data?.encodeAll ?? false;
  const error = data?.error;

  const handleEncode = () => {
    try {
      const result = encodeHtml(input, mode, encodeAll);
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
      const result = decodeHtml(input);
      onChange({ ...data, output: result, error: undefined });
    } catch (err) {
      onChange({
        ...data,
        output: '',
        error: err instanceof Error ? err.message : 'Decoding failed'
      });
    }
  };

  const handleModeChange = (newMode: HtmlEntityMode) => {
    onChange({ ...data, mode: newMode });
  };

  const handleCopy = () => {
    if (output) {
      navigator.clipboard.writeText(output);
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">HTML Entity Encoder</div>

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

      {/* Encode all option */}
      <label className="flex items-center gap-2 text-xs text-slate-300">
        <input
          type="checkbox"
          checked={encodeAll}
          onChange={(e) => onChange({ ...data, encodeAll: e.target.checked })}
          className="rounded bg-slate-800 border-slate-600 text-emerald-500 focus:ring-emerald-500"
        />
        Encode all characters (not just security-sensitive)
      </label>

      {/* Input area */}
      <textarea
        value={input}
        onChange={(e) => onChange({ ...data, input: e.target.value })}
        rows={4}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 transition-colors font-mono"
        placeholder="Enter text or HTML entities"
      />

      {/* Action buttons */}
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

      {/* Quick reference */}
      <div className="text-[10px] text-slate-500">
        <div className="font-medium mb-1">Common entities:</div>
        <div className="flex flex-wrap gap-x-3">
          <span>&lt; → &amp;lt;</span>
          <span>&gt; → &amp;gt;</span>
          <span>&amp; → &amp;amp;</span>
          <span>&quot; → &amp;quot;</span>
        </div>
      </div>
    </div>
  );
};

export class HtmlEntityEncoderTool {
  static Component = HtmlEntityEncoderToolComponent;
}
