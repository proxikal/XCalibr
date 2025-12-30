import React from 'react';
import type {
  UrlCodecData
} from './tool-types';

const UrlCodecToolComponent = ({
  data,
  onChange
}: {
  data: UrlCodecData | undefined;
  onChange: (next: UrlCodecData) => void;
}) => {
  const mode = data?.mode ?? 'encode';
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const error = data?.error;

  const updateInput = (value: string) => {
    try {
      const result = mode === 'encode' ? encodeURIComponent(value) : decodeURIComponent(value);
      onChange({ mode, input: value, output: result, error: undefined });
    } catch {
      onChange({ mode, input: value, output: '', error: 'Unable to decode input.' });
    }
  };

  const toggleMode = () => {
    const nextMode = mode === 'encode' ? 'decode' : 'encode';
    try {
      const result = nextMode === 'encode'
        ? encodeURIComponent(input)
        : decodeURIComponent(input);
      onChange({ mode: nextMode, input, output: result, error: undefined });
    } catch {
      onChange({ mode: nextMode, input, output: '', error: 'Unable to decode input.' });
    }
  };

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
      <textarea
        value={input}
        onChange={(event) => updateInput(event.target.value)}
        rows={4}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors"
        placeholder="Enter text to encode/decode"
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <textarea
        value={output}
        readOnly
        rows={4}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none"
        placeholder="Result"
      />
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
