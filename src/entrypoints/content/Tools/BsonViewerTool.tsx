import React from 'react';
import {
  normalizeBsonValue
} from './helpers';
import type {
  BsonViewerData
} from './tool-types';

const BsonViewerToolComponent = ({
  data,
  onChange
}: {
  data: BsonViewerData | undefined;
  onChange: (next: BsonViewerData) => void;
}) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handleParse = () => {
    try {
      const parsed = JSON.parse(input);
      const normalized = normalizeBsonValue(parsed);
      onChange({
        input,
        output: JSON.stringify(normalized, null, 2),
        error: ''
      });
    } catch (err) {
      onChange({
        input,
        output: '',
        error: err instanceof Error ? err.message : 'Invalid JSON'
      });
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">BSON Viewer</div>
      <textarea
        value={input}
        onChange={(event) => onChange({ input: event.target.value, output, error })}
        rows={6}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Paste BSON (extended JSON)..."
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <button
        type="button"
        onClick={handleParse}
        disabled={!input.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Normalize
      </button>
      <textarea
        value={output}
        readOnly
        rows={5}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Normalized output..."
      />
    </div>
  );
};
export class BsonViewerTool {
  static Component = BsonViewerToolComponent;
}
