import React from 'react';
import {
  resolveJsonPath
} from './helpers';
import type {
  JsonPathTesterData
} from './tool-types';

const JsonPathTesterToolComponent = ({
  data,
  onChange
}: {
  data: JsonPathTesterData | undefined;
  onChange: (next: JsonPathTesterData) => void;
}) => {
  const input = data?.input ?? '';
  const path = data?.path ?? '$';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handleRun = () => {
    try {
      const parsed = JSON.parse(input);
      const result = resolveJsonPath(parsed, path);
      onChange({
        input,
        path,
        output: JSON.stringify(result, null, 2),
        error: ''
      });
    } catch (err) {
      onChange({
        input,
        path,
        output: '',
        error: err instanceof Error ? err.message : 'Invalid JSON'
      });
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">JSON Path Tester</div>
      <input
        type="text"
        value={path}
        onChange={(event) => onChange({ input, path: event.target.value, output, error })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="$.items[0].name"
      />
      <textarea
        value={input}
        onChange={(event) =>
          onChange({ input: event.target.value, path, output, error })
        }
        rows={6}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Paste JSON data..."
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <button
        type="button"
        onClick={handleRun}
        disabled={!input.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Run Path
      </button>
      <textarea
        value={output}
        readOnly
        rows={4}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Result..."
      />
    </div>
  );
};
export class JsonPathTesterTool {
  static Component = JsonPathTesterToolComponent;
}
