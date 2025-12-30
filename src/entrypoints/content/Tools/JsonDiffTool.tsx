import React from 'react';
import {
  diffJson
} from './helpers';
import type {
  JsonDiffData
} from './tool-types';

const JsonDiffToolComponent = ({
  data,
  onChange
}: {
  data: JsonDiffData | undefined;
  onChange: (next: JsonDiffData) => void;
}) => {
  const left = data?.left ?? '';
  const right = data?.right ?? '';
  const diff = data?.diff ?? [];
  const error = data?.error ?? '';

  const handleDiff = () => {
    try {
      const leftParsed = JSON.parse(left);
      const rightParsed = JSON.parse(right);
      const result = diffJson(leftParsed, rightParsed);
      onChange({ left, right, diff: result, error: '' });
    } catch (err) {
      onChange({
        left,
        right,
        diff: [],
        error: err instanceof Error ? err.message : 'Invalid JSON'
      });
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">JSON Diff</div>
      <textarea
        value={left}
        onChange={(event) => onChange({ left: event.target.value, right, diff, error })}
        rows={4}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Left JSON..."
      />
      <textarea
        value={right}
        onChange={(event) => onChange({ left, right: event.target.value, diff, error })}
        rows={4}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Right JSON..."
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <button
        type="button"
        onClick={handleDiff}
        disabled={!left.trim() || !right.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Compare
      </button>
      <div className="rounded border border-slate-800 bg-slate-900/60 p-3 text-[11px] text-slate-300 max-h-32 overflow-y-auto no-scrollbar">
        {diff.length === 0 ? 'No differences found.' : diff.join('\n')}
      </div>
    </div>
  );
};
export class JsonDiffTool {
  static Component = JsonDiffToolComponent;
}
