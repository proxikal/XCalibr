import React from 'react';
import {
  runRegexTest
} from './helpers';
import type {
  RegexTesterData
} from './tool-types';

const RegexTesterToolComponent = ({
  data,
  onChange
}: {
  data: RegexTesterData | undefined;
  onChange: (next: RegexTesterData) => void;
}) => {
  const pattern = data?.pattern ?? '';
  const flags = data?.flags ?? 'g';
  const text = data?.text ?? '';
  const matches = data?.matches ?? [];
  const error = data?.error ?? '';

  const handleTest = () => {
    const result = runRegexTest(pattern, flags, text);
    onChange({ pattern, flags, text, matches: result.matches, error: result.error ?? '' });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Regex Tester</div>
      <input
        type="text"
        value={pattern}
        onChange={(event) => onChange({ pattern: event.target.value, flags, text, matches, error })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder="Regex pattern"
      />
      <input
        type="text"
        value={flags}
        onChange={(event) => onChange({ pattern, flags: event.target.value, text, matches, error })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder="Flags (e.g. gi)"
      />
      <textarea
        value={text}
        onChange={(event) => onChange({ pattern, flags, text: event.target.value, matches, error })}
        rows={4}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder="Test string..."
      />
      {error ? <div className="text-[11px] text-rose-300">{error}</div> : null}
      <button
        type="button"
        onClick={handleTest}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Run Test
      </button>
      <div className="rounded border border-slate-800 bg-slate-900/60 p-3 text-[11px] text-slate-300 max-h-24 overflow-y-auto no-scrollbar">
        {matches.length === 0 ? 'No matches.' : matches.join('\n')}
      </div>
    </div>
  );
};
export class RegexTesterTool {
  static Component = RegexTesterToolComponent;
}
