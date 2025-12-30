import React from 'react';
import {
  lintFirebaseRules
} from './helpers';
import type {
  FirebaseRulesLinterData
} from './tool-types';

const FirebaseRulesLinterToolComponent = ({
  data,
  onChange
}: {
  data: FirebaseRulesLinterData | undefined;
  onChange: (next: FirebaseRulesLinterData) => void;
}) => {
  const input = data?.input ?? '';
  const warnings = data?.warnings ?? [];
  const error = data?.error ?? '';

  const handleLint = () => {
    try {
      const parsed = JSON.parse(input);
      const result = lintFirebaseRules(parsed);
      onChange({ input, warnings: result, error: '' });
    } catch (err) {
      onChange({
        input,
        warnings: [],
        error: err instanceof Error ? err.message : 'Invalid JSON'
      });
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Firebase Rules Linter</div>
      <textarea
        value={input}
        onChange={(event) => onChange({ input: event.target.value, warnings, error })}
        rows={6}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Paste rules JSON..."
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <button
        type="button"
        onClick={handleLint}
        disabled={!input.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Lint Rules
      </button>
      <div className="rounded border border-slate-800 bg-slate-900/60 p-3 text-[11px] text-slate-300 max-h-32 overflow-y-auto no-scrollbar">
        {warnings.length === 0 ? 'No warnings.' : warnings.join('\n')}
      </div>
    </div>
  );
};
export class FirebaseRulesLinterTool {
  static Component = FirebaseRulesLinterToolComponent;
}
