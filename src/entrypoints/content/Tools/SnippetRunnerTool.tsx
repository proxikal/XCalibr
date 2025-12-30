import React from 'react';
import type {
  SnippetRunnerData
} from './tool-types';

const SnippetRunnerToolComponent = ({
  data,
  onChange
}: {
  data: SnippetRunnerData | undefined;
  onChange: (next: SnippetRunnerData) => void;
}) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handleRun = () => {
    try {
      // eslint-disable-next-line no-new-func
      const result = new Function(input)();
      onChange({ input, output: String(result ?? ''), error: '' });
    } catch (err) {
      onChange({
        input,
        output: '',
        error: err instanceof Error ? err.message : 'Execution failed'
      });
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Console Snippet Runner</div>
      <textarea
        value={input}
        onChange={(event) => onChange({ input: event.target.value, output, error })}
        rows={5}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="JavaScript snippet..."
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
        Run Snippet
      </button>
      <textarea
        value={output}
        readOnly
        rows={3}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Output..."
      />
    </div>
  );
};
export class SnippetRunnerTool {
  static Component = SnippetRunnerToolComponent;
}
