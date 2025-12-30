import React from 'react';
import {
  jsonArrayToCsv
} from './helpers';
import type {
  SqlToCsvData
} from './tool-types';

const SqlToCsvToolComponent = ({
  data,
  onChange
}: {
  data: SqlToCsvData | undefined;
  onChange: (next: SqlToCsvData) => void;
}) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handleConvert = () => {
    try {
      const parsed = JSON.parse(input);
      const csv = jsonArrayToCsv(parsed);
      if (!csv) {
        onChange({ input, output: '', error: 'Input must be a JSON array.' });
        return;
      }
      onChange({ input, output: csv, error: '' });
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
      <div className="text-xs text-slate-200">SQL to CSV</div>
      <textarea
        value={input}
        onChange={(event) => onChange({ input: event.target.value, output, error })}
        rows={6}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Paste JSON array from SQL result..."
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <div className="flex gap-2">
        <button
          type="button"
          onClick={handleConvert}
          disabled={!input.trim()}
          className="flex-1 rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          Convert
        </button>
        <button
          type="button"
          onClick={() => navigator.clipboard.writeText(output)}
          disabled={!output}
          className="flex-1 rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          Copy
        </button>
      </div>
      <textarea
        value={output}
        readOnly
        rows={4}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="CSV output..."
      />
    </div>
  );
};
export class SqlToCsvTool {
  static Component = SqlToCsvToolComponent;
}
