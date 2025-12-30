import React from 'react';
import {
  formatSql
} from './helpers';
import type {
  SqlFormatterData
} from './tool-types';

const SqlFormatterToolComponent = ({
  data,
  onChange
}: {
  data: SqlFormatterData | undefined;
  onChange: (next: SqlFormatterData) => void;
}) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';

  const handleFormat = () => {
    onChange({ input, output: formatSql(input) });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">SQL Formatter</div>
      <textarea
        value={input}
        onChange={(event) => onChange({ input: event.target.value, output })}
        rows={6}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Paste SQL here..."
      />
      <button
        type="button"
        onClick={handleFormat}
        disabled={!input.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Format SQL
      </button>
      <textarea
        value={output}
        readOnly
        rows={6}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Formatted output..."
      />
    </div>
  );
};
export class SqlFormatterTool {
  static Component = SqlFormatterToolComponent;
}
