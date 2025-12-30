import React from 'react';
import {
  suggestIndex
} from './helpers';
import type {
  IndexAdvisorData
} from './tool-types';

const IndexAdvisorToolComponent = ({
  data,
  onChange
}: {
  data: IndexAdvisorData | undefined;
  onChange: (next: IndexAdvisorData) => void;
}) => {
  const table = data?.table ?? '';
  const columns = data?.columns ?? '';
  const unique = data?.unique ?? false;
  const output = data?.output ?? '';

  const handleSuggest = () => {
    const result = suggestIndex(
      table,
      columns
        .split(',')
        .map((entry) => entry.trim())
        .filter(Boolean),
      unique
    );
    onChange({ table, columns, unique, output: result });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Index Advisor</div>
      <input
        type="text"
        value={table}
        onChange={(event) =>
          onChange({ table: event.target.value, columns, unique, output })
        }
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Table name"
      />
      <input
        type="text"
        value={columns}
        onChange={(event) =>
          onChange({ table, columns: event.target.value, unique, output })
        }
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Columns (comma separated)"
      />
      <label className="flex items-center gap-2 text-[11px] text-slate-400">
        <input
          type="checkbox"
          checked={unique}
          onChange={(event) =>
            onChange({ table, columns, unique: event.target.checked, output })
          }
          className="h-3 w-3 rounded border border-slate-700 bg-slate-800 text-blue-500 focus:ring-0 focus:outline-none"
        />
        Unique index
      </label>
      <button
        type="button"
        onClick={handleSuggest}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Suggest Index
      </button>
      <textarea
        value={output}
        readOnly
        rows={3}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Suggested index..."
      />
    </div>
  );
};
export class IndexAdvisorTool {
  static Component = IndexAdvisorToolComponent;
}
