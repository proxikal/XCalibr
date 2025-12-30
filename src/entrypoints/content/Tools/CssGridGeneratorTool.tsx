import React from 'react';
import type {
  CssGridGeneratorData
} from './tool-types';

const CssGridGeneratorToolComponent = ({
  data,
  onChange
}: {
  data: CssGridGeneratorData | undefined;
  onChange: (next: CssGridGeneratorData) => void;
}) => {
  const columns = data?.columns ?? 'repeat(3, 1fr)';
  const rows = data?.rows ?? 'auto';
  const gap = data?.gap ?? '16px';
  const output = data?.output ?? '';

  const handleGenerate = () => {
    const css = `display: grid;\n grid-template-columns: ${columns};\n grid-template-rows: ${rows};\n gap: ${gap};`;
    onChange({ columns, rows, gap, output: css });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">CSS Grid Generator</div>
      <input
        type="text"
        value={columns}
        onChange={(event) => onChange({ columns: event.target.value, rows, gap, output })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Columns (e.g. repeat(3, 1fr))"
      />
      <input
        type="text"
        value={rows}
        onChange={(event) => onChange({ columns, rows: event.target.value, gap, output })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Rows (e.g. auto)"
      />
      <input
        type="text"
        value={gap}
        onChange={(event) => onChange({ columns, rows, gap: event.target.value, output })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Gap (e.g. 16px)"
      />
      <button
        type="button"
        onClick={handleGenerate}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Generate CSS
      </button>
      <textarea
        value={output}
        readOnly
        rows={4}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="CSS output..."
      />
    </div>
  );
};
export class CssGridGeneratorTool {
  static Component = CssGridGeneratorToolComponent;
}
