import React from 'react';
import {
  optimizeSvg
} from './helpers';
import type {
  SvgOptimizerData
} from './tool-types';

const SvgOptimizerToolComponent = ({
  data,
  onChange
}: {
  data: SvgOptimizerData | undefined;
  onChange: (next: SvgOptimizerData) => void;
}) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const handleOptimize = () => onChange({ input, output: optimizeSvg(input) });
  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">SVG Optimizer</div>
      <textarea
        value={input}
        onChange={(event) => onChange({ input: event.target.value, output })}
        rows={5}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="<svg>...</svg>"
      />
      <button
        type="button"
        onClick={handleOptimize}
        disabled={!input.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Optimize SVG
      </button>
      <textarea
        value={output}
        readOnly
        rows={5}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Optimized output..."
      />
    </div>
  );
};
export class SvgOptimizerTool {
  static Component = SvgOptimizerToolComponent;
}
