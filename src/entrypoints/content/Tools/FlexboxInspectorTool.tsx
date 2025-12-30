import React from 'react';
import type {
  FlexboxInspectorData
} from './tool-types';

const FlexboxInspectorToolComponent = ({
  data,
  onChange
}: {
  data: FlexboxInspectorData | undefined;
  onChange: (next: FlexboxInspectorData) => void;
}) => {
  const selector = data?.selector ?? '';
  const output = data?.output ?? [];

  const handleInspect = () => {
    const element = document.querySelector(selector);
    if (!element) {
      onChange({ selector, output: ['Element not found.'] });
      return;
    }
    const style = window.getComputedStyle(element);
    onChange({
      selector,
      output: [
        `display: ${style.display}`,
        `flex-direction: ${style.flexDirection}`,
        `justify-content: ${style.justifyContent}`,
        `align-items: ${style.alignItems}`,
        `gap: ${style.gap}`
      ]
    });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Flexbox Inspector</div>
      <input
        type="text"
        value={selector}
        onChange={(event) => onChange({ selector: event.target.value, output })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="CSS selector (e.g. .container)"
      />
      <button
        type="button"
        onClick={handleInspect}
        disabled={!selector.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Inspect
      </button>
      <div className="rounded border border-slate-800 bg-slate-900/60 p-3 text-[11px] text-slate-300">
        {output.length === 0 ? 'No data yet.' : output.join('\n')}
      </div>
    </div>
  );
};
export class FlexboxInspectorTool {
  static Component = FlexboxInspectorToolComponent;
}
