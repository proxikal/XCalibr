import React from 'react';
import {
  contrastRatio
} from './helpers';
import type {
  ContrastCheckerData
} from './tool-types';

const ContrastCheckerToolComponent = ({
  data,
  onChange
}: {
  data: ContrastCheckerData | undefined;
  onChange: (next: ContrastCheckerData) => void;
}) => {
  const foreground = data?.foreground ?? '#0f172a';
  const background = data?.background ?? '#ffffff';
  const ratio = data?.ratio ?? '';
  const status = data?.status ?? '';

  const handleCheck = () => {
    const result = contrastRatio(foreground, background);
    if (!result) {
      onChange({ foreground, background, ratio: '', status: 'Invalid colors.' });
      return;
    }
    const rounded = result.toFixed(2);
    const passAA = result >= 4.5;
    const passAAA = result >= 7;
    onChange({
      foreground,
      background,
      ratio: rounded,
      status: passAAA ? 'AAA Pass' : passAA ? 'AA Pass' : 'Fail'
    });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Contrast Checker</div>
      <div className="flex gap-2">
        <input
          type="color"
          value={foreground}
          onChange={(event) =>
            onChange({ foreground: event.target.value, background, ratio, status })
          }
          className="h-10 w-10 rounded border border-slate-700 bg-slate-800"
        />
        <input
          type="color"
          value={background}
          onChange={(event) =>
            onChange({ foreground, background: event.target.value, ratio, status })
          }
          className="h-10 w-10 rounded border border-slate-700 bg-slate-800"
        />
        <div className="flex-1 text-[11px] text-slate-500 flex items-center">
          Ratio: {ratio || '—'} ({status || '—'})
        </div>
      </div>
      <button
        type="button"
        onClick={handleCheck}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Check Contrast
      </button>
    </div>
  );
};
export class ContrastCheckerTool {
  static Component = ContrastCheckerToolComponent;
}
