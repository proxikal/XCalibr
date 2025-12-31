import React, { useMemo, useState } from 'react';
import type { BorderRadiusGeneratorData } from './tool-types';

type Props = {
  data: BorderRadiusGeneratorData | undefined;
  onChange: (next: BorderRadiusGeneratorData) => void;
};

const BorderRadiusGeneratorToolComponent = ({ data, onChange }: Props) => {
  const topLeft = data?.topLeft ?? 10;
  const topRight = data?.topRight ?? 10;
  const bottomRight = data?.bottomRight ?? 10;
  const bottomLeft = data?.bottomLeft ?? 10;
  const unit = data?.unit ?? 'px';
  const [copied, setCopied] = useState(false);

  const cssOutput = useMemo(() => {
    const values = [topLeft, topRight, bottomRight, bottomLeft];
    const allSame = values.every(v => v === values[0]);
    if (allSame) {
      return `border-radius: ${topLeft}${unit};`;
    }
    return `border-radius: ${topLeft}${unit} ${topRight}${unit} ${bottomRight}${unit} ${bottomLeft}${unit};`;
  }, [topLeft, topRight, bottomRight, bottomLeft, unit]);

  const handleCopy = () => {
    navigator.clipboard.writeText(cssOutput);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Border Radius Generator</div>

      <div className="flex justify-center py-4">
        <div
          className="w-24 h-24 bg-emerald-600"
          style={{ borderRadius: `${topLeft}${unit} ${topRight}${unit} ${bottomRight}${unit} ${bottomLeft}${unit}` }}
        />
      </div>

      <div className="flex gap-2 justify-center mb-2">
        {(['px', '%'] as const).map((u) => (
          <button
            key={u}
            type="button"
            onClick={() => onChange({ ...data, unit: u })}
            className={`px-3 py-1 text-[10px] rounded ${
              unit === u
                ? 'bg-emerald-600 text-white'
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
            }`}
          >
            {u}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-2">
        <div className="space-y-1">
          <div className="flex justify-between text-[10px]">
            <span className="text-slate-400">Top Left</span>
            <span className="text-slate-300">{topLeft}{unit}</span>
          </div>
          <input
            type="range"
            min="0"
            max={unit === '%' ? 50 : 100}
            value={topLeft}
            onChange={(e) => onChange({ ...data, topLeft: Number(e.target.value) })}
            className="w-full"
          />
        </div>

        <div className="space-y-1">
          <div className="flex justify-between text-[10px]">
            <span className="text-slate-400">Top Right</span>
            <span className="text-slate-300">{topRight}{unit}</span>
          </div>
          <input
            type="range"
            min="0"
            max={unit === '%' ? 50 : 100}
            value={topRight}
            onChange={(e) => onChange({ ...data, topRight: Number(e.target.value) })}
            className="w-full"
          />
        </div>

        <div className="space-y-1">
          <div className="flex justify-between text-[10px]">
            <span className="text-slate-400">Bottom Left</span>
            <span className="text-slate-300">{bottomLeft}{unit}</span>
          </div>
          <input
            type="range"
            min="0"
            max={unit === '%' ? 50 : 100}
            value={bottomLeft}
            onChange={(e) => onChange({ ...data, bottomLeft: Number(e.target.value) })}
            className="w-full"
          />
        </div>

        <div className="space-y-1">
          <div className="flex justify-between text-[10px]">
            <span className="text-slate-400">Bottom Right</span>
            <span className="text-slate-300">{bottomRight}{unit}</span>
          </div>
          <input
            type="range"
            min="0"
            max={unit === '%' ? 50 : 100}
            value={bottomRight}
            onChange={(e) => onChange({ ...data, bottomRight: Number(e.target.value) })}
            className="w-full"
          />
        </div>
      </div>

      <div className="relative">
        <button
          type="button"
          onClick={handleCopy}
          className="absolute top-2 right-2 text-[10px] text-slate-400 hover:text-white"
        >
          {copied ? 'Copied!' : 'Copy'}
        </button>
        <pre className="bg-slate-900 border border-slate-700 rounded p-2 text-[10px] text-emerald-400 font-mono">
          {cssOutput}
        </pre>
      </div>
    </div>
  );
};

export class BorderRadiusGeneratorTool {
  static Component = BorderRadiusGeneratorToolComponent;
}
