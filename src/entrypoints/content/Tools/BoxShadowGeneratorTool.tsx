import React, { useMemo, useState } from 'react';
import type { BoxShadowGeneratorData } from './tool-types';

type Props = {
  data: BoxShadowGeneratorData | undefined;
  onChange: (next: BoxShadowGeneratorData) => void;
};

const BoxShadowGeneratorToolComponent = ({ data, onChange }: Props) => {
  const horizontalOffset = data?.horizontalOffset ?? 5;
  const verticalOffset = data?.verticalOffset ?? 5;
  const blurRadius = data?.blurRadius ?? 10;
  const spreadRadius = data?.spreadRadius ?? 0;
  const color = data?.color ?? 'rgba(0,0,0,0.25)';
  const inset = data?.inset ?? false;
  const [copied, setCopied] = useState(false);

  const cssOutput = useMemo(() => {
    const insetStr = inset ? 'inset ' : '';
    return `box-shadow: ${insetStr}${horizontalOffset}px ${verticalOffset}px ${blurRadius}px ${spreadRadius}px ${color};`;
  }, [horizontalOffset, verticalOffset, blurRadius, spreadRadius, color, inset]);

  const handleCopy = () => {
    navigator.clipboard.writeText(cssOutput);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Box Shadow Generator</div>

      <div className="flex justify-center py-4">
        <div
          className="w-24 h-24 bg-slate-700 rounded"
          style={{ boxShadow: cssOutput.replace('box-shadow: ', '').replace(';', '') }}
        />
      </div>

      <div className="space-y-2">
        <div className="space-y-1">
          <div className="flex justify-between text-[10px]">
            <span className="text-slate-400">Horizontal Offset</span>
            <span className="text-slate-300">{horizontalOffset}px</span>
          </div>
          <input
            type="range"
            min="-50"
            max="50"
            value={horizontalOffset}
            onChange={(e) => onChange({ ...data, horizontalOffset: Number(e.target.value) })}
            className="w-full"
          />
        </div>

        <div className="space-y-1">
          <div className="flex justify-between text-[10px]">
            <span className="text-slate-400">Vertical Offset</span>
            <span className="text-slate-300">{verticalOffset}px</span>
          </div>
          <input
            type="range"
            min="-50"
            max="50"
            value={verticalOffset}
            onChange={(e) => onChange({ ...data, verticalOffset: Number(e.target.value) })}
            className="w-full"
          />
        </div>

        <div className="space-y-1">
          <div className="flex justify-between text-[10px]">
            <span className="text-slate-400">Blur Radius</span>
            <span className="text-slate-300">{blurRadius}px</span>
          </div>
          <input
            type="range"
            min="0"
            max="100"
            value={blurRadius}
            onChange={(e) => onChange({ ...data, blurRadius: Number(e.target.value) })}
            className="w-full"
          />
        </div>

        <div className="space-y-1">
          <div className="flex justify-between text-[10px]">
            <span className="text-slate-400">Spread Radius</span>
            <span className="text-slate-300">{spreadRadius}px</span>
          </div>
          <input
            type="range"
            min="-50"
            max="50"
            value={spreadRadius}
            onChange={(e) => onChange({ ...data, spreadRadius: Number(e.target.value) })}
            className="w-full"
          />
        </div>

        <div className="grid grid-cols-2 gap-2">
          <div className="space-y-1">
            <div className="text-[10px] text-slate-400">Color</div>
            <input
              type="text"
              value={color}
              onChange={(e) => onChange({ ...data, color: e.target.value })}
              className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-emerald-500 font-mono"
            />
          </div>
          <label className="flex items-center gap-2 cursor-pointer pt-4">
            <input
              type="checkbox"
              checked={inset}
              onChange={(e) => onChange({ ...data, inset: e.target.checked })}
              className="w-4 h-4 rounded"
            />
            <span className="text-[11px] text-slate-300">Inset</span>
          </label>
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

export class BoxShadowGeneratorTool {
  static Component = BoxShadowGeneratorToolComponent;
}
