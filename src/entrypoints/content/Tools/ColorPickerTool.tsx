import React from 'react';
import {
  hexToRgb
} from './helpers';
import type {
  ColorPickerData,
  ColorHistoryEntry
} from './tool-types';

interface EyeDropperResult {
  sRGBHex: string;
}

interface EyeDropperConstructor {
  new (): { open: () => Promise<EyeDropperResult> };
}

const generateId = () =>
  typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID()
    : `color_${Date.now()}_${Math.random().toString(16).slice(2)}`;

const ColorPickerToolComponent = ({
  data,
  onChange
}: {
  data: ColorPickerData | undefined;
  onChange: (next: ColorPickerData) => void;
}) => {
  const color = data?.color ?? '#2563eb';
  const history = data?.history ?? [];
  const rgb = hexToRgb(color);
  const rgbLabel = rgb ? `rgb(${rgb.r}, ${rgb.g}, ${rgb.b})` : 'Invalid HEX';
  const rgbaLabel = rgb
    ? `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, 1)`
    : 'Invalid HEX';

  const addToHistory = (hex: string) => {
    const rgbValue = hexToRgb(hex);
    if (!rgbValue) return;

    const entry: ColorHistoryEntry = {
      id: generateId(),
      timestamp: Date.now(),
      hex,
      rgb: `rgb(${rgbValue.r}, ${rgbValue.g}, ${rgbValue.b})`
    };

    onChange({
      color: hex,
      history: [entry, ...history.filter((e) => e.hex !== hex)].slice(0, 20)
    });
  };

  const pickFromPage = async () => {
    if (!('EyeDropper' in window)) return;
    try {
      const dropper = new (window as Window & { EyeDropper: EyeDropperConstructor })
        .EyeDropper();
      const result = await dropper.open();
      addToHistory(result.sRGBHex);
    } catch {
      // User cancelled the eye dropper.
    }
  };

  const handleColorChange = (newColor: string) => {
    onChange({ ...data, color: newColor });
  };

  const handleColorCommit = () => {
    if (hexToRgb(color)) {
      addToHistory(color);
    }
  };

  const handleSelectHistoryItem = (entry: ColorHistoryEntry) => {
    onChange({ ...data, color: entry.hex });
  };

  const handleRemoveHistoryItem = (id: string) => {
    onChange({
      ...data,
      history: history.filter((entry) => entry.id !== id)
    });
  };

  const handleExport = () => {
    const json = JSON.stringify(history, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `color-history-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleClearHistory = () => {
    onChange({ ...data, history: [] });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Color Picker</div>
      <div className="flex items-center gap-3">
        <input
          type="color"
          value={color}
          onChange={(event) => handleColorChange(event.target.value)}
          onBlur={handleColorCommit}
          className="h-10 w-10 rounded border border-slate-700 bg-slate-800 cursor-pointer"
        />
        <div className="text-xs text-slate-400">
          Pick a color or use the page picker.
        </div>
      </div>
      <button
        type="button"
        className="w-full rounded bg-slate-800 px-2 py-1 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
        onClick={pickFromPage}
        disabled={!('EyeDropper' in window)}
      >
        {('EyeDropper' in window) ? 'Pick from page' : 'EyeDropper not supported'}
      </button>
      <div className="flex items-center gap-2">
        <input
          type="text"
          value={color}
          onChange={(event) => handleColorChange(event.target.value)}
          onBlur={handleColorCommit}
          onKeyDown={(event) => {
            if (event.key === 'Enter') handleColorCommit();
          }}
          className="flex-1 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        />
        <button
          type="button"
          className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
          onClick={() => navigator.clipboard.writeText(color)}
        >
          Copy
        </button>
      </div>
      <div className="space-y-1 text-[11px] text-slate-400">
        <div>HEX: <span className="text-slate-200">{color}</span></div>
        <div>RGB: <span className="text-slate-200">{rgbLabel}</span></div>
        <div>RGBA: <span className="text-slate-200">{rgbaLabel}</span></div>
      </div>

      {history.length > 0 && (
        <>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={handleExport}
              className="flex-1 rounded bg-slate-800 px-2 py-1 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
            >
              Export JSON
            </button>
            <button
              type="button"
              onClick={handleClearHistory}
              className="flex-1 rounded bg-slate-800 px-2 py-1 text-xs text-rose-300 hover:bg-slate-700 transition-colors"
            >
              Clear History
            </button>
          </div>

          <div className="text-[10px] text-slate-500 uppercase tracking-wide">
            History
          </div>
          <div className="flex flex-wrap gap-1">
            {history.map((entry) => (
              <div
                key={entry.id}
                className="group relative"
              >
                <button
                  type="button"
                  onClick={() => handleSelectHistoryItem(entry)}
                  className="w-6 h-6 rounded border border-slate-700 hover:border-blue-500 transition-colors"
                  style={{ backgroundColor: entry.hex }}
                  title={`${entry.hex}\n${entry.rgb}\n${new Date(entry.timestamp).toLocaleString()}`}
                />
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    handleRemoveHistoryItem(entry.id);
                  }}
                  className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-slate-800 border border-slate-600 text-[8px] text-slate-400 hover:text-rose-400 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center"
                >
                  ×
                </button>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
};
export class ColorPickerTool {
  static Component = ColorPickerToolComponent;
}
