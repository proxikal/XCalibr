import React from 'react';

export type CssFilterGeneratorData = {
  blur?: number;
  brightness?: number;
  contrast?: number;
  grayscale?: number;
  hueRotate?: number;
  invert?: number;
  opacity?: number;
  saturate?: number;
  sepia?: number;
};

type Props = {
  data: CssFilterGeneratorData;
  onChange: (data: CssFilterGeneratorData) => void;
};

const filterControls = [
  { key: 'blur', label: 'Blur', min: 0, max: 20, unit: 'px', defaultVal: 0 },
  { key: 'brightness', label: 'Brightness', min: 0, max: 200, unit: '%', defaultVal: 100 },
  { key: 'contrast', label: 'Contrast', min: 0, max: 200, unit: '%', defaultVal: 100 },
  { key: 'grayscale', label: 'Grayscale', min: 0, max: 100, unit: '%', defaultVal: 0 },
  { key: 'hueRotate', label: 'Hue Rotate', min: 0, max: 360, unit: 'deg', defaultVal: 0 },
  { key: 'invert', label: 'Invert', min: 0, max: 100, unit: '%', defaultVal: 0 },
  { key: 'opacity', label: 'Opacity', min: 0, max: 100, unit: '%', defaultVal: 100 },
  { key: 'saturate', label: 'Saturate', min: 0, max: 200, unit: '%', defaultVal: 100 },
  { key: 'sepia', label: 'Sepia', min: 0, max: 100, unit: '%', defaultVal: 0 }
] as const;

const CssFilterGenerator: React.FC<Props> = ({ data, onChange }) => {
  const getValue = (key: string) => {
    const control = filterControls.find((c) => c.key === key);
    return (data[key as keyof CssFilterGeneratorData] as number) ?? control?.defaultVal ?? 0;
  };

  const generateFilterCSS = () => {
    const filters: string[] = [];

    filterControls.forEach(({ key, unit, defaultVal }) => {
      const value = getValue(key);
      if (value !== defaultVal) {
        if (key === 'blur') {
          filters.push(`blur(${value}${unit})`);
        } else if (key === 'hueRotate') {
          filters.push(`hue-rotate(${value}${unit})`);
        } else {
          filters.push(`${key}(${value}${unit})`);
        }
      }
    });

    return filters.length > 0 ? filters.join(' ') : 'none';
  };

  const filterCSS = generateFilterCSS();

  const copyToClipboard = () => {
    navigator.clipboard.writeText(`filter: ${filterCSS};`);
  };

  const resetFilters = () => {
    onChange({});
  };

  return (
    <div className="space-y-4">
      <div className="space-y-3">
        {filterControls.map(({ key, label, min, max, unit }) => (
          <div key={key}>
            <div className="flex justify-between items-center mb-1">
              <label className="text-xs text-gray-400">{label}</label>
              <span className="text-xs text-gray-500">
                {getValue(key)}{unit}
              </span>
            </div>
            <input
              type="range"
              min={min}
              max={max}
              value={getValue(key)}
              onChange={(e) =>
                onChange({ ...data, [key]: Number(e.target.value) })
              }
              className="w-full"
            />
          </div>
        ))}
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Preview</label>
        <div className="relative w-full h-24 bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 rounded border border-gray-700 overflow-hidden">
          <div
            className="absolute inset-0 flex items-center justify-center text-white text-2xl font-bold"
            style={{ filter: filterCSS }}
          >
            Preview
          </div>
        </div>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">CSS Output</label>
        <div className="p-3 bg-[#1a1a2e] border border-gray-700 rounded font-mono text-xs text-green-400 break-all">
          filter: {filterCSS};
        </div>
      </div>

      <div className="flex gap-2">
        <button
          onClick={resetFilters}
          className="flex-1 py-2 bg-[#1a1a2e] border border-gray-700 hover:bg-gray-800 text-gray-300 rounded text-sm"
        >
          Reset
        </button>
        <button
          onClick={copyToClipboard}
          className="flex-1 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded text-sm"
        >
          Copy CSS
        </button>
      </div>
    </div>
  );
};

export class CssFilterGeneratorTool {
  static Component = CssFilterGenerator;
}
