import React from 'react';

export type UnitConverterData = {
  value?: number;
  category?: string;
  fromUnit?: string;
  results?: { unit: string; value: string }[];
};

type Props = {
  data: UnitConverterData | undefined;
  onChange: (data: UnitConverterData) => void;
};

const categories: Record<string, { units: Record<string, number>; base: string }> = {
  length: {
    base: 'px',
    units: {
      px: 1,
      rem: 16,
      em: 16,
      pt: 1.333333,
      in: 96,
      cm: 37.795275591,
      mm: 3.7795275591
    }
  },
  storage: {
    base: 'bytes',
    units: {
      bytes: 1,
      KB: 1024,
      MB: 1024 * 1024,
      GB: 1024 * 1024 * 1024,
      TB: 1024 * 1024 * 1024 * 1024
    }
  },
  time: {
    base: 'ms',
    units: {
      ms: 1,
      seconds: 1000,
      minutes: 60000,
      hours: 3600000,
      days: 86400000
    }
  },
  angle: {
    base: 'deg',
    units: {
      deg: 1,
      rad: 57.2957795131,
      turn: 360,
      grad: 0.9
    }
  }
};

const UnitConverter: React.FC<Props> = ({ data, onChange }) => {
  const value = data?.value ?? 16;
  const category = data?.category ?? 'length';
  const fromUnit = data?.fromUnit ?? 'px';
  const results = data?.results ?? [];

  const handleConvert = () => {
    const cat = categories[category];
    if (!cat) return;

    const baseValue = value * cat.units[fromUnit];
    const conversions = Object.entries(cat.units).map(([unit, factor]) => ({
      unit,
      value: (baseValue / factor).toFixed(unit === 'bytes' ? 0 : 4).replace(/\.?0+$/, '')
    }));

    onChange({ ...data, results: conversions });
  };

  const currentUnits = categories[category]?.units ?? {};

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Category</label>
          <select
            value={category}
            onChange={(e) => onChange({
              ...data,
              category: e.target.value,
              fromUnit: Object.keys(categories[e.target.value].units)[0],
              results: []
            })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          >
            <option value="length">Length (px, rem, em)</option>
            <option value="storage">Storage (bytes, KB, MB)</option>
            <option value="time">Time (ms, sec, min)</option>
            <option value="angle">Angle (deg, rad)</option>
          </select>
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">From Unit</label>
          <select
            value={fromUnit}
            onChange={(e) => onChange({ ...data, fromUnit: e.target.value })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          >
            {Object.keys(currentUnits).map(unit => (
              <option key={unit} value={unit}>{unit}</option>
            ))}
          </select>
        </div>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Value</label>
        <input
          type="number"
          value={value}
          onChange={(e) => onChange({ ...data, value: parseFloat(e.target.value) || 0 })}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-sm"
        />
      </div>

      <button
        onClick={handleConvert}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-sm"
      >
        Convert
      </button>

      {results.length > 0 && (
        <div className="space-y-1">
          {results.map((r, idx) => (
            <div
              key={idx}
              className={`flex justify-between items-center p-2 rounded text-sm ${
                r.unit === fromUnit
                  ? 'bg-blue-900/30 border border-blue-700'
                  : 'bg-[#1a1a2e]'
              }`}
              onClick={() => navigator.clipboard.writeText(r.value)}
              style={{ cursor: 'pointer' }}
              title="Click to copy"
            >
              <span className="text-gray-300">{r.unit}</span>
              <span className="font-mono text-green-400">{r.value}</span>
            </div>
          ))}
        </div>
      )}

      <div className="text-xs text-gray-500">
        Click any result to copy value
      </div>
    </div>
  );
};

export class UnitConverterTool {
  static Component = UnitConverter;
}
