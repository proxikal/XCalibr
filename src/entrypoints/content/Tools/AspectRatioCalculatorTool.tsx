import React from 'react';

export type AspectRatioCalculatorData = {
  width?: number;
  height?: number;
  ratio?: string;
  newWidth?: number;
  newHeight?: number;
  mode?: 'calculate' | 'resize';
};

type Props = {
  data: AspectRatioCalculatorData | undefined;
  onChange: (data: AspectRatioCalculatorData) => void;
};

const commonRatios = [
  { label: '16:9 (HD)', width: 16, height: 9 },
  { label: '4:3 (Standard)', width: 4, height: 3 },
  { label: '21:9 (Ultrawide)', width: 21, height: 9 },
  { label: '1:1 (Square)', width: 1, height: 1 },
  { label: '3:2 (Photo)', width: 3, height: 2 },
  { label: '2:3 (Portrait)', width: 2, height: 3 },
  { label: '9:16 (Mobile)', width: 9, height: 16 }
];

const gcd = (a: number, b: number): number => {
  return b === 0 ? a : gcd(b, a % b);
};

const AspectRatioCalculator: React.FC<Props> = ({ data, onChange }) => {
  const width = data?.width ?? 1920;
  const height = data?.height ?? 1080;
  const ratio = data?.ratio ?? '';
  const newWidth = data?.newWidth ?? 0;
  const newHeight = data?.newHeight ?? 0;
  const mode = data?.mode ?? 'calculate';

  const handleCalculate = () => {
    const divisor = gcd(width, height);
    const ratioW = width / divisor;
    const ratioH = height / divisor;
    onChange({ ...data, ratio: `${ratioW}:${ratioH}` });
  };

  const handlePreset = (w: number, h: number) => {
    onChange({ ...data, width: w * 100, height: h * 100, ratio: `${w}:${h}` });
  };

  const handleResizeByWidth = () => {
    if (!newWidth || !width || !height) return;
    const aspectRatio = height / width;
    const calculatedHeight = Math.round(newWidth * aspectRatio);
    onChange({ ...data, newHeight: calculatedHeight });
  };

  const handleResizeByHeight = () => {
    if (!newHeight || !width || !height) return;
    const aspectRatio = width / height;
    const calculatedWidth = Math.round(newHeight * aspectRatio);
    onChange({ ...data, newWidth: calculatedWidth });
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-2 mb-2">
        <button
          onClick={() => onChange({ ...data, mode: 'calculate' })}
          className={`flex-1 py-1.5 rounded text-xs ${
            mode === 'calculate' ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300'
          }`}
        >
          Calculate Ratio
        </button>
        <button
          onClick={() => onChange({ ...data, mode: 'resize' })}
          className={`flex-1 py-1.5 rounded text-xs ${
            mode === 'resize' ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300'
          }`}
        >
          Resize
        </button>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Width</label>
          <input
            type="number"
            value={width}
            onChange={(e) => onChange({ ...data, width: parseInt(e.target.value) || 0 })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-sm"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Height</label>
          <input
            type="number"
            value={height}
            onChange={(e) => onChange({ ...data, height: parseInt(e.target.value) || 0 })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-sm"
          />
        </div>
      </div>

      {mode === 'calculate' && (
        <>
          <button
            onClick={handleCalculate}
            className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-sm"
          >
            Calculate Ratio
          </button>

          {ratio && (
            <div className="bg-[#0d0d1a] border border-gray-700 rounded p-3 text-center">
              <div className="text-xs text-gray-400 mb-1">Aspect Ratio</div>
              <div className="text-2xl font-mono text-green-400">{ratio}</div>
            </div>
          )}

          <div>
            <div className="text-xs text-gray-400 mb-2">Common Presets</div>
            <div className="grid grid-cols-2 gap-1">
              {commonRatios.map((r) => (
                <button
                  key={r.label}
                  onClick={() => handlePreset(r.width, r.height)}
                  className="py-1.5 px-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-xs"
                >
                  {r.label}
                </button>
              ))}
            </div>
          </div>
        </>
      )}

      {mode === 'resize' && (
        <div className="space-y-3">
          <div className="text-xs text-gray-400">
            Resize while preserving aspect ratio ({width}x{height})
          </div>

          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="block text-xs text-gray-400 mb-1">New Width</label>
              <input
                type="number"
                value={newWidth || ''}
                onChange={(e) => onChange({ ...data, newWidth: parseInt(e.target.value) || 0 })}
                placeholder="Enter width..."
                className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-sm"
              />
              <button
                onClick={handleResizeByWidth}
                className="w-full mt-1 py-1.5 bg-green-600 hover:bg-green-500 text-white rounded text-xs"
              >
                Calculate Height
              </button>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">New Height</label>
              <input
                type="number"
                value={newHeight || ''}
                onChange={(e) => onChange({ ...data, newHeight: parseInt(e.target.value) || 0 })}
                placeholder="Enter height..."
                className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-sm"
              />
              <button
                onClick={handleResizeByHeight}
                className="w-full mt-1 py-1.5 bg-green-600 hover:bg-green-500 text-white rounded text-xs"
              >
                Calculate Width
              </button>
            </div>
          </div>

          {newWidth > 0 && newHeight > 0 && (
            <div className="bg-[#0d0d1a] border border-gray-700 rounded p-3 text-center">
              <div className="text-xs text-gray-400 mb-1">New Dimensions</div>
              <div className="text-xl font-mono text-green-400">
                {newWidth} x {newHeight}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export class AspectRatioCalculatorTool {
  static Component = AspectRatioCalculator;
}
