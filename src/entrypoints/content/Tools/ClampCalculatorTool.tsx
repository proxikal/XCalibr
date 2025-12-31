import React from 'react';

export type ClampCalculatorData = {
  minViewport?: number;
  maxViewport?: number;
  minFontSize?: number;
  maxFontSize?: number;
  unit?: 'px' | 'rem';
};

type Props = {
  data: ClampCalculatorData | undefined;
  onChange: (data: ClampCalculatorData) => void;
};

const ClampCalculator: React.FC<Props> = ({ data, onChange }) => {
  const minViewport = data?.minViewport ?? 320;
  const maxViewport = data?.maxViewport ?? 1200;
  const minFontSize = data?.minFontSize ?? 16;
  const maxFontSize = data?.maxFontSize ?? 24;
  const unit = data?.unit ?? 'px';

  const calculateClamp = () => {
    // Formula: clamp(min, preferredValue + vw, max)
    // preferredValue = minSize - (minViewport * slope)
    // slope = (maxSize - minSize) / (maxViewport - minViewport)

    const slope = (maxFontSize - minFontSize) / (maxViewport - minViewport);
    const yIntercept = minFontSize - slope * minViewport;

    // Convert to vw
    const vwValue = slope * 100; // slope * 100vw

    if (unit === 'rem') {
      const minRem = minFontSize / 16;
      const maxRem = maxFontSize / 16;
      const yInterceptRem = yIntercept / 16;

      return `clamp(${minRem.toFixed(4)}rem, ${yInterceptRem.toFixed(4)}rem + ${vwValue.toFixed(4)}vw, ${maxRem.toFixed(4)}rem)`;
    }

    return `clamp(${minFontSize}px, ${yIntercept.toFixed(4)}px + ${vwValue.toFixed(4)}vw, ${maxFontSize}px)`;
  };

  const clampOutput = calculateClamp();

  const copyOutput = () => {
    navigator.clipboard.writeText(clampOutput);
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Min Viewport (px)</label>
          <input
            type="number"
            min="0"
            value={minViewport}
            onChange={(e) => onChange({ ...data, minViewport: Math.max(0, Number(e.target.value)) })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Max Viewport (px)</label>
          <input
            type="number"
            min="0"
            value={maxViewport}
            onChange={(e) => onChange({ ...data, maxViewport: Math.max(0, Number(e.target.value)) })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white"
          />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Min Font Size (px)</label>
          <input
            type="number"
            min="1"
            value={minFontSize}
            onChange={(e) => onChange({ ...data, minFontSize: Math.max(1, Number(e.target.value)) })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Max Font Size (px)</label>
          <input
            type="number"
            min="1"
            value={maxFontSize}
            onChange={(e) => onChange({ ...data, maxFontSize: Math.max(1, Number(e.target.value)) })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white"
          />
        </div>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Output Unit</label>
        <div className="flex gap-2">
          <button
            onClick={() => onChange({ ...data, unit: 'px' })}
            className={`flex-1 py-2 rounded text-xs ${
              unit === 'px'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            px
          </button>
          <button
            onClick={() => onChange({ ...data, unit: 'rem' })}
            className={`flex-1 py-2 rounded text-xs ${
              unit === 'rem'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            rem
          </button>
        </div>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">CSS Output</label>
        <div className="bg-[#1a1a2e] border border-gray-700 rounded p-3">
          <code className="text-green-400 text-xs font-mono break-all">
            font-size: {clampOutput};
          </code>
        </div>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Preview</label>
        <div className="bg-[#1a1a2e] border border-gray-700 rounded p-3 text-center">
          <span
            className="text-white"
            style={{ fontSize: minFontSize }}
          >
            Min ({minFontSize}px)
          </span>
          <span className="text-gray-500 mx-2">→</span>
          <span
            className="text-white"
            style={{ fontSize: maxFontSize }}
          >
            Max ({maxFontSize}px)
          </span>
        </div>
      </div>

      <button
        onClick={copyOutput}
        className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded text-sm"
      >
        Copy CSS
      </button>

      <div className="text-xs text-gray-500 space-y-1">
        <p>Formula: clamp(min, preferred + slope, max)</p>
        <p>The font will scale smoothly between {minFontSize}px at {minViewport}px viewport and {maxFontSize}px at {maxViewport}px viewport.</p>
      </div>
    </div>
  );
};

export class ClampCalculatorTool {
  static Component = ClampCalculator;
}
