import React from 'react';

export type ColorStop = {
  color: string;
  position: number;
};

export type CssGradientGeneratorData = {
  type?: 'linear' | 'radial' | 'conic';
  angle?: number;
  colorStops?: ColorStop[];
  output?: string;
};

type Props = {
  data: CssGradientGeneratorData;
  onChange: (data: CssGradientGeneratorData) => void;
};

const CssGradientGenerator: React.FC<Props> = ({ data, onChange }) => {
  const type = data.type || 'linear';
  const angle = data.angle ?? 90;
  const colorStops = data.colorStops || [
    { color: '#667eea', position: 0 },
    { color: '#764ba2', position: 100 }
  ];

  const generateGradientCSS = () => {
    const stops = [...colorStops]
      .sort((a, b) => a.position - b.position)
      .map((stop) => `${stop.color} ${stop.position}%`)
      .join(', ');

    switch (type) {
      case 'radial':
        return `radial-gradient(circle, ${stops})`;
      case 'conic':
        return `conic-gradient(from ${angle}deg, ${stops})`;
      default:
        return `linear-gradient(${angle}deg, ${stops})`;
    }
  };

  const gradientCSS = generateGradientCSS();

  const updateColorStop = (index: number, updates: Partial<ColorStop>) => {
    const newStops = colorStops.map((stop, i) =>
      i === index ? { ...stop, ...updates } : stop
    );
    onChange({ ...data, colorStops: newStops });
  };

  const addColorStop = () => {
    const newPosition = colorStops.length > 0
      ? Math.min(100, Math.max(...colorStops.map(s => s.position)) + 10)
      : 50;
    onChange({
      ...data,
      colorStops: [...colorStops, { color: '#ffffff', position: newPosition }]
    });
  };

  const removeColorStop = (index: number) => {
    if (colorStops.length <= 2) return;
    onChange({
      ...data,
      colorStops: colorStops.filter((_, i) => i !== index)
    });
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(`background: ${gradientCSS};`);
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">Gradient Type</label>
        <div className="flex gap-2">
          {(['linear', 'radial', 'conic'] as const).map((t) => (
            <button
              key={t}
              onClick={() => onChange({ ...data, type: t })}
              className={`flex-1 py-2 rounded text-sm capitalize ${
                type === t
                  ? 'bg-indigo-600 text-white'
                  : 'bg-[#1a1a2e] text-gray-400 border border-gray-700'
              }`}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {(type === 'linear' || type === 'conic') && (
        <div>
          <label className="block text-xs text-gray-400 mb-1">
            Angle: {angle}°
          </label>
          <input
            type="range"
            min="0"
            max="360"
            value={angle}
            onChange={(e) => onChange({ ...data, angle: Number(e.target.value) })}
            className="w-full"
          />
        </div>
      )}

      <div>
        <div className="flex justify-between items-center mb-2">
          <label className="text-xs text-gray-400">Color Stops</label>
          <button
            onClick={addColorStop}
            className="text-xs text-indigo-400 hover:text-indigo-300"
          >
            + Add Stop
          </button>
        </div>
        <div className="space-y-2">
          {colorStops.map((stop, index) => (
            <div key={index} className="flex items-center gap-2">
              <input
                type="color"
                value={stop.color}
                onChange={(e) => updateColorStop(index, { color: e.target.value })}
                className="w-10 h-8 bg-transparent border border-gray-700 rounded cursor-pointer"
              />
              <input
                type="text"
                value={stop.color}
                onChange={(e) => updateColorStop(index, { color: e.target.value })}
                className="w-24 px-2 py-1 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-sm"
              />
              <input
                type="number"
                min="0"
                max="100"
                value={stop.position}
                onChange={(e) => updateColorStop(index, { position: Number(e.target.value) })}
                className="w-16 px-2 py-1 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
              />
              <span className="text-gray-400 text-sm">%</span>
              {colorStops.length > 2 && (
                <button
                  onClick={() => removeColorStop(index)}
                  className="text-red-400 hover:text-red-300 text-sm"
                >
                  ×
                </button>
              )}
            </div>
          ))}
        </div>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Preview</label>
        <div
          className="w-full h-24 rounded border border-gray-700"
          style={{ background: gradientCSS }}
        />
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">CSS Output</label>
        <div className="p-3 bg-[#1a1a2e] border border-gray-700 rounded font-mono text-xs text-green-400 break-all">
          background: {gradientCSS};
        </div>
      </div>

      <button
        onClick={copyToClipboard}
        className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded text-sm"
      >
        Copy CSS
      </button>
    </div>
  );
};

export class CssGradientGeneratorTool {
  static Component = CssGradientGenerator;
}
