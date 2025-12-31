import React from 'react';

export type CssTransformGeneratorData = {
  translateX?: number;
  translateY?: number;
  rotate?: number;
  scaleX?: number;
  scaleY?: number;
  skewX?: number;
  skewY?: number;
};

type Props = {
  data: CssTransformGeneratorData;
  onChange: (data: CssTransformGeneratorData) => void;
};

const CssTransformGenerator: React.FC<Props> = ({ data, onChange }) => {
  const translateX = data.translateX ?? 0;
  const translateY = data.translateY ?? 0;
  const rotate = data.rotate ?? 0;
  const scaleX = data.scaleX ?? 1;
  const scaleY = data.scaleY ?? 1;
  const skewX = data.skewX ?? 0;
  const skewY = data.skewY ?? 0;

  const generateTransformCSS = () => {
    const transforms: string[] = [];

    if (translateX !== 0 || translateY !== 0) {
      transforms.push(`translate(${translateX}px, ${translateY}px)`);
    }
    if (rotate !== 0) {
      transforms.push(`rotate(${rotate}deg)`);
    }
    if (scaleX !== 1 || scaleY !== 1) {
      transforms.push(`scale(${scaleX}, ${scaleY})`);
    }
    if (skewX !== 0 || skewY !== 0) {
      transforms.push(`skew(${skewX}deg, ${skewY}deg)`);
    }

    return transforms.length > 0 ? transforms.join(' ') : 'none';
  };

  const transformCSS = generateTransformCSS();

  const copyToClipboard = () => {
    navigator.clipboard.writeText(`transform: ${transformCSS};`);
  };

  const resetTransforms = () => {
    onChange({});
  };

  return (
    <div className="space-y-4">
      <div className="space-y-3">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Translate X: {translateX}px</label>
          <input
            type="range"
            min="-200"
            max="200"
            value={translateX}
            onChange={(e) => onChange({ ...data, translateX: Number(e.target.value) })}
            className="w-full"
          />
        </div>

        <div>
          <label className="block text-xs text-gray-400 mb-1">Translate Y: {translateY}px</label>
          <input
            type="range"
            min="-200"
            max="200"
            value={translateY}
            onChange={(e) => onChange({ ...data, translateY: Number(e.target.value) })}
            className="w-full"
          />
        </div>

        <div>
          <label className="block text-xs text-gray-400 mb-1">Rotate: {rotate}°</label>
          <input
            type="range"
            min="-180"
            max="180"
            value={rotate}
            onChange={(e) => onChange({ ...data, rotate: Number(e.target.value) })}
            className="w-full"
          />
        </div>

        <div>
          <label className="block text-xs text-gray-400 mb-1">Scale X: {scaleX.toFixed(1)}</label>
          <input
            type="range"
            min="0"
            max="3"
            step="0.1"
            value={scaleX}
            onChange={(e) => onChange({ ...data, scaleX: Number(e.target.value) })}
            className="w-full"
          />
        </div>

        <div>
          <label className="block text-xs text-gray-400 mb-1">Scale Y: {scaleY.toFixed(1)}</label>
          <input
            type="range"
            min="0"
            max="3"
            step="0.1"
            value={scaleY}
            onChange={(e) => onChange({ ...data, scaleY: Number(e.target.value) })}
            className="w-full"
          />
        </div>

        <div>
          <label className="block text-xs text-gray-400 mb-1">Skew X: {skewX}°</label>
          <input
            type="range"
            min="-45"
            max="45"
            value={skewX}
            onChange={(e) => onChange({ ...data, skewX: Number(e.target.value) })}
            className="w-full"
          />
        </div>

        <div>
          <label className="block text-xs text-gray-400 mb-1">Skew Y: {skewY}°</label>
          <input
            type="range"
            min="-45"
            max="45"
            value={skewY}
            onChange={(e) => onChange({ ...data, skewY: Number(e.target.value) })}
            className="w-full"
          />
        </div>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Preview</label>
        <div className="relative w-full h-24 bg-[#1a1a2e] border border-gray-700 rounded overflow-hidden flex items-center justify-center">
          <div
            className="w-12 h-12 bg-indigo-500 rounded"
            style={{ transform: transformCSS }}
          />
        </div>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">CSS Output</label>
        <div className="p-3 bg-[#1a1a2e] border border-gray-700 rounded font-mono text-xs text-green-400 break-all">
          transform: {transformCSS};
        </div>
      </div>

      <div className="flex gap-2">
        <button
          onClick={resetTransforms}
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

export class CssTransformGeneratorTool {
  static Component = CssTransformGenerator;
}
