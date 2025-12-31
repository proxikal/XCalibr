import React, { useRef, useEffect } from 'react';

export type FaviconGeneratorData = {
  character?: string;
  bgColor?: string;
  textColor?: string;
  size?: 16 | 32 | 64 | 128;
  shape?: 'square' | 'circle';
};

type Props = {
  data: FaviconGeneratorData;
  onChange: (data: FaviconGeneratorData) => void;
};

const FaviconGenerator: React.FC<Props> = ({ data, onChange }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const character = data.character || '🔥';
  const bgColor = data.bgColor || '#4f46e5';
  const textColor = data.textColor || '#ffffff';
  const size = data.size || 32;
  const shape = data.shape || 'square';

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    canvas.width = size;
    canvas.height = size;

    // Clear canvas
    ctx.clearRect(0, 0, size, size);

    // Draw background
    ctx.fillStyle = bgColor;
    if (shape === 'circle') {
      ctx.beginPath();
      ctx.arc(size / 2, size / 2, size / 2, 0, Math.PI * 2);
      ctx.fill();
    } else {
      ctx.fillRect(0, 0, size, size);
    }

    // Draw character/emoji
    ctx.fillStyle = textColor;
    ctx.font = `${size * 0.6}px sans-serif`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(character, size / 2, size / 2);
  }, [character, bgColor, textColor, size, shape]);

  const downloadFavicon = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const link = document.createElement('a');
    link.download = `favicon-${size}x${size}.png`;
    link.href = canvas.toDataURL('image/png');
    link.click();
  };

  const generateIcoHtml = () => {
    return `<link rel="icon" type="image/png" sizes="${size}x${size}" href="favicon-${size}x${size}.png">`;
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs text-gray-400 mb-1">
            Character/Emoji
          </label>
          <input
            type="text"
            value={character}
            onChange={(e) => onChange({ ...data, character: e.target.value.slice(0, 2) })}
            placeholder="Enter emoji or character"
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-center text-2xl"
            maxLength={2}
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">
            Size
          </label>
          <select
            value={size}
            onChange={(e) => onChange({ ...data, size: Number(e.target.value) as 16 | 32 | 64 | 128 })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white"
          >
            <option value={16}>16x16</option>
            <option value={32}>32x32</option>
            <option value={64}>64x64</option>
            <option value={128}>128x128</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs text-gray-400 mb-1">
            Background Color
          </label>
          <div className="flex gap-2">
            <input
              type="color"
              value={bgColor}
              onChange={(e) => onChange({ ...data, bgColor: e.target.value })}
              className="w-12 h-10 bg-transparent border border-gray-700 rounded cursor-pointer"
            />
            <input
              type="text"
              value={bgColor}
              onChange={(e) => onChange({ ...data, bgColor: e.target.value })}
              className="flex-1 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-sm"
            />
          </div>
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">
            Text Color
          </label>
          <div className="flex gap-2">
            <input
              type="color"
              value={textColor}
              onChange={(e) => onChange({ ...data, textColor: e.target.value })}
              className="w-12 h-10 bg-transparent border border-gray-700 rounded cursor-pointer"
            />
            <input
              type="text"
              value={textColor}
              onChange={(e) => onChange({ ...data, textColor: e.target.value })}
              className="flex-1 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-sm"
            />
          </div>
        </div>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Shape</label>
        <div className="flex gap-2">
          <button
            onClick={() => onChange({ ...data, shape: 'square' })}
            className={`flex-1 py-2 rounded text-sm ${
              shape === 'square'
                ? 'bg-indigo-600 text-white'
                : 'bg-[#1a1a2e] text-gray-400 border border-gray-700'
            }`}
          >
            Square
          </button>
          <button
            onClick={() => onChange({ ...data, shape: 'circle' })}
            className={`flex-1 py-2 rounded text-sm ${
              shape === 'circle'
                ? 'bg-indigo-600 text-white'
                : 'bg-[#1a1a2e] text-gray-400 border border-gray-700'
            }`}
          >
            Circle
          </button>
        </div>
      </div>

      <div className="flex items-center justify-center p-6 bg-[#1a1a2e] border border-gray-700 rounded">
        <div className="text-center">
          <div className="mb-2 text-xs text-gray-400">Preview ({size}x{size})</div>
          <canvas
            ref={canvasRef}
            className="mx-auto border border-gray-600"
            style={{ width: Math.max(size, 64), height: Math.max(size, 64), imageRendering: 'pixelated' }}
          />
        </div>
      </div>

      <div className="flex gap-2">
        <button
          onClick={downloadFavicon}
          className="flex-1 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded text-sm"
        >
          Generate & Download
        </button>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">HTML Link Tag</label>
        <div className="p-3 bg-[#1a1a2e] border border-gray-700 rounded font-mono text-xs text-green-400 break-all">
          {generateIcoHtml()}
        </div>
      </div>
    </div>
  );
};

export class FaviconGeneratorTool {
  static Component = FaviconGenerator;
}
