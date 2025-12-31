import React from 'react';

export type PlaceholderImageData = {
  width?: number;
  height?: number;
  bgColor?: string;
  textColor?: string;
  text?: string;
  format?: 'png' | 'jpg' | 'gif' | 'webp';
};

type Props = {
  data: PlaceholderImageData;
  onChange: (data: PlaceholderImageData) => void;
};

const PlaceholderImage: React.FC<Props> = ({ data, onChange }) => {
  const width = data.width ?? 300;
  const height = data.height ?? 200;
  const bgColor = data.bgColor ?? '#cccccc';
  const textColor = data.textColor ?? '#666666';
  const text = data.text ?? '';
  const format = data.format ?? 'png';

  const generatePlaceholderUrl = () => {
    // Using placeholder.com service
    const bg = bgColor.replace('#', '');
    const fg = textColor.replace('#', '');
    const displayText = text || `${width}x${height}`;
    return `https://via.placeholder.com/${width}x${height}/${bg}/${fg}.${format}?text=${encodeURIComponent(displayText)}`;
  };

  const generateDataUrl = () => {
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');
    if (!ctx) return '';

    // Draw background
    ctx.fillStyle = bgColor;
    ctx.fillRect(0, 0, width, height);

    // Draw text
    ctx.fillStyle = textColor;
    const displayText = text || `${width}×${height}`;
    const fontSize = Math.min(width, height) / 5;
    ctx.font = `bold ${fontSize}px sans-serif`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(displayText, width / 2, height / 2);

    return canvas.toDataURL(`image/${format === 'jpg' ? 'jpeg' : format}`);
  };

  const placeholderUrl = generatePlaceholderUrl();
  const dataUrl = generateDataUrl();

  const copyUrl = () => {
    navigator.clipboard.writeText(placeholderUrl);
  };

  const copyDataUrl = () => {
    navigator.clipboard.writeText(dataUrl);
  };

  const downloadImage = () => {
    const link = document.createElement('a');
    link.download = `placeholder-${width}x${height}.${format}`;
    link.href = dataUrl;
    link.click();
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Width (px)</label>
          <input
            type="number"
            min="1"
            max="2000"
            value={width}
            onChange={(e) => onChange({ ...data, width: Math.max(1, Number(e.target.value)) })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Height (px)</label>
          <input
            type="number"
            min="1"
            max="2000"
            value={height}
            onChange={(e) => onChange({ ...data, height: Math.max(1, Number(e.target.value)) })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white"
          />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Background</label>
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
              className="flex-1 px-2 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-sm"
            />
          </div>
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Text Color</label>
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
              className="flex-1 px-2 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-sm"
            />
          </div>
        </div>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Custom Text (optional)</label>
        <input
          type="text"
          value={text}
          onChange={(e) => onChange({ ...data, text: e.target.value })}
          placeholder={`${width}×${height}`}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white"
        />
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Format</label>
        <select
          value={format}
          onChange={(e) => onChange({ ...data, format: e.target.value as typeof format })}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white"
        >
          <option value="png">PNG</option>
          <option value="jpg">JPG</option>
          <option value="gif">GIF</option>
          <option value="webp">WebP</option>
        </select>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Preview</label>
        <div className="flex justify-center p-4 bg-[#1a1a2e] border border-gray-700 rounded">
          <img
            src={dataUrl}
            alt="Placeholder preview"
            style={{ maxWidth: '100%', maxHeight: 150 }}
          />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <button
          onClick={copyUrl}
          className="py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded text-sm"
        >
          Copy URL
        </button>
        <button
          onClick={downloadImage}
          className="py-2 bg-gray-700 hover:bg-gray-600 text-white rounded text-sm"
        >
          Generate & Download
        </button>
      </div>

      <button
        onClick={copyDataUrl}
        className="w-full py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-sm"
      >
        Copy Data URL
      </button>
    </div>
  );
};

export class PlaceholderImageTool {
  static Component = PlaceholderImage;
}
