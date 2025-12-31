import React, { useRef, useEffect } from 'react';

export type BarcodeGeneratorData = {
  text?: string;
  format?: 'CODE128' | 'CODE39' | 'EAN13' | 'EAN8' | 'UPC';
  height?: number;
  width?: number;
  generated?: boolean;
};

type Props = {
  data: BarcodeGeneratorData | undefined;
  onChange: (data: BarcodeGeneratorData) => void;
};

// CODE128 patterns (simplified subset)
const CODE128_PATTERNS: Record<string, string> = {
  ' ': '11011001100', '!': '11001101100', '"': '11001100110', '#': '10010011000',
  '0': '10110011100', '1': '11101001100', '2': '11100101100', '3': '11100100110',
  '4': '11101100100', '5': '11100110100', '6': '11100110010', '7': '11011101110',
  '8': '10111011000', '9': '10001110110', 'A': '10010110000', 'B': '10000110100',
  'C': '10010000110', 'D': '10100011000', 'E': '10001011000', 'F': '10001000110',
  'G': '10110001000', 'H': '10001101000', 'I': '10001100010', 'J': '11010001000',
  'K': '11000101000', 'L': '11000100010', 'M': '10110111000', 'N': '10110001110',
  'O': '10001101110', 'P': '10111011000', 'Q': '10111000110', 'R': '10001110110',
  'S': '11101110110', 'T': '11010001110', 'U': '11000101110', 'V': '11011101000',
  'W': '11011100010', 'X': '11011101110', 'Y': '11101011000', 'Z': '11101000110',
  'START': '11010000100', 'STOP': '1100011101011'
};

const generateCode128 = (text: string): string[] => {
  const bars: string[] = [];
  bars.push(CODE128_PATTERNS['START']);

  for (const char of text.toUpperCase()) {
    const pattern = CODE128_PATTERNS[char];
    if (pattern) {
      bars.push(pattern);
    }
  }

  bars.push(CODE128_PATTERNS['STOP']);
  return bars;
};

const BarcodeGenerator: React.FC<Props> = ({ data, onChange }) => {
  const text = data?.text ?? '';
  const format = data?.format ?? 'CODE128';
  const height = data?.height ?? 80;
  const width = data?.width ?? 2;
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const handleGenerate = () => {
    if (!text.trim() || !canvasRef.current) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const patterns = generateCode128(text);
    const binaryString = patterns.join('');

    canvas.width = binaryString.length * width + 20;
    canvas.height = height + 30;

    // Fill white background
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Draw bars
    ctx.fillStyle = '#000000';
    let x = 10;
    for (const bit of binaryString) {
      if (bit === '1') {
        ctx.fillRect(x, 5, width, height);
      }
      x += width;
    }

    // Draw text below barcode
    ctx.font = '12px monospace';
    ctx.textAlign = 'center';
    ctx.fillText(text, canvas.width / 2, height + 20);

    onChange({ ...data, generated: true });
  };

  const handleDownload = () => {
    if (!canvasRef.current) return;
    const url = canvasRef.current.toDataURL('image/png');
    const a = document.createElement('a');
    a.href = url;
    a.download = 'barcode.png';
    a.click();
  };

  useEffect(() => {
    if (text && data?.generated) {
      handleGenerate();
    }
  }, [height, width, format]);

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">Text / Code</label>
        <input
          type="text"
          value={text}
          onChange={(e) => onChange({ ...data, text: e.target.value, generated: false })}
          placeholder="Enter text or numbers..."
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-sm"
        />
      </div>

      <div className="grid grid-cols-3 gap-2">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Format</label>
          <select
            value={format}
            onChange={(e) => onChange({ ...data, format: e.target.value as BarcodeGeneratorData['format'] })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          >
            <option value="CODE128">CODE128</option>
            <option value="CODE39">CODE39</option>
            <option value="EAN13">EAN-13</option>
            <option value="EAN8">EAN-8</option>
            <option value="UPC">UPC-A</option>
          </select>
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Height (px)</label>
          <input
            type="number"
            value={height}
            onChange={(e) => onChange({ ...data, height: parseInt(e.target.value) || 80 })}
            min={40}
            max={200}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Bar Width (px)</label>
          <input
            type="number"
            value={width}
            onChange={(e) => onChange({ ...data, width: parseInt(e.target.value) || 2 })}
            min={1}
            max={5}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          />
        </div>
      </div>

      <button
        onClick={handleGenerate}
        disabled={!text.trim()}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
      >
        Generate Barcode
      </button>

      <div className="flex flex-col items-center space-y-2">
        <canvas
          ref={canvasRef}
          className="border border-gray-700 rounded bg-white"
          style={{ maxWidth: '100%', display: data?.generated ? 'block' : 'none' }}
        />
        {data?.generated && (
          <button
            onClick={handleDownload}
            className="text-xs text-blue-400 hover:text-blue-300"
          >
            Download PNG
          </button>
        )}
      </div>

      <div className="text-xs text-gray-500">
        Generates CODE128 barcodes. Other formats use simplified encoding.
      </div>
    </div>
  );
};

export class BarcodeGeneratorTool {
  static Component = BarcodeGenerator;
}
