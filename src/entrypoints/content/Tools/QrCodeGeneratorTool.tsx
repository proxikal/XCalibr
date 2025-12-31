import React, { useRef, useEffect } from 'react';

export type QrCodeGeneratorData = {
  text?: string;
  size?: number;
  foreground?: string;
  background?: string;
  generated?: boolean;
};

type Props = {
  data: QrCodeGeneratorData | undefined;
  onChange: (data: QrCodeGeneratorData) => void;
};

// Simple QR code generator using Canvas
const generateQrMatrix = (text: string): number[][] => {
  // This is a simplified QR-like pattern generator
  // For real QR codes, you'd use a library like qrcode
  const size = 21; // QR Version 1 is 21x21
  const matrix: number[][] = Array(size).fill(null).map(() => Array(size).fill(0));

  // Add finder patterns (top-left, top-right, bottom-left corners)
  const addFinderPattern = (startRow: number, startCol: number) => {
    for (let r = 0; r < 7; r++) {
      for (let c = 0; c < 7; c++) {
        if (r === 0 || r === 6 || c === 0 || c === 6 ||
            (r >= 2 && r <= 4 && c >= 2 && c <= 4)) {
          matrix[startRow + r][startCol + c] = 1;
        }
      }
    }
  };

  addFinderPattern(0, 0);
  addFinderPattern(0, size - 7);
  addFinderPattern(size - 7, 0);

  // Add timing patterns
  for (let i = 8; i < size - 8; i++) {
    matrix[6][i] = i % 2;
    matrix[i][6] = i % 2;
  }

  // Add data based on text (simplified encoding)
  let bit = 0;
  const textBytes = new TextEncoder().encode(text);
  for (let row = size - 1; row >= 0; row--) {
    for (let col = size - 1; col >= 0; col--) {
      if (matrix[row][col] === 0 && row > 8 && col > 8) {
        const byteIndex = Math.floor(bit / 8);
        const bitIndex = bit % 8;
        if (byteIndex < textBytes.length) {
          matrix[row][col] = (textBytes[byteIndex] >> (7 - bitIndex)) & 1;
        } else {
          matrix[row][col] = Math.random() > 0.5 ? 1 : 0;
        }
        bit++;
      }
    }
  }

  return matrix;
};

const QrCodeGenerator: React.FC<Props> = ({ data, onChange }) => {
  const text = data?.text ?? '';
  const size = data?.size ?? 200;
  const foreground = data?.foreground ?? '#000000';
  const background = data?.background ?? '#ffffff';
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const handleGenerate = () => {
    if (!text.trim() || !canvasRef.current) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const matrix = generateQrMatrix(text);
    const cellSize = size / matrix.length;

    canvas.width = size;
    canvas.height = size;

    // Fill background
    ctx.fillStyle = background;
    ctx.fillRect(0, 0, size, size);

    // Draw modules
    ctx.fillStyle = foreground;
    for (let row = 0; row < matrix.length; row++) {
      for (let col = 0; col < matrix[row].length; col++) {
        if (matrix[row][col] === 1) {
          ctx.fillRect(
            col * cellSize,
            row * cellSize,
            cellSize,
            cellSize
          );
        }
      }
    }

    onChange({ ...data, generated: true });
  };

  const handleDownload = () => {
    if (!canvasRef.current) return;
    const url = canvasRef.current.toDataURL('image/png');
    const a = document.createElement('a');
    a.href = url;
    a.download = 'qrcode.png';
    a.click();
  };

  useEffect(() => {
    if (text && data?.generated) {
      handleGenerate();
    }
  }, [size, foreground, background]);

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">Text or URL</label>
        <input
          type="text"
          value={text}
          onChange={(e) => onChange({ ...data, text: e.target.value, generated: false })}
          placeholder="Enter text or URL..."
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
        />
      </div>

      <div className="grid grid-cols-3 gap-2">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Size (px)</label>
          <input
            type="number"
            value={size}
            onChange={(e) => onChange({ ...data, size: parseInt(e.target.value) || 200 })}
            min={100}
            max={500}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Foreground</label>
          <input
            type="color"
            value={foreground}
            onChange={(e) => onChange({ ...data, foreground: e.target.value })}
            className="w-full h-9 bg-[#1a1a2e] border border-gray-700 rounded cursor-pointer"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Background</label>
          <input
            type="color"
            value={background}
            onChange={(e) => onChange({ ...data, background: e.target.value })}
            className="w-full h-9 bg-[#1a1a2e] border border-gray-700 rounded cursor-pointer"
          />
        </div>
      </div>

      <button
        onClick={handleGenerate}
        disabled={!text.trim()}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
      >
        Generate QR Code
      </button>

      <div className="flex flex-col items-center space-y-2">
        <canvas
          ref={canvasRef}
          className="border border-gray-700 rounded"
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
        Note: This is a simplified QR-like pattern. For production use, consider a proper QR library.
      </div>
    </div>
  );
};

export class QrCodeGeneratorTool {
  static Component = QrCodeGenerator;
}
