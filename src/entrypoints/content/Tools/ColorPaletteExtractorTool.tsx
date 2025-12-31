import React, { useRef } from 'react';

export type ColorPaletteExtractorData = {
  colorCount?: number;
  colors?: string[];
  imageUrl?: string;
};

type Props = {
  data: ColorPaletteExtractorData | undefined;
  onChange: (data: ColorPaletteExtractorData) => void;
};

// Simple quantization algorithm for color extraction
const extractColors = (
  imageData: ImageData,
  numColors: number
): string[] => {
  const pixels: number[][] = [];
  const data = imageData.data;

  // Sample every 10th pixel for performance
  for (let i = 0; i < data.length; i += 40) {
    const r = data[i];
    const g = data[i + 1];
    const b = data[i + 2];
    const a = data[i + 3];
    if (a > 128) { // Only include non-transparent pixels
      pixels.push([r, g, b]);
    }
  }

  if (pixels.length === 0) return [];

  // Simple k-means-like clustering
  const centroids: number[][] = [];
  const step = Math.floor(pixels.length / numColors);

  for (let i = 0; i < numColors; i++) {
    const idx = Math.min(i * step, pixels.length - 1);
    centroids.push([...pixels[idx]]);
  }

  // Run a few iterations
  for (let iter = 0; iter < 10; iter++) {
    const clusters: number[][][] = Array.from({ length: numColors }, () => []);

    // Assign pixels to nearest centroid
    for (const pixel of pixels) {
      let minDist = Infinity;
      let minIdx = 0;
      for (let i = 0; i < centroids.length; i++) {
        const dist = Math.sqrt(
          Math.pow(pixel[0] - centroids[i][0], 2) +
          Math.pow(pixel[1] - centroids[i][1], 2) +
          Math.pow(pixel[2] - centroids[i][2], 2)
        );
        if (dist < minDist) {
          minDist = dist;
          minIdx = i;
        }
      }
      clusters[minIdx].push(pixel);
    }

    // Update centroids
    for (let i = 0; i < numColors; i++) {
      if (clusters[i].length > 0) {
        const sum = clusters[i].reduce(
          (acc, p) => [acc[0] + p[0], acc[1] + p[1], acc[2] + p[2]],
          [0, 0, 0]
        );
        centroids[i] = [
          Math.round(sum[0] / clusters[i].length),
          Math.round(sum[1] / clusters[i].length),
          Math.round(sum[2] / clusters[i].length)
        ];
      }
    }
  }

  // Convert to hex
  return centroids.map(([r, g, b]) => {
    const toHex = (n: number) => n.toString(16).padStart(2, '0');
    return `#${toHex(r)}${toHex(g)}${toHex(b)}`;
  });
};

const ColorPaletteExtractor: React.FC<Props> = ({ data, onChange }) => {
  const colorCount = data?.colorCount ?? 5;
  const colors = data?.colors ?? [];
  const imageUrl = data?.imageUrl ?? '';
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith('image/')) return;

    const img = new Image();
    const reader = new FileReader();

    reader.onload = (re) => {
      img.onload = () => {
        const canvas = document.createElement('canvas');
        // Resize for performance while keeping aspect ratio
        const maxDim = 200;
        const scale = Math.min(maxDim / img.width, maxDim / img.height);
        canvas.width = img.width * scale;
        canvas.height = img.height * scale;

        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const extractedColors = extractColors(imageData, colorCount);

        onChange({
          ...data,
          colors: extractedColors,
          imageUrl: re.target?.result as string
        });
      };
      img.src = re.target?.result as string;
    };
    reader.readAsDataURL(file);
  };

  const handleColorCountChange = (count: number) => {
    onChange({ ...data, colorCount: count });
  };

  const copyColor = (color: string) => {
    navigator.clipboard.writeText(color);
  };

  const copyAllColors = () => {
    const colorList = colors.join(', ');
    navigator.clipboard.writeText(colorList);
  };

  const reExtract = () => {
    if (!imageUrl) return;

    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      const maxDim = 200;
      const scale = Math.min(maxDim / img.width, maxDim / img.height);
      canvas.width = img.width * scale;
      canvas.height = img.height * scale;

      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const extractedColors = extractColors(imageData, colorCount);

      onChange({
        ...data,
        colors: extractedColors
      });
    };
    img.src = imageUrl;
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">
          Number of Colors: {colorCount}
        </label>
        <input
          type="range"
          min="3"
          max="10"
          value={colorCount}
          onChange={(e) => handleColorCountChange(Number(e.target.value))}
          className="w-full h-2 bg-gray-700 rounded-lg appearance-none cursor-pointer"
        />
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Upload image</label>
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*"
          onChange={handleFileChange}
          className="w-full text-xs text-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-xs file:bg-gray-700 file:text-gray-300 hover:file:bg-gray-600"
        />
      </div>

      {imageUrl && (
        <div className="bg-[#1a1a2e] border border-gray-700 rounded p-2">
          <img
            src={imageUrl}
            alt="Source"
            style={{ maxWidth: '100%', maxHeight: 100 }}
            className="mx-auto"
          />
        </div>
      )}

      {colors.length > 0 && (
        <>
          <div>
            <label className="block text-xs text-gray-400 mb-2">Extracted Colors</label>
            <div className="grid grid-cols-5 gap-2">
              {colors.map((color, idx) => (
                <div
                  key={idx}
                  className="text-center cursor-pointer"
                  onClick={() => copyColor(color)}
                  title="Click to copy"
                >
                  <div
                    className="w-full h-10 rounded border border-gray-600"
                    style={{ backgroundColor: color }}
                  />
                  <div className="text-xs text-gray-300 mt-1 font-mono">
                    {color.toUpperCase()}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="flex gap-2">
            <button
              onClick={reExtract}
              className="flex-1 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded text-sm"
            >
              Re-extract
            </button>
            <button
              onClick={copyAllColors}
              className="flex-1 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded text-sm"
            >
              Copy All
            </button>
          </div>
        </>
      )}

      <div className="text-xs text-gray-500">
        <p>Click on a color to copy its hex value.</p>
      </div>
    </div>
  );
};

export class ColorPaletteExtractorTool {
  static Component = ColorPaletteExtractor;
}
