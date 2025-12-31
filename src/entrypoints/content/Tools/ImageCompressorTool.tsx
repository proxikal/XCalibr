import React, { useRef } from 'react';

export type ImageCompressorData = {
  quality?: number;
  format?: 'jpeg' | 'png' | 'webp';
  originalSize?: number;
  compressedSize?: number;
  compressedUrl?: string;
  fileName?: string;
};

type Props = {
  data: ImageCompressorData | undefined;
  onChange: (data: ImageCompressorData) => void;
};

const ImageCompressor: React.FC<Props> = ({ data, onChange }) => {
  const quality = data?.quality ?? 80;
  const format = data?.format ?? 'jpeg';
  const originalSize = data?.originalSize ?? 0;
  const compressedSize = data?.compressedSize ?? 0;
  const compressedUrl = data?.compressedUrl ?? '';
  const fileName = data?.fileName ?? '';
  const fileInputRef = useRef<HTMLInputElement>(null);

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const compressImage = (file: File) => {
    const img = new Image();
    const reader = new FileReader();

    reader.onload = (e) => {
      img.onload = () => {
        const canvas = document.createElement('canvas');
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        ctx.drawImage(img, 0, 0);

        const mimeType = format === 'png' ? 'image/png' :
                        format === 'webp' ? 'image/webp' : 'image/jpeg';

        const qualityValue = format === 'png' ? undefined : quality / 100;
        const dataUrl = canvas.toDataURL(mimeType, qualityValue);

        // Calculate compressed size from base64
        const base64 = dataUrl.split(',')[1];
        const compressed = atob(base64).length;

        onChange({
          ...data,
          originalSize: file.size,
          compressedSize: compressed,
          compressedUrl: dataUrl,
          fileName: file.name
        });
      };
      img.src = e.target?.result as string;
    };
    reader.readAsDataURL(file);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith('image/')) return;

    compressImage(file);
  };

  const handleQualityChange = (newQuality: number) => {
    onChange({ ...data, quality: newQuality });
  };

  const handleFormatChange = (newFormat: 'jpeg' | 'png' | 'webp') => {
    onChange({ ...data, format: newFormat });
  };

  const downloadCompressed = () => {
    if (!compressedUrl) return;

    const link = document.createElement('a');
    const baseName = fileName.replace(/\.[^/.]+$/, '');
    link.download = `${baseName}-compressed.${format}`;
    link.href = compressedUrl;
    link.click();
  };

  const compressionRatio = originalSize > 0
    ? ((1 - compressedSize / originalSize) * 100).toFixed(1)
    : '0';

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">
          Quality: {quality}%
        </label>
        <input
          type="range"
          min="10"
          max="100"
          value={quality}
          onChange={(e) => handleQualityChange(Number(e.target.value))}
          className="w-full h-2 bg-gray-700 rounded-lg appearance-none cursor-pointer"
        />
        <div className="flex justify-between text-xs text-gray-500 mt-1">
          <span>Smaller</span>
          <span>Better</span>
        </div>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Output Format</label>
        <div className="flex gap-2">
          {(['jpeg', 'png', 'webp'] as const).map((fmt) => (
            <button
              key={fmt}
              onClick={() => handleFormatChange(fmt)}
              className={`flex-1 py-2 rounded text-xs uppercase ${
                format === fmt
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
            >
              {fmt}
            </button>
          ))}
        </div>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Select image</label>
        <input
          ref={fileInputRef}
          type="file"
          accept="image/*"
          onChange={handleFileChange}
          className="w-full text-xs text-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-xs file:bg-gray-700 file:text-gray-300 hover:file:bg-gray-600"
        />
      </div>

      {compressedUrl && (
        <>
          <div className="bg-[#1a1a2e] border border-gray-700 rounded p-3">
            <div className="flex justify-center mb-3">
              <img
                src={compressedUrl}
                alt="Compressed preview"
                style={{ maxWidth: '100%', maxHeight: 150 }}
              />
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="text-gray-400">Original:</div>
              <div className="text-white">{formatBytes(originalSize)}</div>
              <div className="text-gray-400">Compressed:</div>
              <div className="text-white">{formatBytes(compressedSize)}</div>
              <div className="text-gray-400">Reduction:</div>
              <div className={`${Number(compressionRatio) > 0 ? 'text-green-400' : 'text-red-400'}`}>
                {compressionRatio}%
              </div>
            </div>
          </div>

          <button
            onClick={downloadCompressed}
            className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded text-sm"
          >
            Download Compressed
          </button>
        </>
      )}

      <div className="text-xs text-gray-500">
        <p>Note: PNG format uses lossless compression (quality slider has no effect).</p>
      </div>
    </div>
  );
};

export class ImageCompressorTool {
  static Component = ImageCompressor;
}
