import React, { useRef } from 'react';

export type Base64ImageConverterData = {
  mode?: 'imageToBase64' | 'base64ToImage';
  input?: string;
  output?: string;
  error?: string;
};

type Props = {
  data: Base64ImageConverterData | undefined;
  onChange: (data: Base64ImageConverterData) => void;
};

const Base64ImageConverter: React.FC<Props> = ({ data, onChange }) => {
  const mode = data?.mode ?? 'imageToBase64';
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const error = data?.error ?? '';
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith('image/')) {
      onChange({ ...data, error: 'Please select an image file' });
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const base64 = reader.result as string;
      onChange({
        ...data,
        output: base64,
        error: ''
      });
    };
    reader.onerror = () => {
      onChange({ ...data, error: 'Failed to read file' });
    };
    reader.readAsDataURL(file);
  };

  const handleBase64Input = (value: string) => {
    onChange({ ...data, input: value, error: '' });

    if (!value.trim()) {
      onChange({ ...data, input: value, output: '', error: '' });
      return;
    }

    // Validate base64 image data
    if (value.startsWith('data:image/')) {
      onChange({ ...data, input: value, output: value, error: '' });
    } else {
      // Try to make it a valid data URL
      const withPrefix = `data:image/png;base64,${value.replace(/^data:image\/\w+;base64,/, '')}`;
      try {
        atob(value.replace(/^data:image\/\w+;base64,/, ''));
        onChange({ ...data, input: value, output: withPrefix, error: '' });
      } catch {
        onChange({ ...data, input: value, output: '', error: 'Invalid Base64 string' });
      }
    }
  };

  const copyOutput = () => {
    if (output) {
      navigator.clipboard.writeText(output);
    }
  };

  const downloadImage = () => {
    if (!output || !output.startsWith('data:image/')) return;

    const link = document.createElement('a');
    link.href = output;
    const format = output.match(/data:image\/(\w+);/)?.[1] || 'png';
    link.download = `image.${format}`;
    link.click();
  };

  return (
    <div className="space-y-3">
      <div>
        <label className="block text-xs text-gray-400 mb-1">Mode</label>
        <div className="flex gap-2">
          <button
            onClick={() => onChange({ ...data, mode: 'imageToBase64', input: '', output: '', error: '' })}
            className={`flex-1 py-2 rounded text-xs ${
              mode === 'imageToBase64'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            Image to Base64
          </button>
          <button
            onClick={() => onChange({ ...data, mode: 'base64ToImage', input: '', output: '', error: '' })}
            className={`flex-1 py-2 rounded text-xs ${
              mode === 'base64ToImage'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            Base64 to Image
          </button>
        </div>
      </div>

      {mode === 'imageToBase64' ? (
        <>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Select Image</label>
            <input
              ref={fileInputRef}
              type="file"
              accept="image/*"
              onChange={handleFileChange}
              className="w-full text-xs text-gray-400 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-xs file:bg-gray-700 file:text-gray-300 hover:file:bg-gray-600"
            />
          </div>

          {output && (
            <>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Preview</label>
                <div className="bg-[#1a1a2e] border border-gray-700 rounded p-2 flex justify-center">
                  <img
                    src={output}
                    alt="Preview"
                    style={{ maxWidth: '100%', maxHeight: 150 }}
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs text-gray-400 mb-1">Base64 Output</label>
                <textarea
                  value={output}
                  readOnly
                  rows={4}
                  className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
                />
              </div>

              <button
                onClick={copyOutput}
                className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded text-sm"
              >
                Copy Base64
              </button>
            </>
          )}
        </>
      ) : (
        <>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Base64 Input</label>
            <textarea
              value={input}
              onChange={(e) => handleBase64Input(e.target.value)}
              placeholder="Paste Base64 string or data URL..."
              rows={4}
              className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
            />
          </div>

          {error && (
            <div className="text-red-400 text-xs">{error}</div>
          )}

          {output && !error && (
            <>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Image Preview</label>
                <div className="bg-[#1a1a2e] border border-gray-700 rounded p-2 flex justify-center">
                  <img
                    src={output}
                    alt="Converted"
                    style={{ maxWidth: '100%', maxHeight: 150 }}
                  />
                </div>
              </div>

              <button
                onClick={downloadImage}
                className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded text-sm"
              >
                Download Image
              </button>
            </>
          )}
        </>
      )}
    </div>
  );
};

export class Base64ImageConverterTool {
  static Component = Base64ImageConverter;
}
