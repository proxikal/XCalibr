import React from 'react';

export type TextToBinaryData = {
  input?: string;
  output?: string;
  mode?: 'encode' | 'decode';
  separator?: string;
};

type Props = {
  data: TextToBinaryData | undefined;
  onChange: (data: TextToBinaryData) => void;
};

const textToBinary = (text: string, separator: string): string => {
  return [...text]
    .map(char => char.charCodeAt(0).toString(2).padStart(8, '0'))
    .join(separator);
};

const binaryToText = (binary: string): string => {
  // Remove any non-binary characters and split into 8-bit chunks
  const clean = binary.replace(/[^01]/g, '');
  const chunks = clean.match(/.{1,8}/g) || [];
  return chunks
    .map(chunk => String.fromCharCode(parseInt(chunk, 2)))
    .join('');
};

const TextToBinary: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const mode = data?.mode ?? 'encode';
  const separator = data?.separator ?? ' ';

  const handleEncode = () => {
    const result = textToBinary(input, separator);
    onChange({ ...data, output: result, mode: 'encode' });
  };

  const handleDecode = () => {
    const result = binaryToText(input);
    onChange({ ...data, output: result, mode: 'decode' });
  };

  const copyOutput = () => {
    if (output) {
      navigator.clipboard.writeText(output);
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">
          {mode === 'encode' ? 'Text Input' : 'Binary Input'}
        </label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value, output: '' })}
          placeholder={mode === 'encode' ? 'Enter text to convert to binary...' : 'Enter binary to convert to text...'}
          rows={4}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
        />
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Separator</label>
        <select
          value={separator}
          onChange={(e) => onChange({ ...data, separator: e.target.value })}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
        >
          <option value=" ">Space</option>
          <option value="">None</option>
          <option value="\n">Newline</option>
          <option value=", ">Comma</option>
        </select>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <button
          onClick={handleEncode}
          disabled={!input}
          className="py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
        >
          To Binary
        </button>
        <button
          onClick={handleDecode}
          disabled={!input}
          className="py-2 bg-green-600 hover:bg-green-500 disabled:bg-gray-600 text-white rounded text-sm"
        >
          To Text
        </button>
      </div>

      {output && (
        <div>
          <div className="flex justify-between items-center mb-1">
            <label className="text-xs text-gray-400">
              {mode === 'encode' ? 'Binary Output' : 'Text Output'}
            </label>
            <button
              onClick={copyOutput}
              className="text-xs text-blue-400 hover:text-blue-300"
            >
              Copy
            </button>
          </div>
          <textarea
            value={output}
            readOnly
            rows={4}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-green-400 font-mono text-xs resize-none"
          />
        </div>
      )}
    </div>
  );
};

export class TextToBinaryTool {
  static Component = TextToBinary;
}
