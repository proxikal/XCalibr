import React from 'react';

export type HexViewerData = {
  input?: string;
  hexOutput?: string;
  asciiOutput?: string;
  bytesPerLine?: number;
};

type Props = {
  data: HexViewerData | undefined;
  onChange: (data: HexViewerData) => void;
};

const textToHex = (text: string, bytesPerLine: number): { hex: string; ascii: string }[] => {
  const bytes = new TextEncoder().encode(text);
  const lines: { hex: string; ascii: string }[] = [];

  for (let i = 0; i < bytes.length; i += bytesPerLine) {
    const chunk = bytes.slice(i, i + bytesPerLine);
    const hexParts: string[] = [];
    const asciiParts: string[] = [];

    for (let j = 0; j < bytesPerLine; j++) {
      if (j < chunk.length) {
        hexParts.push(chunk[j].toString(16).padStart(2, '0').toUpperCase());
        const char = chunk[j];
        asciiParts.push(char >= 32 && char <= 126 ? String.fromCharCode(char) : '.');
      } else {
        hexParts.push('  ');
        asciiParts.push(' ');
      }
    }

    lines.push({
      hex: hexParts.join(' '),
      ascii: asciiParts.join('')
    });
  }

  return lines;
};

const HexViewer: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const hexOutput = data?.hexOutput ?? '';
  const bytesPerLine = data?.bytesPerLine ?? 16;

  const handleConvert = () => {
    const lines = textToHex(input, bytesPerLine);
    const hexStr = lines.map((l, i) => {
      const offset = (i * bytesPerLine).toString(16).padStart(8, '0').toUpperCase();
      return `${offset}  ${l.hex}  |${l.ascii}|`;
    }).join('\n');

    onChange({
      ...data,
      hexOutput: hexStr
    });
  };

  const copyOutput = () => {
    if (hexOutput) {
      navigator.clipboard.writeText(hexOutput);
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">Input Text</label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value, hexOutput: '' })}
          placeholder="Enter text to view as hex..."
          rows={4}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
        />
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Bytes Per Line</label>
        <select
          value={bytesPerLine}
          onChange={(e) => onChange({ ...data, bytesPerLine: Number(e.target.value) })}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
        >
          <option value="8">8 bytes</option>
          <option value="16">16 bytes</option>
          <option value="32">32 bytes</option>
        </select>
      </div>

      <button
        onClick={handleConvert}
        disabled={!input}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
      >
        View Hex
      </button>

      {hexOutput && (
        <div>
          <div className="flex justify-between items-center mb-1">
            <label className="text-xs text-gray-400">Hex Dump (Offset | Hex | ASCII)</label>
            <button
              onClick={copyOutput}
              className="text-xs text-blue-400 hover:text-blue-300"
            >
              Copy
            </button>
          </div>
          <textarea
            value={hexOutput}
            readOnly
            rows={10}
            className="w-full px-3 py-2 bg-[#0d0d1a] border border-gray-700 rounded text-green-400 font-mono text-xs resize-none"
          />
          <div className="text-xs text-gray-500 mt-1">
            {input.length} characters, {new TextEncoder().encode(input).length} bytes
          </div>
        </div>
      )}
    </div>
  );
};

export class HexViewerTool {
  static Component = HexViewer;
}
