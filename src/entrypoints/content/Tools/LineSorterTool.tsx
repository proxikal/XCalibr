import React from 'react';

export type LineSorterData = {
  input?: string;
  output?: string;
  sortType?: 'asc' | 'desc' | 'numeric' | 'random' | 'reverse';
  removeDuplicates?: boolean;
  trimLines?: boolean;
  removeEmpty?: boolean;
};

type Props = {
  data: LineSorterData | undefined;
  onChange: (data: LineSorterData) => void;
};

const LineSorter: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const sortType = data?.sortType ?? 'asc';
  const removeDuplicates = data?.removeDuplicates ?? false;
  const trimLines = data?.trimLines ?? true;
  const removeEmpty = data?.removeEmpty ?? true;

  const processLines = () => {
    let lines = input.split('\n');

    // Trim lines
    if (trimLines) {
      lines = lines.map(l => l.trim());
    }

    // Remove empty lines
    if (removeEmpty) {
      lines = lines.filter(l => l.length > 0);
    }

    // Remove duplicates
    if (removeDuplicates) {
      lines = [...new Set(lines)];
    }

    // Sort
    switch (sortType) {
      case 'asc':
        lines.sort((a, b) => a.localeCompare(b));
        break;
      case 'desc':
        lines.sort((a, b) => b.localeCompare(a));
        break;
      case 'numeric':
        lines.sort((a, b) => {
          const numA = parseFloat(a) || 0;
          const numB = parseFloat(b) || 0;
          return numA - numB;
        });
        break;
      case 'random':
        for (let i = lines.length - 1; i > 0; i--) {
          const j = Math.floor(Math.random() * (i + 1));
          [lines[i], lines[j]] = [lines[j], lines[i]];
        }
        break;
      case 'reverse':
        lines.reverse();
        break;
    }

    onChange({ ...data, output: lines.join('\n') });
  };

  const copyOutput = () => {
    if (output) {
      navigator.clipboard.writeText(output);
    }
  };

  const inputLineCount = input.split('\n').filter(l => l.trim()).length;
  const outputLineCount = output.split('\n').filter(l => l.trim()).length;

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">Input Lines</label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          placeholder="Enter one item per line..."
          rows={6}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
        />
        <div className="text-xs text-gray-500 mt-1">{inputLineCount} lines</div>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Sort Type</label>
          <select
            value={sortType}
            onChange={(e) => onChange({ ...data, sortType: e.target.value as typeof sortType })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          >
            <option value="asc">A → Z</option>
            <option value="desc">Z → A</option>
            <option value="numeric">Numeric</option>
            <option value="random">Random</option>
            <option value="reverse">Reverse</option>
          </select>
        </div>
        <div className="space-y-1 pt-5">
          <label className="flex items-center gap-2 text-xs text-gray-300">
            <input
              type="checkbox"
              checked={removeDuplicates}
              onChange={(e) => onChange({ ...data, removeDuplicates: e.target.checked })}
              className="w-3 h-3"
            />
            Remove duplicates
          </label>
          <label className="flex items-center gap-2 text-xs text-gray-300">
            <input
              type="checkbox"
              checked={removeEmpty}
              onChange={(e) => onChange({ ...data, removeEmpty: e.target.checked })}
              className="w-3 h-3"
            />
            Remove empty lines
          </label>
        </div>
      </div>

      <button
        onClick={processLines}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-sm"
      >
        Process Lines
      </button>

      {output && (
        <div>
          <div className="flex justify-between items-center mb-1">
            <label className="text-xs text-gray-400">Output ({outputLineCount} lines)</label>
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
            rows={6}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-green-400 font-mono text-xs resize-none"
          />
        </div>
      )}
    </div>
  );
};

export class LineSorterTool {
  static Component = LineSorter;
}
