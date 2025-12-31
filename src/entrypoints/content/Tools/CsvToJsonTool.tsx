import React from 'react';

export type CsvToJsonData = {
  input?: string;
  output?: string;
  delimiter?: string;
  hasHeader?: boolean;
  error?: string;
};

type Props = {
  data: CsvToJsonData | undefined;
  onChange: (data: CsvToJsonData) => void;
};

const parseCsv = (input: string, delimiter: string, hasHeader: boolean): unknown[] => {
  const lines = input.trim().split('\n');
  if (lines.length === 0) return [];

  const parseRow = (row: string): string[] => {
    const result: string[] = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < row.length; i++) {
      const char = row[i];
      if (char === '"') {
        if (inQuotes && row[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (char === delimiter && !inQuotes) {
        result.push(current.trim());
        current = '';
      } else {
        current += char;
      }
    }
    result.push(current.trim());
    return result;
  };

  const rows = lines.map(parseRow);

  if (hasHeader && rows.length > 0) {
    const headers = rows[0];
    return rows.slice(1).map(row => {
      const obj: Record<string, string> = {};
      headers.forEach((header, i) => {
        obj[header] = row[i] || '';
      });
      return obj;
    });
  }

  return rows;
};

const CsvToJson: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const delimiter = data?.delimiter ?? ',';
  const hasHeader = data?.hasHeader ?? true;
  const error = data?.error ?? '';

  const handleConvert = () => {
    try {
      const result = parseCsv(input, delimiter, hasHeader);
      onChange({
        ...data,
        output: JSON.stringify(result, null, 2),
        error: ''
      });
    } catch (e) {
      onChange({
        ...data,
        output: '',
        error: e instanceof Error ? e.message : 'Conversion failed'
      });
    }
  };

  const copyOutput = () => {
    if (output) {
      navigator.clipboard.writeText(output);
    }
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Delimiter</label>
          <select
            value={delimiter}
            onChange={(e) => onChange({ ...data, delimiter: e.target.value })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          >
            <option value=",">Comma (,)</option>
            <option value=";">Semicolon (;)</option>
            <option value="\t">Tab</option>
            <option value="|">Pipe (|)</option>
          </select>
        </div>
        <div className="flex items-end">
          <label className="flex items-center gap-2 text-sm text-gray-300">
            <input
              type="checkbox"
              checked={hasHeader}
              onChange={(e) => onChange({ ...data, hasHeader: e.target.checked })}
              className="w-4 h-4"
            />
            First row is header
          </label>
        </div>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">CSV Input</label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          placeholder="name,age,city&#10;John,30,NYC&#10;Jane,25,LA"
          rows={6}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
        />
      </div>

      <button
        onClick={handleConvert}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-sm"
      >
        Convert to JSON
      </button>

      {error && (
        <div className="text-red-400 text-xs">{error}</div>
      )}

      {output && (
        <div>
          <div className="flex justify-between items-center mb-1">
            <label className="text-xs text-gray-400">JSON Output</label>
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
            rows={8}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-green-400 font-mono text-xs resize-none"
          />
        </div>
      )}
    </div>
  );
};

export class CsvToJsonTool {
  static Component = CsvToJson;
}
