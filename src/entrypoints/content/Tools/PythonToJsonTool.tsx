import React from 'react';

export type PythonToJsonData = {
  input?: string;
  output?: string;
  error?: string;
};

type Props = {
  data: PythonToJsonData | undefined;
  onChange: (data: PythonToJsonData) => void;
};

const pythonToJson = (pythonStr: string): string => {
  let result = pythonStr;

  // Replace Python None with null
  result = result.replace(/\bNone\b/g, 'null');

  // Replace Python True with true
  result = result.replace(/\bTrue\b/g, 'true');

  // Replace Python False with false
  result = result.replace(/\bFalse\b/g, 'false');

  // Replace single quotes with double quotes (for keys and string values)
  // This is simplified and may not handle all edge cases
  result = result.replace(/'/g, '"');

  // Replace Python tuples () with arrays [] - simple cases only
  result = result.replace(/\(([^()]*)\)/g, '[$1]');

  // Try to parse and re-stringify for proper formatting
  try {
    const parsed = JSON.parse(result);
    return JSON.stringify(parsed, null, 2);
  } catch {
    // Return as-is if can't parse
    return result;
  }
};

const PythonToJson: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handleConvert = () => {
    try {
      const converted = pythonToJson(input);
      // Validate it's proper JSON
      JSON.parse(converted);
      onChange({
        ...data,
        output: converted,
        error: ''
      });
    } catch (e) {
      onChange({
        ...data,
        error: e instanceof Error ? e.message : 'Failed to convert Python to JSON'
      });
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(output);
  };

  const loadExample = () => {
    const example = `{'name': 'John', 'age': 30, 'active': True, 'data': None, 'items': ['a', 'b', 'c']}`;
    onChange({ ...data, input: example });
  };

  return (
    <div className="space-y-4">
      <div>
        <div className="flex justify-between items-center mb-1">
          <label className="text-xs text-gray-400">Python Dict Input</label>
          <button onClick={loadExample} className="text-xs text-blue-400 hover:text-blue-300">
            Load Example
          </button>
        </div>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          placeholder={`{'key': 'value', 'enabled': True, 'count': None}`}
          className="w-full h-28 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
        />
      </div>

      <button
        onClick={handleConvert}
        disabled={!input.trim()}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
      >
        Convert to JSON
      </button>

      {error && (
        <div className="text-red-400 text-xs p-2 bg-red-900/20 rounded">
          {error}
        </div>
      )}

      {output && !error && (
        <div className="space-y-2">
          <div className="flex justify-between items-center">
            <span className="text-xs text-gray-400">JSON Output</span>
            <button onClick={handleCopy} className="text-xs text-blue-400 hover:text-blue-300">
              Copy
            </button>
          </div>
          <textarea
            readOnly
            value={output}
            className="w-full h-28 px-3 py-2 bg-[#0d0d1a] border border-gray-700 rounded text-green-400 font-mono text-xs resize-none"
          />
        </div>
      )}

      <div className="bg-[#1a1a2e] p-3 rounded text-xs">
        <div className="text-gray-400 mb-2">Python to JSON Conversions:</div>
        <div className="grid grid-cols-2 gap-2 font-mono">
          <div className="text-yellow-400">None</div>
          <div className="text-green-400">null</div>
          <div className="text-yellow-400">True</div>
          <div className="text-green-400">true</div>
          <div className="text-yellow-400">False</div>
          <div className="text-green-400">false</div>
          <div className="text-yellow-400">'string'</div>
          <div className="text-green-400">"string"</div>
        </div>
      </div>
    </div>
  );
};

export class PythonToJsonTool {
  static Component = PythonToJson;
}
