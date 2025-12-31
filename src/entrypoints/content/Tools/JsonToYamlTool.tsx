import React from 'react';

export type JsonToYamlData = {
  input?: string;
  output?: string;
  error?: string;
};

type Props = {
  data: JsonToYamlData | undefined;
  onChange: (data: JsonToYamlData) => void;
};

const jsonToYaml = (obj: unknown, indent = 0): string => {
  const spaces = '  '.repeat(indent);

  if (obj === null) return 'null';
  if (obj === undefined) return 'null';
  if (typeof obj === 'boolean') return obj ? 'true' : 'false';
  if (typeof obj === 'number') return String(obj);
  if (typeof obj === 'string') {
    // Check if string needs quoting
    if (obj === '' || obj.includes('\n') || obj.includes(':') || obj.includes('#') ||
        /^[\[\]{}&*!|>'"@`%]/.test(obj) || obj.trim() !== obj) {
      return JSON.stringify(obj);
    }
    return obj;
  }

  if (Array.isArray(obj)) {
    if (obj.length === 0) return '[]';
    return obj.map((item, idx) => {
      const val = jsonToYaml(item, indent + 1);
      if (typeof item === 'object' && item !== null && !Array.isArray(item)) {
        const lines = val.split('\n');
        return `${idx === 0 ? '' : spaces}- ` + lines[0] + '\n' + lines.slice(1).map(l => spaces + '  ' + l).join('\n');
      }
      return `${idx === 0 ? '' : spaces}- ${val}`;
    }).join('\n').replace(/^\n/, '');
  }

  if (typeof obj === 'object') {
    const entries = Object.entries(obj);
    if (entries.length === 0) return '{}';
    return entries.map(([key, value], idx) => {
      const yamlValue = jsonToYaml(value, indent + 1);
      if (typeof value === 'object' && value !== null && (Array.isArray(value) ? value.length > 0 : Object.keys(value).length > 0)) {
        return `${idx === 0 ? '' : spaces}${key}:\n${spaces}  ${yamlValue.split('\n').join('\n' + spaces + '  ')}`;
      }
      return `${idx === 0 ? '' : spaces}${key}: ${yamlValue}`;
    }).join('\n').replace(/^\n/, '');
  }

  return String(obj);
};

const JsonToYaml: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handleConvert = () => {
    try {
      const parsed = JSON.parse(input);
      const yaml = jsonToYaml(parsed);
      onChange({
        ...data,
        output: yaml,
        error: ''
      });
    } catch (e) {
      onChange({
        ...data,
        output: '',
        error: e instanceof Error ? e.message : 'Invalid JSON'
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
      <div>
        <label className="block text-xs text-gray-400 mb-1">JSON Input</label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          placeholder='{"name": "John", "age": 30}'
          rows={8}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
        />
      </div>

      <button
        onClick={handleConvert}
        disabled={!input.trim()}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
      >
        Convert to YAML
      </button>

      {error && (
        <div className="text-red-400 text-xs p-2 bg-red-900/20 rounded">{error}</div>
      )}

      {output && (
        <div>
          <div className="flex justify-between items-center mb-1">
            <label className="text-xs text-gray-400">YAML Output</label>
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
            rows={10}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-green-400 font-mono text-xs resize-none"
          />
        </div>
      )}
    </div>
  );
};

export class JsonToYamlTool {
  static Component = JsonToYaml;
}
