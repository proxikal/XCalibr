import React from 'react';

export type YamlToJsonData = {
  input?: string;
  output?: string;
  error?: string;
};

type Props = {
  data: YamlToJsonData | undefined;
  onChange: (data: YamlToJsonData) => void;
};

// Simple YAML parser for basic cases (key: value, nested, arrays)
const parseYaml = (yaml: string): unknown => {
  const lines = yaml.split('\n');
  const stack: { indent: number; obj: Record<string, unknown>; key?: string }[] = [{ indent: -1, obj: {} }];

  for (let lineNum = 0; lineNum < lines.length; lineNum++) {
    const line = lines[lineNum];
    if (!line.trim() || line.trim().startsWith('#')) continue;

    const indent = line.search(/\S/);
    const content = line.trim();

    // Pop stack until we find parent
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }

    const parent = stack[stack.length - 1];

    // Array item
    if (content.startsWith('- ')) {
      const value = content.slice(2).trim();
      const parentKey = parent.key;
      if (parentKey) {
        const parentObj = stack[stack.length - 2]?.obj ?? parent.obj;
        if (!Array.isArray(parentObj[parentKey])) {
          parentObj[parentKey] = [];
        }
        (parentObj[parentKey] as unknown[]).push(parseValue(value));
      }
      continue;
    }

    // Key: value
    const colonIdx = content.indexOf(':');
    if (colonIdx === -1) {
      throw new Error(`Invalid YAML at line ${lineNum + 1}: ${content}`);
    }

    const key = content.slice(0, colonIdx).trim();
    const valueStr = content.slice(colonIdx + 1).trim();

    if (valueStr === '' || valueStr === '|' || valueStr === '>') {
      // Nested object or multi-line string
      parent.obj[key] = {};
      stack.push({ indent, obj: parent.obj[key] as Record<string, unknown>, key });
    } else {
      parent.obj[key] = parseValue(valueStr);
    }
  }

  return stack[0].obj;
};

const parseValue = (value: string): unknown => {
  if (value === '' || value === 'null' || value === '~') return null;
  if (value === 'true') return true;
  if (value === 'false') return false;

  // Remove quotes
  if ((value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }

  // Number
  const num = Number(value);
  if (!isNaN(num) && value !== '') return num;

  // Array inline
  if (value.startsWith('[') && value.endsWith(']')) {
    try {
      return JSON.parse(value);
    } catch {
      return value;
    }
  }

  return value;
};

const YamlToJson: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handleConvert = () => {
    try {
      const result = parseYaml(input);
      onChange({
        ...data,
        output: JSON.stringify(result, null, 2),
        error: ''
      });
    } catch (e) {
      onChange({
        ...data,
        output: '',
        error: e instanceof Error ? e.message : 'Invalid YAML'
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
        <label className="block text-xs text-gray-400 mb-1">YAML Input</label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          placeholder="name: John&#10;age: 30&#10;hobbies:&#10;  - reading&#10;  - coding"
          rows={8}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
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
        <div className="text-red-400 text-xs p-2 bg-red-900/20 rounded">{error}</div>
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
            rows={10}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-green-400 font-mono text-xs resize-none"
          />
        </div>
      )}
    </div>
  );
};

export class YamlToJsonTool {
  static Component = YamlToJson;
}
