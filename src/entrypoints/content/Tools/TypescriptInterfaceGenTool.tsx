import React from 'react';

export type TypescriptInterfaceGenData = {
  input?: string;
  output?: string;
  interfaceName?: string;
  useType?: boolean;
  error?: string;
};

type Props = {
  data: TypescriptInterfaceGenData | undefined;
  onChange: (data: TypescriptInterfaceGenData) => void;
};

const getTypeFromValue = (value: unknown): string => {
  if (value === null) return 'null';
  if (Array.isArray(value)) {
    if (value.length === 0) return 'unknown[]';
    const itemType = getTypeFromValue(value[0]);
    return `${itemType}[]`;
  }
  if (typeof value === 'object') return 'object';
  return typeof value;
};

const generateInterface = (
  obj: Record<string, unknown>,
  name: string,
  useType: boolean,
  indent: string = ''
): string => {
  const keyword = useType ? 'type' : 'interface';
  const assignment = useType ? ' = ' : ' ';
  const lines: string[] = [];

  lines.push(`${indent}${keyword} ${name}${assignment}{`);

  for (const [key, value] of Object.entries(obj)) {
    const propName = /^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(key) ? key : `"${key}"`;

    if (value === null) {
      lines.push(`${indent}  ${propName}: null;`);
    } else if (Array.isArray(value)) {
      if (value.length > 0 && typeof value[0] === 'object' && value[0] !== null) {
        const itemName = `${name}${key.charAt(0).toUpperCase() + key.slice(1)}Item`;
        lines.push(`${indent}  ${propName}: ${itemName}[];`);
      } else {
        const itemType = value.length > 0 ? getTypeFromValue(value[0]) : 'unknown';
        lines.push(`${indent}  ${propName}: ${itemType}[];`);
      }
    } else if (typeof value === 'object') {
      const nestedName = `${name}${key.charAt(0).toUpperCase() + key.slice(1)}`;
      lines.push(`${indent}  ${propName}: ${nestedName};`);
    } else {
      lines.push(`${indent}  ${propName}: ${typeof value};`);
    }
  }

  lines.push(`${indent}}${useType ? ';' : ''}`);

  // Generate nested interfaces
  for (const [key, value] of Object.entries(obj)) {
    if (Array.isArray(value) && value.length > 0 && typeof value[0] === 'object' && value[0] !== null) {
      const itemName = `${name}${key.charAt(0).toUpperCase() + key.slice(1)}Item`;
      lines.push('');
      lines.push(generateInterface(value[0] as Record<string, unknown>, itemName, useType, indent));
    } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      const nestedName = `${name}${key.charAt(0).toUpperCase() + key.slice(1)}`;
      lines.push('');
      lines.push(generateInterface(value as Record<string, unknown>, nestedName, useType, indent));
    }
  }

  return lines.join('\n');
};

const TypescriptInterfaceGen: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const interfaceName = data?.interfaceName ?? 'Root';
  const useType = data?.useType ?? false;
  const error = data?.error ?? '';

  const handleGenerate = () => {
    try {
      const parsed = JSON.parse(input);
      if (typeof parsed !== 'object' || parsed === null) {
        throw new Error('Input must be a JSON object');
      }
      const generated = generateInterface(parsed, interfaceName, useType);
      onChange({ ...data, output: generated, error: '' });
    } catch (e) {
      onChange({
        ...data,
        error: e instanceof Error ? e.message : 'Invalid JSON'
      });
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(output);
  };

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Interface Name</label>
          <input
            type="text"
            value={interfaceName}
            onChange={(e) => onChange({ ...data, interfaceName: e.target.value })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          />
        </div>
        <div className="flex items-end pb-2">
          <label className="flex items-center gap-2 text-sm text-gray-300">
            <input
              type="checkbox"
              checked={useType}
              onChange={(e) => onChange({ ...data, useType: e.target.checked })}
              className="rounded bg-gray-700 border-gray-600"
            />
            Use <code className="text-blue-400">type</code> instead of <code className="text-blue-400">interface</code>
          </label>
        </div>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">JSON Input</label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          placeholder='{"name": "John", "age": 30, "active": true}'
          className="w-full h-28 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
        />
      </div>

      <button
        onClick={handleGenerate}
        disabled={!input.trim()}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
      >
        Generate TypeScript
      </button>

      {error && (
        <div className="text-red-400 text-xs p-2 bg-red-900/20 rounded">
          {error}
        </div>
      )}

      {output && !error && (
        <div className="space-y-2">
          <div className="flex justify-between items-center">
            <span className="text-xs text-gray-400">TypeScript Output</span>
            <button onClick={handleCopy} className="text-xs text-blue-400 hover:text-blue-300">
              Copy
            </button>
          </div>
          <textarea
            readOnly
            value={output}
            className="w-full h-32 px-3 py-2 bg-[#0d0d1a] border border-gray-700 rounded text-green-400 font-mono text-xs resize-none"
          />
        </div>
      )}
    </div>
  );
};

export class TypescriptInterfaceGenTool {
  static Component = TypescriptInterfaceGen;
}
