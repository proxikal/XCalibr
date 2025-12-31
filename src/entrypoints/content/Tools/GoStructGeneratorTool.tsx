import React from 'react';

export type GoStructGeneratorData = {
  input?: string;
  output?: string;
  structName?: string;
  includeJsonTags?: boolean;
  omitempty?: boolean;
  error?: string;
};

type Props = {
  data: GoStructGeneratorData | undefined;
  onChange: (data: GoStructGeneratorData) => void;
};

const capitalize = (str: string): string => {
  return str.charAt(0).toUpperCase() + str.slice(1);
};

const toGoType = (value: unknown): string => {
  if (value === null) return 'interface{}';
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]interface{}';
    return `[]${toGoType(value[0])}`;
  }
  switch (typeof value) {
    case 'string': return 'string';
    case 'number': return Number.isInteger(value) ? 'int' : 'float64';
    case 'boolean': return 'bool';
    case 'object': return 'struct';
    default: return 'interface{}';
  }
};

const generateStruct = (
  obj: Record<string, unknown>,
  name: string,
  includeJsonTags: boolean,
  omitempty: boolean,
  indent: string = ''
): string => {
  const lines: string[] = [];
  const nestedStructs: string[] = [];

  lines.push(`${indent}type ${name} struct {`);

  for (const [key, value] of Object.entries(obj)) {
    const fieldName = capitalize(key);
    let goType = toGoType(value);
    let jsonTag = '';

    if (includeJsonTags) {
      const omitemptyStr = omitempty ? ',omitempty' : '';
      jsonTag = ` \`json:"${key}${omitemptyStr}"\``;
    }

    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      const nestedName = `${name}${fieldName}`;
      goType = nestedName;
      nestedStructs.push(generateStruct(value as Record<string, unknown>, nestedName, includeJsonTags, omitempty, indent));
    } else if (Array.isArray(value) && value.length > 0 && typeof value[0] === 'object' && value[0] !== null) {
      const nestedName = `${name}${fieldName}Item`;
      goType = `[]${nestedName}`;
      nestedStructs.push(generateStruct(value[0] as Record<string, unknown>, nestedName, includeJsonTags, omitempty, indent));
    }

    lines.push(`${indent}\t${fieldName} ${goType}${jsonTag}`);
  }

  lines.push(`${indent}}`);

  if (nestedStructs.length > 0) {
    lines.push('');
    lines.push(...nestedStructs);
  }

  return lines.join('\n');
};

const GoStructGenerator: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const structName = data?.structName ?? 'Root';
  const includeJsonTags = data?.includeJsonTags ?? true;
  const omitempty = data?.omitempty ?? false;
  const error = data?.error ?? '';

  const handleGenerate = () => {
    try {
      const parsed = JSON.parse(input);
      if (typeof parsed !== 'object' || parsed === null) {
        throw new Error('Input must be a JSON object');
      }
      const generated = generateStruct(parsed, structName, includeJsonTags, omitempty);
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
      <div>
        <label className="block text-xs text-gray-400 mb-1">Struct Name</label>
        <input
          type="text"
          value={structName}
          onChange={(e) => onChange({ ...data, structName: e.target.value })}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
        />
      </div>

      <div className="flex gap-4">
        <label className="flex items-center gap-2 text-sm text-gray-300">
          <input
            type="checkbox"
            checked={includeJsonTags}
            onChange={(e) => onChange({ ...data, includeJsonTags: e.target.checked })}
            className="rounded bg-gray-700 border-gray-600"
          />
          Include json tags
        </label>
        <label className="flex items-center gap-2 text-sm text-gray-300">
          <input
            type="checkbox"
            checked={omitempty}
            onChange={(e) => onChange({ ...data, omitempty: e.target.checked })}
            className="rounded bg-gray-700 border-gray-600"
          />
          Add omitempty
        </label>
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
        Generate Go Struct
      </button>

      {error && (
        <div className="text-red-400 text-xs p-2 bg-red-900/20 rounded">
          {error}
        </div>
      )}

      {output && !error && (
        <div className="space-y-2">
          <div className="flex justify-between items-center">
            <span className="text-xs text-gray-400">Go Struct Output</span>
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

export class GoStructGeneratorTool {
  static Component = GoStructGenerator;
}
