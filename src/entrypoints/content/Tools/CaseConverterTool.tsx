import React from 'react';

export type CaseConverterData = {
  input?: string;
  outputs?: Record<string, string>;
};

type Props = {
  data: CaseConverterData | undefined;
  onChange: (data: CaseConverterData) => void;
};

const toWords = (input: string): string[] => {
  // Split by common delimiters and case changes
  return input
    .replace(/([a-z])([A-Z])/g, '$1 $2') // camelCase -> camel Case
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2') // XMLParser -> XML Parser
    .replace(/[_\-\s]+/g, ' ') // underscores, dashes, spaces
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(w => w.length > 0);
};

const conversions: Record<string, (words: string[]) => string> = {
  camelCase: (words) => {
    if (words.length === 0) return '';
    return words[0] + words.slice(1).map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('');
  },
  PascalCase: (words) => {
    return words.map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('');
  },
  snake_case: (words) => {
    return words.join('_');
  },
  'kebab-case': (words) => {
    return words.join('-');
  },
  CONSTANT_CASE: (words) => {
    return words.map(w => w.toUpperCase()).join('_');
  },
  'dot.case': (words) => {
    return words.join('.');
  },
  'path/case': (words) => {
    return words.join('/');
  },
  'Title Case': (words) => {
    return words.map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
  },
  'Sentence case': (words) => {
    if (words.length === 0) return '';
    return words[0].charAt(0).toUpperCase() + words[0].slice(1) + ' ' + words.slice(1).join(' ');
  },
  lowercase: (words) => {
    return words.join(' ');
  },
  UPPERCASE: (words) => {
    return words.map(w => w.toUpperCase()).join(' ');
  }
};

const CaseConverter: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const outputs = data?.outputs ?? {};

  const handleConvert = () => {
    const words = toWords(input);
    const newOutputs: Record<string, string> = {};

    for (const [name, converter] of Object.entries(conversions)) {
      newOutputs[name] = converter(words);
    }

    onChange({ ...data, outputs: newOutputs });
  };

  const copyOutput = (value: string) => {
    navigator.clipboard.writeText(value);
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">Input Text</label>
        <input
          type="text"
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          placeholder="Enter text to convert..."
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
        />
      </div>

      <button
        onClick={handleConvert}
        disabled={!input.trim()}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
      >
        Convert All Cases
      </button>

      {Object.keys(outputs).length > 0 && (
        <div className="space-y-2 max-h-64 overflow-y-auto">
          {Object.entries(outputs).map(([name, value]) => (
            <div
              key={name}
              className="bg-[#1a1a2e] border border-gray-700 rounded p-2"
            >
              <div className="flex justify-between items-center">
                <span className="text-xs text-gray-400">{name}</span>
                <button
                  onClick={() => copyOutput(value)}
                  className="text-xs text-blue-400 hover:text-blue-300"
                >
                  Copy
                </button>
              </div>
              <div className="text-sm text-white font-mono mt-1 break-all">
                {value || <span className="text-gray-500 italic">empty</span>}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export class CaseConverterTool {
  static Component = CaseConverter;
}
