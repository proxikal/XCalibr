import React from 'react';

export type StringObfuscatorData = {
  input?: string;
  output?: string;
  method?: 'hex' | 'unicode' | 'octal' | 'base64' | 'charCode';
};

type Props = {
  data: StringObfuscatorData | undefined;
  onChange: (data: StringObfuscatorData) => void;
};

const obfuscateMethods = {
  hex: (str: string) => {
    return [...str].map(c => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
  },
  unicode: (str: string) => {
    return [...str].map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('');
  },
  octal: (str: string) => {
    return [...str].map(c => '\\' + c.charCodeAt(0).toString(8).padStart(3, '0')).join('');
  },
  base64: (str: string) => {
    return btoa(str);
  },
  charCode: (str: string) => {
    const codes = [...str].map(c => c.charCodeAt(0)).join(',');
    return `String.fromCharCode(${codes})`;
  }
};

const StringObfuscator: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const method = data?.method ?? 'hex';

  const handleObfuscate = () => {
    const result = obfuscateMethods[method](input);
    onChange({ ...data, output: result });
  };

  const copyOutput = () => {
    if (output) {
      navigator.clipboard.writeText(output);
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">Input String</label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          placeholder="Enter text to obfuscate..."
          rows={4}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
        />
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Obfuscation Method</label>
        <select
          value={method}
          onChange={(e) => onChange({ ...data, method: e.target.value as typeof method })}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
        >
          <option value="hex">Hex Escape (\\x68\\x65)</option>
          <option value="unicode">Unicode Escape (\\u0068)</option>
          <option value="octal">Octal Escape (\\150)</option>
          <option value="base64">Base64 Encode</option>
          <option value="charCode">String.fromCharCode()</option>
        </select>
      </div>

      <button
        onClick={handleObfuscate}
        disabled={!input}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
      >
        Obfuscate
      </button>

      {output && (
        <div>
          <div className="flex justify-between items-center mb-1">
            <label className="text-xs text-gray-400">Obfuscated Output</label>
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
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-green-400 font-mono text-xs resize-none break-all"
          />
          <div className="text-xs text-gray-500 mt-1">
            Original: {input.length} chars → Obfuscated: {output.length} chars
          </div>
        </div>
      )}
    </div>
  );
};

export class StringObfuscatorTool {
  static Component = StringObfuscator;
}
