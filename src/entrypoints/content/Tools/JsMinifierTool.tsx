import React from 'react';

export type JsMinifierData = {
  input?: string;
  output?: string;
  originalSize?: number;
  minifiedSize?: number;
  error?: string;
};

type Props = {
  data: JsMinifierData | undefined;
  onChange: (data: JsMinifierData) => void;
};

const minifyJs = (code: string): string => {
  let result = code;

  // Remove single line comments
  result = result.replace(/\/\/.*$/gm, '');

  // Remove multi-line comments
  result = result.replace(/\/\*[\s\S]*?\*\//g, '');

  // Remove leading/trailing whitespace on each line
  result = result.split('\n').map(line => line.trim()).join('');

  // Remove whitespace around operators (simplified approach)
  result = result.replace(/\s*([=+\-*/<>!&|,;:{}()[\]])\s*/g, '$1');

  // Add space after keywords that need it
  result = result.replace(/\b(return|var|let|const|if|else|for|while|function|typeof|instanceof|new|throw|catch|try|finally)\b(?=[^\s;,(){}])/g, '$1 ');

  // Remove multiple spaces
  result = result.replace(/\s+/g, ' ');

  // Remove space before semicolons and commas
  result = result.replace(/\s+([;,])/g, '$1');

  // Remove trailing semicolons before closing braces
  result = result.replace(/;}/g, '}');

  // Convert true/false to shorter versions where safe (simplified)
  // result = result.replace(/\btrue\b/g, '!0');
  // result = result.replace(/\bfalse\b/g, '!1');

  return result.trim();
};

const JsMinifier: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const originalSize = data?.originalSize ?? 0;
  const minifiedSize = data?.minifiedSize ?? 0;
  const error = data?.error ?? '';

  const handleMinify = () => {
    try {
      const minified = minifyJs(input);
      onChange({
        ...data,
        output: minified,
        originalSize: new Blob([input]).size,
        minifiedSize: new Blob([minified]).size,
        error: ''
      });
    } catch (e) {
      onChange({
        ...data,
        error: e instanceof Error ? e.message : 'Failed to minify JavaScript'
      });
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(output);
  };

  const savings = originalSize > 0 ? ((1 - minifiedSize / originalSize) * 100).toFixed(1) : '0';

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">JavaScript Input</label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          placeholder={`function example() {\n  const x = 1;\n  return x + 2;\n}`}
          className="w-full h-32 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
        />
      </div>

      <button
        onClick={handleMinify}
        disabled={!input.trim()}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
      >
        Minify JavaScript
      </button>

      {error && (
        <div className="text-red-400 text-xs p-2 bg-red-900/20 rounded">
          {error}
        </div>
      )}

      {output && !error && (
        <div className="space-y-2">
          <div className="flex justify-between items-center">
            <span className="text-xs text-gray-400">Minified Output</span>
            <button onClick={handleCopy} className="text-xs text-blue-400 hover:text-blue-300">
              Copy
            </button>
          </div>
          <textarea
            readOnly
            value={output}
            className="w-full h-24 px-3 py-2 bg-[#0d0d1a] border border-gray-700 rounded text-green-400 font-mono text-xs resize-none"
          />

          <div className="grid grid-cols-3 gap-2 text-center">
            <div className="bg-[#1a1a2e] p-2 rounded">
              <div className="text-xs text-gray-400">Original</div>
              <div className="text-sm font-mono text-gray-300">{originalSize} bytes</div>
            </div>
            <div className="bg-[#1a1a2e] p-2 rounded">
              <div className="text-xs text-gray-400">Minified</div>
              <div className="text-sm font-mono text-green-400">{minifiedSize} bytes</div>
            </div>
            <div className="bg-[#1a1a2e] p-2 rounded">
              <div className="text-xs text-gray-400">Savings</div>
              <div className="text-sm font-mono text-blue-400">{savings}%</div>
            </div>
          </div>
        </div>
      )}

      <div className="text-xs text-gray-500">
        Basic minification: removes comments, whitespace, and newlines.
      </div>
    </div>
  );
};

export class JsMinifierTool {
  static Component = JsMinifier;
}
