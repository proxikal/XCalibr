import React from 'react';

export type CssMinifierData = {
  input?: string;
  output?: string;
  originalSize?: number;
  minifiedSize?: number;
  error?: string;
};

type Props = {
  data: CssMinifierData | undefined;
  onChange: (data: CssMinifierData) => void;
};

const minifyCss = (css: string): string => {
  let result = css;

  // Remove comments
  result = result.replace(/\/\*[\s\S]*?\*\//g, '');

  // Remove newlines and extra whitespace
  result = result.replace(/\s+/g, ' ');

  // Remove spaces around special characters
  result = result.replace(/\s*([{};:,>+~])\s*/g, '$1');

  // Remove trailing semicolons before closing braces
  result = result.replace(/;}/g, '}');

  // Remove spaces around opening braces
  result = result.replace(/\s*{\s*/g, '{');

  // Remove leading zeros from decimals
  result = result.replace(/(:|\s)0+\.(\d+)/g, '$1.$2');

  // Remove units from zero values
  result = result.replace(/(:|\s)0(px|em|rem|%|pt|vh|vw|vmin|vmax)/gi, '$10');

  // Shorten hex colors where possible (#aabbcc -> #abc)
  result = result.replace(/#([0-9a-f])\1([0-9a-f])\2([0-9a-f])\3/gi, '#$1$2$3');

  return result.trim();
};

const CssMinifier: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const originalSize = data?.originalSize ?? 0;
  const minifiedSize = data?.minifiedSize ?? 0;
  const error = data?.error ?? '';

  const handleMinify = () => {
    try {
      const minified = minifyCss(input);
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
        error: e instanceof Error ? e.message : 'Failed to minify CSS'
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
        <label className="block text-xs text-gray-400 mb-1">CSS Input</label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          placeholder={`.container {\n  margin: 0 auto;\n  padding: 20px;\n  /* comment */\n}`}
          className="w-full h-32 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
        />
      </div>

      <button
        onClick={handleMinify}
        disabled={!input.trim()}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
      >
        Minify CSS
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
        Removes comments, whitespace, shortens hex colors, and optimizes zeros.
      </div>
    </div>
  );
};

export class CssMinifierTool {
  static Component = CssMinifier;
}
