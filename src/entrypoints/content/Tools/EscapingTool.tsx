import React from 'react';

export type EscapingToolData = {
  input?: string;
  output?: string;
  language?: 'json' | 'javascript' | 'python' | 'sql' | 'html' | 'url' | 'regex';
  mode?: 'escape' | 'unescape';
};

type Props = {
  data: EscapingToolData | undefined;
  onChange: (data: EscapingToolData) => void;
};

const escapeHandlers: Record<string, { escape: (s: string) => string; unescape: (s: string) => string }> = {
  json: {
    escape: (s) => JSON.stringify(s).slice(1, -1),
    unescape: (s) => {
      try {
        return JSON.parse(`"${s}"`);
      } catch {
        return s;
      }
    }
  },
  javascript: {
    escape: (s) => s
      .replace(/\\/g, '\\\\')
      .replace(/'/g, "\\'")
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\t/g, '\\t'),
    unescape: (s) => s
      .replace(/\\n/g, '\n')
      .replace(/\\r/g, '\r')
      .replace(/\\t/g, '\t')
      .replace(/\\"/g, '"')
      .replace(/\\'/g, "'")
      .replace(/\\\\/g, '\\')
  },
  python: {
    escape: (s) => s
      .replace(/\\/g, '\\\\')
      .replace(/'/g, "\\'")
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\t/g, '\\t'),
    unescape: (s) => s
      .replace(/\\n/g, '\n')
      .replace(/\\r/g, '\r')
      .replace(/\\t/g, '\t')
      .replace(/\\"/g, '"')
      .replace(/\\'/g, "'")
      .replace(/\\\\/g, '\\')
  },
  sql: {
    escape: (s) => s.replace(/'/g, "''"),
    unescape: (s) => s.replace(/''/g, "'")
  },
  html: {
    escape: (s) => s
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;'),
    unescape: (s) => s
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
  },
  url: {
    escape: (s) => encodeURIComponent(s),
    unescape: (s) => {
      try {
        return decodeURIComponent(s);
      } catch {
        return s;
      }
    }
  },
  regex: {
    escape: (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
    unescape: (s) => s.replace(/\\([.*+?^${}()|[\]\\])/g, '$1')
  }
};

const Escaping: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const language = data?.language ?? 'json';
  const mode = data?.mode ?? 'escape';

  const handleConvert = () => {
    const handler = escapeHandlers[language];
    if (!handler) return;

    const result = mode === 'escape'
      ? handler.escape(input)
      : handler.unescape(input);

    onChange({ ...data, output: result });
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
          <label className="block text-xs text-gray-400 mb-1">Language/Format</label>
          <select
            value={language}
            onChange={(e) => onChange({ ...data, language: e.target.value as typeof language })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          >
            <option value="json">JSON</option>
            <option value="javascript">JavaScript</option>
            <option value="python">Python</option>
            <option value="sql">SQL</option>
            <option value="html">HTML</option>
            <option value="url">URL</option>
            <option value="regex">Regex</option>
          </select>
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Mode</label>
          <select
            value={mode}
            onChange={(e) => onChange({ ...data, mode: e.target.value as typeof mode })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          >
            <option value="escape">Escape</option>
            <option value="unescape">Unescape</option>
          </select>
        </div>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Input</label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value })}
          placeholder="Enter text to escape or unescape..."
          rows={4}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
        />
      </div>

      <button
        onClick={handleConvert}
        disabled={!input}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
      >
        {mode === 'escape' ? 'Escape' : 'Unescape'}
      </button>

      {output && (
        <div>
          <div className="flex justify-between items-center mb-1">
            <label className="text-xs text-gray-400">Output</label>
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
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-green-400 font-mono text-xs resize-none"
          />
        </div>
      )}
    </div>
  );
};

export class EscapingTool {
  static Component = Escaping;
}
