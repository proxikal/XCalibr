import React from 'react';

export type RegexHighlighterData = {
  pattern?: string;
  text?: string;
  flags?: string;
  matches?: string[];
  matchCount?: number;
  error?: string;
};

type Props = {
  data: RegexHighlighterData | undefined;
  onChange: (data: RegexHighlighterData) => void;
};

const RegexHighlighter: React.FC<Props> = ({ data, onChange }) => {
  const pattern = data?.pattern ?? '';
  const text = data?.text ?? '';
  const flags = data?.flags ?? 'g';
  const matches = data?.matches ?? [];
  const matchCount = data?.matchCount ?? 0;
  const error = data?.error ?? '';

  const handleTest = () => {
    if (!pattern) {
      onChange({ ...data, matches: [], matchCount: 0, error: '' });
      return;
    }

    try {
      const regex = new RegExp(pattern, flags);
      const foundMatches: string[] = [];
      let match;

      if (flags.includes('g')) {
        while ((match = regex.exec(text)) !== null) {
          foundMatches.push(match[0]);
          if (foundMatches.length > 100) break; // Limit matches
        }
      } else {
        match = regex.exec(text);
        if (match) foundMatches.push(match[0]);
      }

      onChange({
        ...data,
        matches: foundMatches,
        matchCount: foundMatches.length,
        error: ''
      });
    } catch (e) {
      onChange({
        ...data,
        matches: [],
        matchCount: 0,
        error: e instanceof Error ? e.message : 'Invalid regex'
      });
    }
  };

  const toggleFlag = (flag: string) => {
    const newFlags = flags.includes(flag)
      ? flags.replace(flag, '')
      : flags + flag;
    onChange({ ...data, flags: newFlags });
  };

  const getHighlightedText = () => {
    if (!pattern || error) return text;
    try {
      const regex = new RegExp(pattern, flags.includes('g') ? flags : flags + 'g');
      return text.replace(regex, (match) => `<mark class="bg-yellow-500 text-black">${match}</mark>`);
    } catch {
      return text;
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">Regex Pattern</label>
        <input
          type="text"
          value={pattern}
          onChange={(e) => onChange({ ...data, pattern: e.target.value })}
          placeholder="Enter regex pattern..."
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-sm"
        />
      </div>

      <div className="flex gap-2">
        <label className="flex items-center gap-1 text-xs text-gray-300">
          <input
            type="checkbox"
            checked={flags.includes('g')}
            onChange={() => toggleFlag('g')}
            className="w-3 h-3"
          />
          global
        </label>
        <label className="flex items-center gap-1 text-xs text-gray-300">
          <input
            type="checkbox"
            checked={flags.includes('i')}
            onChange={() => toggleFlag('i')}
            className="w-3 h-3"
          />
          case-insensitive
        </label>
        <label className="flex items-center gap-1 text-xs text-gray-300">
          <input
            type="checkbox"
            checked={flags.includes('m')}
            onChange={() => toggleFlag('m')}
            className="w-3 h-3"
          />
          multiline
        </label>
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1">Test String</label>
        <textarea
          value={text}
          onChange={(e) => onChange({ ...data, text: e.target.value })}
          placeholder="Enter text to test against..."
          rows={4}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
        />
      </div>

      <button
        onClick={handleTest}
        className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-sm"
      >
        Test Regex
      </button>

      {error && (
        <div className="text-red-400 text-xs p-2 bg-red-900/20 rounded">{error}</div>
      )}

      {matchCount > 0 && (
        <>
          <div className="text-sm text-green-400">
            Found {matchCount} match{matchCount !== 1 ? 'es' : ''}
          </div>

          <div>
            <label className="block text-xs text-gray-400 mb-1">Highlighted Matches</label>
            <div
              className="p-3 bg-[#0d0d1a] border border-gray-700 rounded text-white font-mono text-xs whitespace-pre-wrap"
              dangerouslySetInnerHTML={{ __html: getHighlightedText() }}
            />
          </div>

          <div>
            <label className="block text-xs text-gray-400 mb-1">Match List</label>
            <div className="p-2 bg-[#1a1a2e] border border-gray-700 rounded text-xs font-mono max-h-24 overflow-y-auto">
              {matches.map((match, idx) => (
                <div key={idx} className="text-green-400">
                  [{idx}]: &quot;{match}&quot;
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export class RegexHighlighterTool {
  static Component = RegexHighlighter;
}
