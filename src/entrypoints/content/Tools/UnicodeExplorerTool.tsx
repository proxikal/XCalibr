import React from 'react';

export type UnicodeExplorerData = {
  search?: string;
  category?: string;
  selectedChar?: string;
  charCode?: number;
};

type Props = {
  data: UnicodeExplorerData | undefined;
  onChange: (data: UnicodeExplorerData) => void;
};

const categories: Record<string, { start: number; end: number; name: string }> = {
  arrows: { start: 0x2190, end: 0x21FF, name: 'Arrows' },
  math: { start: 0x2200, end: 0x22FF, name: 'Math Operators' },
  symbols: { start: 0x2600, end: 0x26FF, name: 'Misc Symbols' },
  dingbats: { start: 0x2700, end: 0x27BF, name: 'Dingbats' },
  box: { start: 0x2500, end: 0x257F, name: 'Box Drawing' },
  blocks: { start: 0x2580, end: 0x259F, name: 'Block Elements' },
  geometric: { start: 0x25A0, end: 0x25FF, name: 'Geometric Shapes' },
  emoji: { start: 0x1F600, end: 0x1F64F, name: 'Emoji Faces' },
  currency: { start: 0x20A0, end: 0x20CF, name: 'Currency' },
  greek: { start: 0x0370, end: 0x03FF, name: 'Greek' }
};

const getCharsForCategory = (cat: string): string[] => {
  const range = categories[cat];
  if (!range) return [];

  const chars: string[] = [];
  for (let i = range.start; i <= range.end && chars.length < 100; i++) {
    try {
      const char = String.fromCodePoint(i);
      if (char.trim()) {
        chars.push(char);
      }
    } catch {
      // Skip invalid code points
    }
  }
  return chars;
};

const UnicodeExplorer: React.FC<Props> = ({ data, onChange }) => {
  const search = data?.search ?? '';
  const category = data?.category ?? 'arrows';
  const selectedChar = data?.selectedChar ?? '';
  const charCode = data?.charCode;

  const chars = getCharsForCategory(category);

  const handleCharClick = (char: string) => {
    onChange({
      ...data,
      selectedChar: char,
      charCode: char.codePointAt(0)
    });
    navigator.clipboard.writeText(char);
  };

  const filteredChars = search
    ? chars.filter(c => c.includes(search) || c.codePointAt(0)?.toString(16).includes(search.toLowerCase()))
    : chars;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="block text-xs text-gray-400 mb-1">Category</label>
          <select
            value={category}
            onChange={(e) => onChange({ ...data, category: e.target.value })}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          >
            {Object.entries(categories).map(([key, val]) => (
              <option key={key} value={key}>{val.name}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Search</label>
          <input
            type="text"
            value={search}
            onChange={(e) => onChange({ ...data, search: e.target.value })}
            placeholder="Search..."
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
          />
        </div>
      </div>

      <div className="grid grid-cols-10 gap-1 max-h-48 overflow-y-auto p-2 bg-[#0d0d1a] rounded border border-gray-700">
        {filteredChars.map((char, idx) => (
          <button
            key={idx}
            onClick={() => handleCharClick(char)}
            className={`p-2 text-xl rounded hover:bg-gray-700 transition-colors ${
              selectedChar === char ? 'bg-blue-600' : 'bg-[#1a1a2e]'
            }`}
            title={`U+${char.codePointAt(0)?.toString(16).toUpperCase()}`}
          >
            {char}
          </button>
        ))}
      </div>

      {selectedChar && charCode !== undefined && (
        <div className="bg-[#1a1a2e] border border-gray-700 rounded p-4">
          <div className="flex items-center gap-4">
            <div className="text-4xl">{selectedChar}</div>
            <div className="space-y-1 text-xs">
              <div><span className="text-gray-400">Character:</span> <span className="text-white">{selectedChar}</span></div>
              <div><span className="text-gray-400">Unicode:</span> <span className="text-green-400">U+{charCode.toString(16).toUpperCase().padStart(4, '0')}</span></div>
              <div><span className="text-gray-400">Decimal:</span> <span className="text-blue-400">{charCode}</span></div>
              <div><span className="text-gray-400">HTML:</span> <span className="text-yellow-400">&amp;#{charCode};</span></div>
            </div>
          </div>
          <div className="text-xs text-green-400 mt-2">Copied to clipboard!</div>
        </div>
      )}

      <div className="text-xs text-gray-500">
        Click any character to copy. Showing {filteredChars.length} characters.
      </div>
    </div>
  );
};

export class UnicodeExplorerTool {
  static Component = UnicodeExplorer;
}
