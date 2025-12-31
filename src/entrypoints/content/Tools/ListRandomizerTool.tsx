import React from 'react';

export type ListRandomizerData = {
  input?: string;
  output?: string;
  winner?: string;
  pickCount?: number;
};

type Props = {
  data: ListRandomizerData | undefined;
  onChange: (data: ListRandomizerData) => void;
};

const ListRandomizer: React.FC<Props> = ({ data, onChange }) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const winner = data?.winner ?? '';
  const pickCount = data?.pickCount ?? 1;

  const getItems = () => {
    return input.split('\n').map(l => l.trim()).filter(l => l.length > 0);
  };

  const shuffle = () => {
    const items = getItems();
    for (let i = items.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [items[i], items[j]] = [items[j], items[i]];
    }
    onChange({
      ...data,
      output: items.join('\n'),
      winner: ''
    });
  };

  const pickWinner = () => {
    const items = getItems();
    if (items.length === 0) return;

    if (pickCount === 1) {
      const randomIndex = Math.floor(Math.random() * items.length);
      onChange({
        ...data,
        winner: items[randomIndex],
        output: ''
      });
    } else {
      // Pick multiple random items
      const shuffled = [...items];
      for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
      }
      const winners = shuffled.slice(0, Math.min(pickCount, items.length));
      onChange({
        ...data,
        winner: winners.join('\n'),
        output: ''
      });
    }
  };

  const copyOutput = () => {
    if (output) {
      navigator.clipboard.writeText(output);
    }
  };

  const itemCount = getItems().length;

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">Items (one per line)</label>
        <textarea
          value={input}
          onChange={(e) => onChange({ ...data, input: e.target.value, winner: '', output: '' })}
          placeholder="Enter items to randomize..."
          rows={6}
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-xs resize-none"
        />
        <div className="text-xs text-gray-500 mt-1">{itemCount} items</div>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <button
          onClick={shuffle}
          disabled={itemCount === 0}
          className="py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
        >
          Shuffle All
        </button>
        <button
          onClick={pickWinner}
          disabled={itemCount === 0}
          className="py-2 bg-green-600 hover:bg-green-500 disabled:bg-gray-600 text-white rounded text-sm"
        >
          Pick Winner
        </button>
      </div>

      <div className="flex items-center gap-2">
        <label className="text-xs text-gray-400">Pick</label>
        <input
          type="number"
          min="1"
          max="100"
          value={pickCount}
          onChange={(e) => onChange({ ...data, pickCount: Math.max(1, Number(e.target.value)) })}
          className="w-16 px-2 py-1 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
        />
        <span className="text-xs text-gray-400">random item(s)</span>
      </div>

      {winner && (
        <div className="bg-gradient-to-r from-green-900/50 to-blue-900/50 border border-green-600 rounded p-4 text-center">
          <div className="text-xs text-gray-400 mb-2">Winner{pickCount > 1 ? 's' : ''}!</div>
          <div className="text-xl font-bold text-white whitespace-pre-line">{winner}</div>
        </div>
      )}

      {output && (
        <div>
          <div className="flex justify-between items-center mb-1">
            <label className="text-xs text-gray-400">Shuffled List</label>
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
            rows={6}
            className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-green-400 font-mono text-xs resize-none"
          />
        </div>
      )}
    </div>
  );
};

export class ListRandomizerTool {
  static Component = ListRandomizer;
}
