import React, { useEffect, useCallback } from 'react';

export type KeycodeInfoData = {
  lastKey?: string;
  lastCode?: string;
  lastKeyCode?: number;
  ctrlKey?: boolean;
  shiftKey?: boolean;
  altKey?: boolean;
  metaKey?: boolean;
  history?: Array<{
    key: string;
    code: string;
    keyCode: number;
    timestamp: number;
  }>;
};

type Props = {
  data: KeycodeInfoData | undefined;
  onChange: (data: KeycodeInfoData) => void;
};

const KeycodeInfo: React.FC<Props> = ({ data, onChange }) => {
  const lastKey = data?.lastKey ?? '';
  const lastCode = data?.lastCode ?? '';
  const lastKeyCode = data?.lastKeyCode ?? 0;
  const ctrlKey = data?.ctrlKey ?? false;
  const shiftKey = data?.shiftKey ?? false;
  const altKey = data?.altKey ?? false;
  const metaKey = data?.metaKey ?? false;
  const history = data?.history ?? [];

  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    const newEntry = {
      key: e.key,
      code: e.code,
      keyCode: e.keyCode,
      timestamp: Date.now()
    };

    const newHistory = [newEntry, ...history].slice(0, 10);

    onChange({
      ...data,
      lastKey: e.key,
      lastCode: e.code,
      lastKeyCode: e.keyCode,
      ctrlKey: e.ctrlKey,
      shiftKey: e.shiftKey,
      altKey: e.altKey,
      metaKey: e.metaKey,
      history: newHistory
    });
  }, [data, history, onChange]);

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [handleKeyDown]);

  const clearHistory = () => {
    onChange({
      ...data,
      lastKey: '',
      lastCode: '',
      lastKeyCode: 0,
      ctrlKey: false,
      shiftKey: false,
      altKey: false,
      metaKey: false,
      history: []
    });
  };

  const getDisplayKey = (key: string) => {
    const specialKeys: Record<string, string> = {
      ' ': 'Space',
      'Enter': 'Enter ↵',
      'Tab': 'Tab ⇥',
      'Escape': 'Esc',
      'Backspace': '⌫',
      'Delete': 'Del',
      'ArrowUp': '↑',
      'ArrowDown': '↓',
      'ArrowLeft': '←',
      'ArrowRight': '→',
      'Control': 'Ctrl',
      'Meta': '⌘',
      'Alt': 'Alt',
      'Shift': '⇧'
    };
    return specialKeys[key] || key;
  };

  return (
    <div className="space-y-4">
      <div className="text-center text-gray-400 text-sm py-4 bg-[#1a1a2e] rounded border border-gray-700">
        Press any key to see its info
      </div>

      {lastKey && (
        <>
          <div className="text-center">
            <div className="inline-block px-6 py-4 bg-[#1a1a2e] border-2 border-indigo-500 rounded-lg">
              <span className="text-3xl font-bold text-white">
                {getDisplayKey(lastKey)}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="bg-[#1a1a2e] border border-gray-700 rounded p-2">
              <div className="text-gray-400">event.key</div>
              <div className="text-white font-mono">{lastKey}</div>
            </div>
            <div className="bg-[#1a1a2e] border border-gray-700 rounded p-2">
              <div className="text-gray-400">event.code</div>
              <div className="text-white font-mono">{lastCode}</div>
            </div>
            <div className="bg-[#1a1a2e] border border-gray-700 rounded p-2">
              <div className="text-gray-400">event.keyCode</div>
              <div className="text-white font-mono">{lastKeyCode}</div>
            </div>
            <div className="bg-[#1a1a2e] border border-gray-700 rounded p-2">
              <div className="text-gray-400">charCode</div>
              <div className="text-white font-mono">{lastKey.charCodeAt(0) || 0}</div>
            </div>
          </div>

          <div className="flex gap-2 text-xs">
            {ctrlKey && <span className="px-2 py-1 bg-blue-600 text-white rounded">Ctrl</span>}
            {shiftKey && <span className="px-2 py-1 bg-green-600 text-white rounded">Shift</span>}
            {altKey && <span className="px-2 py-1 bg-yellow-600 text-white rounded">Alt</span>}
            {metaKey && <span className="px-2 py-1 bg-purple-600 text-white rounded">Meta/Cmd</span>}
            {!ctrlKey && !shiftKey && !altKey && !metaKey && (
              <span className="text-gray-500">No modifiers</span>
            )}
          </div>
        </>
      )}

      {history.length > 0 && (
        <div>
          <div className="flex justify-between items-center mb-2">
            <label className="text-xs text-gray-400">History</label>
            <button
              onClick={clearHistory}
              className="text-xs text-gray-400 hover:text-white"
            >
              Clear
            </button>
          </div>
          <div className="space-y-1 max-h-32 overflow-y-auto">
            {history.map((entry, i) => (
              <div
                key={entry.timestamp + i}
                className="flex justify-between items-center text-xs bg-[#1a1a2e] border border-gray-700 rounded px-2 py-1"
              >
                <span className="text-white font-mono">{getDisplayKey(entry.key)}</span>
                <span className="text-gray-400">{entry.code}</span>
                <span className="text-gray-500">{entry.keyCode}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export class KeycodeInfoTool {
  static Component = KeycodeInfo;
}
