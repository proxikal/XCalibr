import React, { useState, useEffect, useRef } from 'react';

export type ScratchpadData = {
  content?: string;
  lastSaved?: number;
};

type Props = {
  data: ScratchpadData | undefined;
  onChange: (data: ScratchpadData) => void;
};

const Scratchpad: React.FC<Props> = ({ data, onChange }) => {
  const content = data?.content ?? '';
  const lastSaved = data?.lastSaved;
  const [saveStatus, setSaveStatus] = useState<'saved' | 'saving' | 'idle'>('idle');
  const saveTimeoutRef = useRef<number | null>(null);

  useEffect(() => {
    if (saveTimeoutRef.current) {
      clearTimeout(saveTimeoutRef.current);
    }

    if (content !== '') {
      setSaveStatus('saving');
      saveTimeoutRef.current = window.setTimeout(() => {
        onChange({ ...data, content, lastSaved: Date.now() });
        setSaveStatus('saved');
      }, 500);
    }

    return () => {
      if (saveTimeoutRef.current) {
        clearTimeout(saveTimeoutRef.current);
      }
    };
  }, [content]);

  const handleChange = (newContent: string) => {
    onChange({ ...data, content: newContent });
  };

  const handleClear = () => {
    onChange({ ...data, content: '', lastSaved: Date.now() });
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(content);
  };

  const wordCount = content.trim() ? content.trim().split(/\s+/).length : 0;
  const charCount = content.length;

  const formatLastSaved = () => {
    if (!lastSaved) return '';
    const now = Date.now();
    const diff = now - lastSaved;
    if (diff < 1000) return 'just now';
    if (diff < 60000) return `${Math.floor(diff / 1000)}s ago`;
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    return new Date(lastSaved).toLocaleTimeString();
  };

  return (
    <div className="space-y-3">
      <div className="flex justify-between items-center">
        <div className="text-xs text-gray-400">
          Persistent Scratchpad
        </div>
        <div className="flex items-center gap-2 text-xs">
          {saveStatus === 'saving' && (
            <span className="text-yellow-400">Saving...</span>
          )}
          {saveStatus === 'saved' && lastSaved && (
            <span className="text-green-400">Saved {formatLastSaved()}</span>
          )}
        </div>
      </div>

      <textarea
        value={content}
        onChange={(e) => handleChange(e.target.value)}
        placeholder="Write your notes here... Auto-saves as you type."
        className="w-full h-48 px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm resize-none focus:outline-none focus:border-blue-500"
      />

      <div className="flex justify-between items-center text-xs text-gray-500">
        <div>
          {wordCount} words, {charCount} characters
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleCopy}
            disabled={!content}
            className="text-blue-400 hover:text-blue-300 disabled:text-gray-600"
          >
            Copy
          </button>
          <button
            onClick={handleClear}
            disabled={!content}
            className="text-red-400 hover:text-red-300 disabled:text-gray-600"
          >
            Clear
          </button>
        </div>
      </div>
    </div>
  );
};

export class ScratchpadTool {
  static Component = Scratchpad;
}
