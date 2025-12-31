import React, { useEffect, useMemo, useRef, useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSearch } from '@fortawesome/free-solid-svg-icons';
import type { ToolRegistryEntry } from '../toolregistry';

type SpotlightSearchProps = {
  toolRegistry: ToolRegistryEntry[];
  onOpenTool: (toolId: string) => Promise<void>;
  onClose: () => void;
};

export const SpotlightSearch: React.FC<SpotlightSearchProps> = ({
  toolRegistry,
  onOpenTool,
  onClose
}) => {
  const [query, setQuery] = useState('');
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    requestAnimationFrame(() => inputRef.current?.focus());
  }, []);

  const searchableTools = useMemo(
    () =>
      toolRegistry.map((tool) => ({
        id: tool.id,
        label: tool.title,
        subtitle: tool.subtitle
      })),
    [toolRegistry]
  );

  const matches = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return searchableTools;
    return searchableTools.filter((entry) => {
      const label = entry.label.toLowerCase();
      const subtitle = entry.subtitle?.toLowerCase() ?? '';
      return label.includes(q) || subtitle.includes(q);
    });
  }, [query, searchableTools]);

  const handleOpenTool = async (toolId: string) => {
    await onOpenTool(toolId);
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-[90] flex items-start justify-center bg-slate-950/70 backdrop-blur-sm"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <div
        className="mt-24 w-full max-w-xl rounded-2xl border border-slate-700/80 bg-gradient-to-b from-slate-900 via-slate-900 to-slate-950 shadow-[0_24px_60px_rgba(0,0,0,0.55)]"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="flex items-center gap-3 border-b border-slate-800 px-5 py-4">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-slate-800/80 text-slate-300">
            <FontAwesomeIcon icon={faSearch} className="w-4 h-4" />
          </div>
          <div className="flex-1">
            <div className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
              XCalibr Spotlight
            </div>
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={(event) => {
                if (event.key !== 'Enter') return;
                event.preventDefault();
                const match = matches[0];
                if (!match) return;
                handleOpenTool(match.id);
              }}
              placeholder="Search tools..."
              className="mt-1 w-full bg-transparent text-lg text-slate-100 placeholder:text-slate-500 focus:outline-none"
            />
          </div>
          <div className="text-[10px] text-slate-500">Cmd+Shift+P</div>
        </div>
        <div className="max-h-72 overflow-y-auto p-2">
          {matches.length === 0 ? (
            <div className="px-4 py-6 text-sm text-slate-400">
              Nothing found. Try another keyword.
            </div>
          ) : (
            matches.map((entry) => (
              <button
                key={entry.id}
                type="button"
                className="w-full rounded-xl px-4 py-3 text-left transition-colors hover:bg-slate-800/80"
                onClick={() => handleOpenTool(entry.id)}
              >
                <div className="text-sm text-slate-100">{entry.label}</div>
                <div className="text-[11px] text-slate-500">
                  {entry.subtitle ?? 'Open tool'}
                </div>
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
