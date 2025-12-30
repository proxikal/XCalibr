import React, { useEffect, useRef } from 'react';
import type {
  FontIdentifierData,
  FontCaptureEntry
} from './tool-types';

const generateId = () =>
  typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID()
    : `font_${Date.now()}_${Math.random().toString(16).slice(2)}`;

const FontIdentifierToolComponent = ({
  data,
  onChange
}: {
  data: FontIdentifierData | undefined;
  onChange: (next: FontIdentifierData) => void;
}) => {
  const isActive = data?.isActive ?? false;
  const history = data?.history ?? [];
  const highlightRef = useRef<HTMLDivElement | null>(null);
  const lastElementRef = useRef<Element | null>(null);

  useEffect(() => {
    if (!isActive) {
      if (highlightRef.current) {
        highlightRef.current.remove();
        highlightRef.current = null;
      }
      lastElementRef.current = null;
      return;
    }

    const createHighlight = () => {
      const div = document.createElement('div');
      div.style.position = 'fixed';
      div.style.pointerEvents = 'none';
      div.style.border = '2px solid #3b82f6';
      div.style.borderRadius = '4px';
      div.style.background = 'rgba(59, 130, 246, 0.1)';
      div.style.zIndex = '2147483645';
      div.style.transition = 'all 0.15s ease';
      document.body.appendChild(div);
      return div;
    };

    const handleMouseMove = (event: MouseEvent) => {
      const target = event.target as Element | null;
      if (!target || target === lastElementRef.current) return;

      // Don't highlight our own UI
      const xcalibrRoot = document.getElementById('xcalibr-root');
      if (xcalibrRoot?.contains(target)) {
        if (highlightRef.current) {
          highlightRef.current.style.display = 'none';
        }
        return;
      }

      lastElementRef.current = target;

      if (!highlightRef.current) {
        highlightRef.current = createHighlight();
      }

      const rect = target.getBoundingClientRect();
      highlightRef.current.style.display = 'block';
      highlightRef.current.style.top = `${rect.top}px`;
      highlightRef.current.style.left = `${rect.left}px`;
      highlightRef.current.style.width = `${rect.width}px`;
      highlightRef.current.style.height = `${rect.height}px`;
    };

    const handleClick = (event: MouseEvent) => {
      const target = event.target as Element | null;
      if (!target) return;

      // Don't capture from our own UI
      const xcalibrRoot = document.getElementById('xcalibr-root');
      if (xcalibrRoot?.contains(target)) return;

      event.preventDefault();
      event.stopPropagation();

      const style = window.getComputedStyle(target);
      const entry: FontCaptureEntry = {
        id: generateId(),
        timestamp: Date.now(),
        fontFamily: style.fontFamily,
        fontSize: style.fontSize,
        fontWeight: style.fontWeight,
        lineHeight: style.lineHeight,
        element: target.tagName.toLowerCase()
      };

      onChange({
        isActive: false,
        history: [entry, ...history]
      });
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('click', handleClick, true);

    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('click', handleClick, true);
      if (highlightRef.current) {
        highlightRef.current.remove();
        highlightRef.current = null;
      }
    };
  }, [isActive, history, onChange]);

  const handleExport = () => {
    const json = JSON.stringify(history, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `font-history-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleClearHistory = () => {
    onChange({ isActive: false, history: [] });
  };

  const handleRemoveEntry = (id: string) => {
    onChange({
      ...data,
      history: history.filter((entry) => entry.id !== id)
    });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Font Identifier</div>
      <div className="text-[11px] text-slate-500">
        Click to activate, then click any element to capture its font data.
      </div>

      <button
        type="button"
        onClick={() => onChange({ ...data, isActive: !isActive })}
        className={`w-full rounded px-2 py-1.5 text-xs border transition-colors ${
          isActive
            ? 'bg-blue-500/10 border-blue-500/40 text-blue-200'
            : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
        }`}
      >
        {isActive ? 'Picking... (click an element)' : 'Activate Picker'}
      </button>

      {history.length > 0 && (
        <>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={handleExport}
              className="flex-1 rounded bg-slate-800 px-2 py-1 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
            >
              Export JSON
            </button>
            <button
              type="button"
              onClick={handleClearHistory}
              className="flex-1 rounded bg-slate-800 px-2 py-1 text-xs text-rose-300 hover:bg-slate-700 transition-colors"
            >
              Clear All
            </button>
          </div>

          <div className="space-y-2 max-h-[200px] overflow-y-auto">
            {history.map((entry) => (
              <div
                key={entry.id}
                className="rounded border border-slate-800 bg-slate-900/60 p-2 text-[10px]"
              >
                <div className="flex justify-between items-start mb-1">
                  <span className="text-slate-400">
                    {new Date(entry.timestamp).toLocaleTimeString()}
                  </span>
                  <button
                    type="button"
                    onClick={() => handleRemoveEntry(entry.id)}
                    className="text-slate-500 hover:text-rose-400 text-[9px]"
                  >
                    ✕
                  </button>
                </div>
                <div className="space-y-0.5 text-slate-300">
                  <div className="truncate" title={entry.fontFamily}>
                    <span className="text-slate-500">Family:</span> {entry.fontFamily}
                  </div>
                  <div>
                    <span className="text-slate-500">Size:</span> {entry.fontSize}
                  </div>
                  <div>
                    <span className="text-slate-500">Weight:</span> {entry.fontWeight}
                  </div>
                  <div>
                    <span className="text-slate-500">Line Height:</span> {entry.lineHeight}
                  </div>
                  {entry.element && (
                    <div>
                      <span className="text-slate-500">Element:</span> &lt;{entry.element}&gt;
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {history.length === 0 && (
        <div className="rounded border border-slate-800 bg-slate-900/60 p-3 text-[11px] text-slate-400 text-center">
          No fonts captured yet. Activate the picker and click an element.
        </div>
      )}
    </div>
  );
};

export class FontIdentifierTool {
  static Component = FontIdentifierToolComponent;
}
