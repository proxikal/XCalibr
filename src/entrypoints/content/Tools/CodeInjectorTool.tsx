import React, { useState, useRef, useLayoutEffect } from 'react';
import type {
  CodeInjectorData
} from './tool-types';

const CodeInjectorToolComponent = ({
  data,
  onChange,
  onInject
}: {
  data: CodeInjectorData | undefined;
  onChange: (next: CodeInjectorData) => void;
  onInject: (payload: Required<CodeInjectorData>) => Promise<void>;
}) => {
  const [isInjecting, setIsInjecting] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const cursorPositionRef = useRef<{ start: number; end: number } | null>(null);
  const scope = data?.scope ?? 'current';
  const code = data?.code ?? '';
  const update = (next: Partial<CodeInjectorData>) =>
    onChange({ scope, code, ...next });

  // Restore cursor position after re-render
  useLayoutEffect(() => {
    if (textareaRef.current && cursorPositionRef.current) {
      const { start, end } = cursorPositionRef.current;
      textareaRef.current.setSelectionRange(start, end);
      cursorPositionRef.current = null;
    }
  }, [code]);

  const handleCodeChange = (event: React.ChangeEvent<HTMLTextAreaElement>) => {
    // Save cursor position before state update
    cursorPositionRef.current = {
      start: event.target.selectionStart,
      end: event.target.selectionEnd
    };
    update({ code: event.target.value });
  };

  const handleInject = async () => {
    if (!code.trim()) {
      setStatus('Add some CSS to inject.');
      return;
    }
    setIsInjecting(true);
    setStatus(null);
    try {
      await onInject({ scope, code });
      setStatus('CSS injected successfully.');
    } catch {
      setStatus('Injection failed. Check permissions.');
    } finally {
      setIsInjecting(false);
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">CSS Injector</div>
      <div className="text-[11px] text-slate-500">
        Inject custom CSS styles into the current page or all tabs.
      </div>

      <div className="space-y-2">
        <div className="text-[11px] uppercase tracking-[0.2em] text-slate-500">
          Target
        </div>
        <div className="flex gap-2">
          {([
            { value: 'current', label: 'Current Tab' },
            { value: 'all', label: 'All Tabs' }
          ] as const).map((entry) => (
            <button
              key={entry.value}
              type="button"
              onClick={() => update({ scope: entry.value })}
              className={`flex-1 rounded px-2 py-1 text-[11px] border transition-colors ${
                scope === entry.value
                  ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              {entry.label}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-2">
        <textarea
          ref={textareaRef}
          value={code}
          onChange={handleCodeChange}
          placeholder="/* Paste CSS here */"
          rows={6}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors placeholder:text-slate-500 font-mono"
        />
        {status ? (
          <div className="text-[11px] text-slate-400">{status}</div>
        ) : null}
      </div>

      <button
        type="button"
        onClick={handleInject}
        disabled={isInjecting}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        {isInjecting ? 'Injecting...' : 'Inject CSS'}
      </button>
    </div>
  );
};
export class CodeInjectorTool {
  static Component = CodeInjectorToolComponent;
}
