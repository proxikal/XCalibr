import React, { useState } from 'react';
import type {
  AnimationPreviewData
} from './tool-types';

const defaultCss = 'animation: pulse 1.2s ease-in-out infinite;';
const defaultKeyframes = '@keyframes pulse { 0% { transform: scale(1); } 50% { transform: scale(1.15); } 100% { transform: scale(1); } }';

const AnimationPreviewToolComponent = ({
  data,
  onChange,
  onInject
}: {
  data: AnimationPreviewData | undefined;
  onChange: (next: AnimationPreviewData) => void;
  onInject: (css: string) => Promise<void>;
}) => {
  const css = data?.css ?? defaultCss;
  const [isInjecting, setIsInjecting] = useState(false);
  const [status, setStatus] = useState<string | null>(null);

  const handleInject = async () => {
    if (!css.trim()) {
      setStatus('Add some CSS to inject.');
      return;
    }
    setIsInjecting(true);
    setStatus(null);
    try {
      // Build full CSS with keyframes
      const fullCss = `${defaultKeyframes}\n.xcalibr-animated { ${css} }`;
      await onInject(fullCss);
      setStatus('Injected! Add class "xcalibr-animated" to elements.');
    } catch {
      setStatus('Injection failed. Check permissions.');
    } finally {
      setIsInjecting(false);
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Animation Preview</div>
      <div className="text-[11px] text-slate-500">
        Preview animations and inject them into the page.
      </div>
      <textarea
        value={css}
        onChange={(event) => onChange({ css: event.target.value })}
        rows={4}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="CSS animation..."
      />
      <div className="rounded border border-slate-800 bg-slate-900/60 p-4">
        <div className="xcalibr-animation-preview h-12 w-12 rounded bg-blue-500/70" />
        <style>{`
          ${defaultKeyframes}
          .xcalibr-animation-preview { ${css} }
        `}</style>
      </div>
      {status ? (
        <div className="text-[11px] text-slate-400">{status}</div>
      ) : null}
      <button
        type="button"
        onClick={handleInject}
        disabled={isInjecting}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        {isInjecting ? 'Injecting...' : 'Inject into Page'}
      </button>
    </div>
  );
};
export class AnimationPreviewTool {
  static Component = AnimationPreviewToolComponent;
}
