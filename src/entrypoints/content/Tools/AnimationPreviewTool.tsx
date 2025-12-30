import React from 'react';
import type {
  AnimationPreviewData
} from './tool-types';

const AnimationPreviewToolComponent = ({
  data,
  onChange
}: {
  data: AnimationPreviewData | undefined;
  onChange: (next: AnimationPreviewData) => void;
}) => {
  const css = data?.css ?? 'animation: pulse 1.2s ease-in-out infinite;';
  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Animation Preview</div>
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
          @keyframes pulse { 0% { transform: scale(1); } 50% { transform: scale(1.15); } 100% { transform: scale(1); } }
          .xcalibr-animation-preview { ${css} }
        `}</style>
      </div>
    </div>
  );
};
export class AnimationPreviewTool {
  static Component = AnimationPreviewToolComponent;
}
