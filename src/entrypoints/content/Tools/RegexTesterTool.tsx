import React, { useState } from 'react';
import {
  runRegexTest
} from './helpers';
import type {
  RegexTesterData
} from './tool-types';

const RegexTesterToolComponent = ({
  data,
  onChange
}: {
  data: RegexTesterData | undefined;
  onChange: (next: RegexTesterData) => void;
}) => {
  const pattern = data?.pattern ?? '';
  const flags = data?.flags ?? 'g';
  const text = data?.text ?? '';
  const matches = data?.matches ?? [];
  const error = data?.error ?? '';
  const [mode, setMode] = useState<'custom' | 'page'>('custom');

  const getPageText = (): string => {
    const xcalibrRoot = document.getElementById('xcalibr-root');
    const clone = document.body.cloneNode(true) as HTMLElement;
    const xcalibrInClone = clone.querySelector('#xcalibr-root');
    if (xcalibrInClone) xcalibrInClone.remove();
    return clone.innerText || clone.textContent || '';
  };

  const handleTest = () => {
    const testText = mode === 'page' ? getPageText() : text;
    const result = runRegexTest(pattern, flags, testText);
    onChange({
      pattern,
      flags,
      text: mode === 'custom' ? text : testText.slice(0, 1000) + (testText.length > 1000 ? '...' : ''),
      matches: result.matches.slice(0, 100),
      error: result.error ?? ''
    });
  };

  const handleTestPage = () => {
    setMode('page');
    const pageText = getPageText();
    const result = runRegexTest(pattern, flags, pageText);
    onChange({
      pattern,
      flags,
      text: pageText.slice(0, 1000) + (pageText.length > 1000 ? '...' : ''),
      matches: result.matches.slice(0, 100),
      error: result.error ?? ''
    });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Regex Tester</div>
      <input
        type="text"
        value={pattern}
        onChange={(event) => onChange({ pattern: event.target.value, flags, text, matches, error })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder="Regex pattern"
      />
      <input
        type="text"
        value={flags}
        onChange={(event) => onChange({ pattern, flags: event.target.value, text, matches, error })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder="Flags (e.g. gi)"
      />

      <div className="flex gap-1">
        <button
          type="button"
          onClick={() => setMode('custom')}
          className={`flex-1 rounded px-2 py-1 text-[10px] border transition-colors ${
            mode === 'custom'
              ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
              : 'bg-slate-800 border-slate-700 text-slate-400'
          }`}
        >
          Custom Text
        </button>
        <button
          type="button"
          onClick={() => setMode('page')}
          className={`flex-1 rounded px-2 py-1 text-[10px] border transition-colors ${
            mode === 'page'
              ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
              : 'bg-slate-800 border-slate-700 text-slate-400'
          }`}
        >
          Page Content
        </button>
      </div>

      {mode === 'custom' && (
        <textarea
          value={text}
          onChange={(event) => onChange({ pattern, flags, text: event.target.value, matches, error })}
          rows={4}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
          placeholder="Test string..."
        />
      )}

      {mode === 'page' && (
        <div className="text-[10px] text-slate-500 p-2 bg-slate-800/50 rounded border border-slate-700">
          Will test against current page text content
        </div>
      )}

      {error ? <div className="text-[11px] text-rose-300">{error}</div> : null}

      <div className="flex gap-2">
        <button
          type="button"
          onClick={handleTest}
          className="flex-1 rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
        >
          Run Test
        </button>
        {mode === 'custom' && (
          <button
            type="button"
            onClick={handleTestPage}
            className="rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
            title="Test on page content"
          >
            Test Page
          </button>
        )}
      </div>

      <div className="rounded border border-slate-800 bg-slate-900/60 p-3 text-[11px] text-slate-300 max-h-32 overflow-y-auto">
        {matches.length === 0 ? (
          'No matches.'
        ) : (
          <div className="space-y-1">
            <div className="text-[10px] text-slate-500">{matches.length} match{matches.length !== 1 ? 'es' : ''}</div>
            {matches.map((match, i) => (
              <div key={i} className="font-mono break-all bg-slate-800/50 px-1 rounded">
                {match}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
export class RegexTesterTool {
  static Component = RegexTesterToolComponent;
}
