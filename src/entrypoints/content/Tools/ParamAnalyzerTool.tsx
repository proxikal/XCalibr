import React from 'react';
import {
  buildUrlWithParams
} from './helpers';
import type {
  ParamAnalyzerData
} from './tool-types';

const ParamAnalyzerToolComponent = ({
  data,
  onChange,
  onRefresh
}: {
  data: ParamAnalyzerData | undefined;
  onChange: (next: ParamAnalyzerData) => void;
  onRefresh: () => Promise<void>;
}) => {
  const params = data?.params ?? [];
  const url = data?.url ?? window.location.href;
  const updateParams = (nextParams: { key: string; value: string }[]) =>
    onChange({ url, params: nextParams });
  const applyUrl = (nextUrl: string) => {
    navigator.clipboard.writeText(nextUrl);
    window.location.href = nextUrl;
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs text-slate-200">Param Analyzer</div>
          <div className="text-[11px] text-slate-500">{url}</div>
        </div>
        <button
          type="button"
          onClick={onRefresh}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Refresh
        </button>
      </div>

      {params.length === 0 ? (
        <div className="text-[11px] text-slate-500">
          No query parameters detected.
        </div>
      ) : null}

      <div className="space-y-2">
        {params.map((param, index) => (
          <div key={`${param.key}-${index}`} className="flex gap-2">
            <input
              type="text"
              value={param.key}
              onChange={(event) => {
                const next = [...params];
                next[index] = { ...next[index], key: event.target.value };
                updateParams(next);
              }}
              className="w-1/3 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
              placeholder="Key"
            />
            <input
              type="text"
              value={param.value}
              onChange={(event) => {
                const next = [...params];
                next[index] = { ...next[index], value: event.target.value };
                updateParams(next);
              }}
              className="flex-1 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
              placeholder="Value"
            />
            <button
              type="button"
              onClick={() => updateParams(params.filter((_, i) => i !== index))}
              className="rounded bg-slate-800 px-2 text-[11px] text-slate-400 hover:text-slate-200"
            >
              ×
            </button>
          </div>
        ))}
      </div>

      <button
        type="button"
        onClick={() => updateParams([...params, { key: '', value: '' }])}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Add Param
      </button>

      <button
        type="button"
        onClick={() => {
          const nextUrl = buildUrlWithParams(url, params);
          navigator.clipboard.writeText(nextUrl);
        }}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Copy Updated URL
      </button>
      <button
        type="button"
        onClick={() => applyUrl(buildUrlWithParams(url, params))}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Open Updated URL
      </button>
    </div>
  );
};
export class ParamAnalyzerTool {
  static Component = ParamAnalyzerToolComponent;
}
