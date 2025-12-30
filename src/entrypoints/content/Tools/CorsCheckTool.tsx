import React from 'react';
import type {
  CorsCheckData
} from './tool-types';

const CorsCheckToolComponent = ({
  data,
  onChange,
  onCheck
}: {
  data: CorsCheckData | undefined;
  onChange: (next: CorsCheckData) => void;
  onCheck: (url: string) => Promise<void>;
}) => {
  const url = data?.url ?? '';
  const result = data?.result;
  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">CORS Check</div>
      <input
        type="text"
        value={url}
        onChange={(event) => onChange({ ...data, url: event.target.value })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="https://example.com"
      />
      <button
        type="button"
        onClick={() => onCheck(url)}
        disabled={!url}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Run Check
      </button>
      {data?.error ? (
        <div className="text-[11px] text-rose-300">{data.error}</div>
      ) : null}
      {result ? (
        <div className="space-y-2 text-[11px] text-slate-400">
          <div>Status: {result.status ?? 'Unknown'}</div>
          <div>ACAO: {result.acao ?? 'None'}</div>
          <div>ACAC: {result.acc ?? 'None'}</div>
          <div>Allow-Methods: {result.methods ?? 'None'}</div>
          <div>Allow-Headers: {result.headers ?? 'None'}</div>
        </div>
      ) : null}
    </div>
  );
};
export class CorsCheckTool {
  static Component = CorsCheckToolComponent;
}
