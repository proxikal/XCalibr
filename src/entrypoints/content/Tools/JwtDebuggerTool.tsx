import React from 'react';
import {
  decodeJwt
} from './helpers';
import type {
  JwtDebuggerData
} from './tool-types';

const JwtDebuggerToolComponent = ({
  data,
  onChange
}: {
  data: JwtDebuggerData | undefined;
  onChange: (next: JwtDebuggerData) => void;
}) => {
  const token = data?.token ?? '';
  const header = data?.header ?? '';
  const payload = data?.payload ?? '';
  const error = data?.error ?? '';

  const handleDecode = () => {
    const result = decodeJwt(token);
    if (result.error) {
      onChange({ token, header: '', payload: '', error: result.error });
      return;
    }
    onChange({
      token,
      header: JSON.stringify(result.header, null, 2),
      payload: JSON.stringify(result.payload, null, 2),
      error: ''
    });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">JWT Debugger</div>
      <textarea
        value={token}
        onChange={(event) => onChange({ token: event.target.value, header, payload, error })}
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Paste JWT..."
      />
      {error ? <div className="text-[11px] text-rose-300">{error}</div> : null}
      <button
        type="button"
        onClick={handleDecode}
        disabled={!token.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Decode Token
      </button>
      <textarea
        value={header}
        readOnly
        rows={3}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Header..."
      />
      <textarea
        value={payload}
        readOnly
        rows={4}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Payload..."
      />
    </div>
  );
};
export class JwtDebuggerTool {
  static Component = JwtDebuggerToolComponent;
}
