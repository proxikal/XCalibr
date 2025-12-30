import React from 'react';
import {
  decodeJwt
} from './helpers';
import type {
  OAuthTokenInspectorData
} from './tool-types';

const OAuthTokenInspectorToolComponent = ({
  data,
  onChange
}: {
  data: OAuthTokenInspectorData | undefined;
  onChange: (next: OAuthTokenInspectorData) => void;
}) => {
  const token = data?.token ?? '';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handleInspect = () => {
    const result = decodeJwt(token);
    if (result.error) {
      onChange({ token, output: '', error: result.error });
      return;
    }
    const payload = result.payload ?? {};
    onChange({ token, output: JSON.stringify(payload, null, 2), error: '' });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">OAuth Token Inspector</div>
      <textarea
        value={token}
        onChange={(event) => onChange({ token: event.target.value, output, error })}
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder="Paste access token..."
      />
      {error ? <div className="text-[11px] text-rose-300">{error}</div> : null}
      <button
        type="button"
        onClick={handleInspect}
        disabled={!token.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Inspect Token
      </button>
      <textarea
        value={output}
        readOnly
        rows={4}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Token payload..."
      />
    </div>
  );
};
export class OAuthTokenInspectorTool {
  static Component = OAuthTokenInspectorToolComponent;
}
