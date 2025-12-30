import React from 'react';
import type {
  ApiResponseViewerData
} from './tool-types';

const ApiResponseViewerToolComponent = ({
  data,
  onChange
}: {
  data: ApiResponseViewerData | undefined;
  onChange: (next: ApiResponseViewerData) => void;
}) => {
  const url = data?.url ?? '';
  const response = data?.response ?? '';
  const status = data?.status ?? '';
  const error = data?.error ?? '';

  const handleFetch = async () => {
    const result = await chrome.runtime.sendMessage({
      type: 'xcalibr-http-request',
      payload: { url, method: 'GET', headers: {} }
    });
    if (result?.error) {
      onChange({ url, response: '', status: '', error: result.error });
      return;
    }
    onChange({
      url,
      response: result.body ?? '',
      status: `${result.status} ${result.statusText ?? ''}`.trim(),
      error: ''
    });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">API Response Viewer</div>
      <input
        type="text"
        value={url}
        onChange={(event) => onChange({ url: event.target.value, response, status, error })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="https://api.example.com"
      />
      {error ? <div className="text-[11px] text-rose-300">{error}</div> : null}
      <button
        type="button"
        onClick={handleFetch}
        disabled={!url.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Fetch Response
      </button>
      {status ? <div className="text-[11px] text-slate-500">Status: {status}</div> : null}
      <textarea
        value={response}
        readOnly
        rows={5}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Response body..."
      />
    </div>
  );
};
export class ApiResponseViewerTool {
  static Component = ApiResponseViewerToolComponent;
}
