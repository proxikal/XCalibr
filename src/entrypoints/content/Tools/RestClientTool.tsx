import React from 'react';
import {
  parseHeadersInput
} from './helpers';
import type {
  RestClientData
} from './tool-types';

const RestClientToolComponent = ({
  data,
  onChange
}: {
  data: RestClientData | undefined;
  onChange: (next: RestClientData) => void;
}) => {
  const url = data?.url ?? '';
  const method = data?.method ?? 'GET';
  const headers = data?.headers ?? '';
  const body = data?.body ?? '';
  const response = data?.response ?? '';
  const error = data?.error ?? '';

  const handleSend = async () => {
    const headerEntries = parseHeadersInput(headers).reduce<Record<string, string>>((acc, entry) => {
      acc[entry.name] = entry.value;
      return acc;
    }, {});
    const result = await chrome.runtime.sendMessage({
      type: 'xcalibr-http-request',
      payload: { url, method, headers: headerEntries, body }
    });
    if (result?.error) {
      onChange({ url, method, headers, body, response: '', error: result.error });
      return;
    }
    onChange({
      url,
      method,
      headers,
      body,
      response: result.body ?? '',
      error: ''
    });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">REST Client</div>
      <input
        type="text"
        value={url}
        onChange={(event) => onChange({ url: event.target.value, method, headers, body, response, error })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="https://api.example.com"
      />
      <div className="flex gap-2">
        {['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((option) => (
          <button
            key={option}
            type="button"
            onClick={() => onChange({ url, method: option, headers, body, response, error })}
            className={`flex-1 rounded px-2 py-1 text-[11px] border transition-colors ${
              method === option
                ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
            }`}
          >
            {option}
          </button>
        ))}
      </div>
      <textarea
        value={headers}
        onChange={(event) => onChange({ url, method, headers: event.target.value, body, response, error })}
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder="Header: value"
      />
      <textarea
        value={body}
        onChange={(event) => onChange({ url, method, headers, body: event.target.value, response, error })}
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder="Request body"
      />
      {error ? <div className="text-[11px] text-rose-300">{error}</div> : null}
      <button
        type="button"
        onClick={handleSend}
        disabled={!url.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Send Request
      </button>
      <textarea
        value={response}
        readOnly
        rows={4}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Response..."
      />
    </div>
  );
};
export class RestClientTool {
  static Component = RestClientToolComponent;
}
