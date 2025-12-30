import React from 'react';
import {
  parseHeadersInput
} from './helpers';
import type {
  PayloadReplayData
} from './tool-types';

const PayloadReplayToolComponent = ({
  data,
  onChange,
  onSend
}: {
  data: PayloadReplayData | undefined;
  onChange: (next: PayloadReplayData) => void;
  onSend: (payload: {
    url: string;
    method: string;
    headers: { name: string; value: string }[];
    body: string;
  }) => Promise<void>;
}) => {
  const url = data?.url ?? '';
  const method = data?.method ?? 'GET';
  const headers = data?.headers ?? '';
  const body = data?.body ?? '';
  const update = (next: Partial<PayloadReplayData>) => onChange({ ...data, ...next });

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Payload Replay</div>
      <input
        type="text"
        value={url}
        onChange={(event) => update({ url: event.target.value })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="https://example.com/api"
      />
      <div className="flex gap-2">
        {['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].map((option) => (
          <button
            key={option}
            type="button"
            onClick={() => update({ method: option })}
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
        onChange={(event) => update({ headers: event.target.value })}
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Header: value"
      />
      <textarea
        value={body}
        onChange={(event) => update({ body: event.target.value })}
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Request body"
      />
      <button
        type="button"
        onClick={() =>
          onSend({
            url,
            method,
            headers: parseHeadersInput(headers),
            body
          })
        }
        disabled={!url}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Send Request
      </button>
      {data?.error ? (
        <div className="text-[11px] text-rose-300">{data.error}</div>
      ) : null}
      {typeof data?.responseStatus === 'number' ? (
        <div className="text-[11px] text-slate-500">
          Status: {data.responseStatus}
        </div>
      ) : null}
      {data?.responseHeaders?.length ? (
        <div className="space-y-1">
          {data.responseHeaders.map((header) => (
            <div key={`${header.name}-${header.value}`} className="text-[10px] text-slate-500">
              {header.name}: {header.value}
            </div>
          ))}
        </div>
      ) : null}
      {data?.responseBody ? (
        <textarea
          value={data.responseBody}
          readOnly
          rows={4}
          className="w-full rounded bg-slate-900 text-slate-200 text-xs px-2 py-2 border border-slate-800 focus:outline-none"
        />
      ) : null}
    </div>
  );
};
export class PayloadReplayTool {
  static Component = PayloadReplayToolComponent;
}
