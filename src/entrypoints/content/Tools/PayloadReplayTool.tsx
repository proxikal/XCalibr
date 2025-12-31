import React, { useState, useMemo } from 'react';
import {
  parseHeadersInput
} from './helpers';
import type {
  PayloadReplayData
} from './tool-types';

type ResponseViewMode = 'raw' | 'json' | 'headers';

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
};

const getStatusColor = (status: number): string => {
  if (status >= 200 && status < 300) return 'text-emerald-400';
  if (status >= 300 && status < 400) return 'text-amber-400';
  if (status >= 400) return 'text-red-400';
  return 'text-slate-400';
};

const JsonTreeView = ({ data, depth = 0 }: { data: unknown; depth?: number }) => {
  const [expanded, setExpanded] = useState(depth < 2);

  if (data === null) {
    return <span className="text-slate-500">null</span>;
  }

  if (typeof data === 'undefined') {
    return <span className="text-slate-500">undefined</span>;
  }

  if (typeof data === 'boolean') {
    return <span className="text-amber-400">{data ? 'true' : 'false'}</span>;
  }

  if (typeof data === 'number') {
    return <span className="text-blue-400">{data}</span>;
  }

  if (typeof data === 'string') {
    return <span className="text-emerald-400">"{data}"</span>;
  }

  if (Array.isArray(data)) {
    if (data.length === 0) {
      return <span className="text-slate-400">[]</span>;
    }
    return (
      <div className="pl-3">
        <button
          type="button"
          onClick={() => setExpanded(!expanded)}
          className="text-slate-500 hover:text-slate-300"
        >
          {expanded ? '▼' : '▶'} [{data.length}]
        </button>
        {expanded && (
          <div className="pl-3 border-l border-slate-700">
            {data.map((item, idx) => (
              <div key={idx} className="flex gap-1">
                <span className="text-slate-500 select-none">{idx}:</span>
                <JsonTreeView data={item} depth={depth + 1} />
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  if (typeof data === 'object') {
    const entries = Object.entries(data);
    if (entries.length === 0) {
      return <span className="text-slate-400">{'{}'}</span>;
    }
    return (
      <div className="pl-3">
        <button
          type="button"
          onClick={() => setExpanded(!expanded)}
          className="text-slate-500 hover:text-slate-300"
        >
          {expanded ? '▼' : '▶'} {'{'}...{'}'}
        </button>
        {expanded && (
          <div className="pl-3 border-l border-slate-700">
            {entries.map(([key, value]) => (
              <div key={key} className="flex gap-1">
                <span className="text-purple-400 select-none">"{key}":</span>
                <JsonTreeView data={value} depth={depth + 1} />
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  return <span className="text-slate-400">{String(data)}</span>;
};

const RawRequestPreview = ({
  method,
  url,
  headers,
  body
}: {
  method: string;
  url: string;
  headers: string;
  body: string;
}) => {
  let urlPath = url;
  let host = '';
  try {
    const parsed = new URL(url);
    urlPath = parsed.pathname + parsed.search;
    host = parsed.host;
  } catch {
    // Invalid URL
  }

  const rawRequest = [
    `${method} ${urlPath} HTTP/1.1`,
    host && `Host: ${host}`,
    headers.trim(),
    '',
    body
  ].filter(Boolean).join('\n');

  return (
    <pre className="text-[10px] text-slate-300 bg-slate-900 p-2 rounded border border-slate-800 overflow-x-auto whitespace-pre-wrap font-mono">
      {rawRequest}
    </pre>
  );
};

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
    includeCredentials: boolean;
    followRedirects: boolean;
  }) => Promise<void>;
}) => {
  const [isLoading, setIsLoading] = useState(false);

  const url = data?.url ?? '';
  const method = data?.method ?? 'GET';
  const headers = data?.headers ?? '';
  const body = data?.body ?? '';
  const includeCredentials = data?.includeCredentials ?? false;
  const followRedirects = data?.followRedirects ?? true;
  const showRawRequest = data?.showRawRequest ?? false;
  const responseViewMode = (data?.responseViewMode ?? 'raw') as ResponseViewMode;

  const update = (next: Partial<PayloadReplayData>) => onChange({ ...data, ...next });

  const handleSend = async () => {
    setIsLoading(true);
    try {
      await onSend({
        url,
        method,
        headers: parseHeadersInput(headers),
        body,
        includeCredentials,
        followRedirects
      });
    } finally {
      setIsLoading(false);
    }
  };

  // Parse response body as JSON if possible
  const parsedJson = useMemo(() => {
    if (!data?.responseBody) return null;
    try {
      return JSON.parse(data.responseBody);
    } catch {
      return null;
    }
  }, [data?.responseBody]);

  const isJsonResponse = parsedJson !== null;

  return (
    <div className="flex flex-col h-full space-y-3 overflow-y-auto">
      <div className="text-xs text-slate-200">Payload Replay</div>

      {/* URL Input */}
      <input
        type="text"
        value={url}
        onChange={(event) => update({ url: event.target.value })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="https://example.com/api"
      />

      {/* Method Selection */}
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

      {/* Session Options */}
      <div className="space-y-1">
        <div className="text-[9px] uppercase tracking-widest text-slate-500">Session</div>
        <div className="flex flex-wrap gap-3">
          <label className="flex items-center gap-2 text-[10px] text-slate-400 cursor-pointer">
            <input
              type="checkbox"
              checked={includeCredentials}
              onChange={(e) => update({ includeCredentials: e.target.checked })}
              className="rounded border-slate-700 bg-slate-800"
            />
            Include cookies/credentials
          </label>
          <label className="flex items-center gap-2 text-[10px] text-slate-400 cursor-pointer">
            <input
              type="checkbox"
              checked={followRedirects}
              onChange={(e) => update({ followRedirects: e.target.checked })}
              className="rounded border-slate-700 bg-slate-800"
            />
            Follow redirects
          </label>
        </div>
      </div>

      {/* Headers */}
      <div className="space-y-1">
        <div className="text-[9px] uppercase tracking-widest text-slate-500">Headers</div>
        <textarea
          value={headers}
          onChange={(event) => update({ headers: event.target.value })}
          rows={3}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
          placeholder="Header: value"
        />
      </div>

      {/* Body */}
      <div className="space-y-1">
        <div className="text-[9px] uppercase tracking-widest text-slate-500">Body</div>
        <textarea
          value={body}
          onChange={(event) => update({ body: event.target.value })}
          rows={3}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
          placeholder="Request body"
        />
      </div>

      {/* Raw Request Preview Toggle */}
      <div className="space-y-1">
        <label className="flex items-center gap-2 text-[10px] text-slate-400 cursor-pointer">
          <input
            type="checkbox"
            checked={showRawRequest}
            onChange={(e) => update({ showRawRequest: e.target.checked })}
            className="rounded border-slate-700 bg-slate-800"
          />
          Show raw request preview
        </label>
        {showRawRequest && (
          <RawRequestPreview
            method={method}
            url={url}
            headers={headers}
            body={body}
          />
        )}
      </div>

      {/* Send Button */}
      <button
        type="button"
        onClick={handleSend}
        disabled={!url || isLoading}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        {isLoading ? 'Sending...' : 'Send Request'}
      </button>

      {/* Error */}
      {data?.error && (
        <div className="text-[11px] text-rose-300 bg-rose-500/10 px-2 py-1.5 rounded border border-rose-500/30">
          {data.error}
        </div>
      )}

      {/* Response Section */}
      {typeof data?.responseStatus === 'number' && (
        <div className="space-y-2 border-t border-slate-700 pt-3">
          <div className="text-[9px] uppercase tracking-widest text-slate-500">Response</div>

          {/* Status & Metrics */}
          <div className="flex flex-wrap gap-3 text-[10px]">
            <div>
              <span className="text-slate-500">Status: </span>
              <span className={getStatusColor(data.responseStatus)}>{data.responseStatus}</span>
            </div>
            {data.latencyMs !== undefined && (
              <div>
                <span className="text-slate-500">Latency: </span>
                <span className="text-slate-300">{data.latencyMs.toFixed(0)}ms</span>
              </div>
            )}
            {data.requestSize !== undefined && (
              <div>
                <span className="text-slate-500">Req Size: </span>
                <span className="text-slate-300">{formatBytes(data.requestSize)}</span>
              </div>
            )}
            {data.responseSize !== undefined && (
              <div>
                <span className="text-slate-500">Res Size: </span>
                <span className="text-slate-300">{formatBytes(data.responseSize)}</span>
              </div>
            )}
          </div>

          {/* Redirect Info */}
          {data.redirectCount !== undefined && data.redirectCount > 0 && (
            <div className="text-[10px] bg-amber-500/10 border border-amber-500/30 rounded px-2 py-1">
              <span className="text-amber-400">Redirected {data.redirectCount}x</span>
              {data.finalUrl && (
                <span className="text-slate-400 ml-2 truncate block" title={data.finalUrl}>
                  Final: {data.finalUrl}
                </span>
              )}
            </div>
          )}

          {/* Response View Mode Toggle */}
          <div className="flex gap-1">
            {(['raw', 'json', 'headers'] as const).map((mode) => (
              <button
                key={mode}
                type="button"
                onClick={() => update({ responseViewMode: mode })}
                disabled={mode === 'json' && !isJsonResponse}
                className={`rounded px-2 py-1 text-[10px] border transition-colors disabled:opacity-30 ${
                  responseViewMode === mode
                    ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                    : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                }`}
              >
                {mode === 'raw' ? 'Raw' : mode === 'json' ? 'JSON Tree' : 'Headers'}
              </button>
            ))}
          </div>

          {/* Headers View */}
          {responseViewMode === 'headers' && data.responseHeaders?.length ? (
            <div className="bg-slate-900 rounded border border-slate-800 p-2 max-h-48 overflow-y-auto">
              {data.responseHeaders.map((header, idx) => (
                <div key={`${header.name}-${idx}`} className="text-[10px] flex gap-2">
                  <span className="text-purple-400 shrink-0">{header.name}:</span>
                  <span className="text-slate-300 break-all">{header.value}</span>
                </div>
              ))}
            </div>
          ) : null}

          {/* JSON Tree View */}
          {responseViewMode === 'json' && isJsonResponse && (
            <div className="bg-slate-900 rounded border border-slate-800 p-2 max-h-64 overflow-y-auto text-[10px] font-mono">
              <JsonTreeView data={parsedJson} />
            </div>
          )}

          {/* Raw Response Body */}
          {responseViewMode === 'raw' && data.responseBody && (
            <textarea
              value={data.responseBody}
              readOnly
              rows={6}
              className="w-full rounded bg-slate-900 text-slate-200 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
            />
          )}
        </div>
      )}
    </div>
  );
};

export class PayloadReplayTool {
  static Component = PayloadReplayToolComponent;
}
