import React from 'react';
import type {
  WebhookTesterData
} from './tool-types';

const WebhookTesterToolComponent = ({
  data,
  onChange
}: {
  data: WebhookTesterData | undefined;
  onChange: (next: WebhookTesterData) => void;
}) => {
  const url = data?.url ?? '';
  const body = data?.body ?? '';
  const response = data?.response ?? '';
  const error = data?.error ?? '';

  const handleSend = async () => {
    const result = await chrome.runtime.sendMessage({
      type: 'xcalibr-http-request',
      payload: {
        url,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body
      }
    });
    if (result?.error) {
      onChange({ url, body, response: '', error: result.error });
      return;
    }
    onChange({ url, body, response: result.body ?? '', error: '' });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Webhook Tester</div>
      <input
        type="text"
        value={url}
        onChange={(event) => onChange({ url: event.target.value, body, response, error })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="https://webhook.site/..."
      />
      <textarea
        value={body}
        onChange={(event) => onChange({ url, body: event.target.value, response, error })}
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder='{"event":"ping"}'
      />
      {error ? <div className="text-[11px] text-rose-300">{error}</div> : null}
      <button
        type="button"
        onClick={handleSend}
        disabled={!url.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Send Webhook
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
export class WebhookTesterTool {
  static Component = WebhookTesterToolComponent;
}
