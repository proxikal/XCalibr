import React from 'react';
import type {
  CouchDbDocExplorerData
} from './tool-types';

const CouchDbDocExplorerToolComponent = ({
  data,
  onChange
}: {
  data: CouchDbDocExplorerData | undefined;
  onChange: (next: CouchDbDocExplorerData) => void;
}) => {
  const url = data?.url ?? '';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handleFetch = async () => {
    const result = await chrome.runtime.sendMessage({
      type: 'xcalibr-couchdb-fetch',
      payload: { url }
    });
    onChange({
      url,
      output: result?.output ?? '',
      error: result?.error ?? ''
    });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">CouchDB Doc Explorer</div>
      <input
        type="text"
        value={url}
        onChange={(event) => onChange({ url: event.target.value, output, error })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="https://db.example.com/mydb/docid"
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <button
        type="button"
        onClick={handleFetch}
        disabled={!url.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Fetch Doc
      </button>
      <textarea
        value={output}
        readOnly
        rows={6}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Document output..."
      />
    </div>
  );
};
export class CouchDbDocExplorerTool {
  static Component = CouchDbDocExplorerToolComponent;
}
