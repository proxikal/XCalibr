import React from 'react';
import {
  safeParseJson
} from './helpers';
import type {
  GraphqlExplorerData
} from './tool-types';

const GraphqlExplorerToolComponent = ({
  data,
  onChange
}: {
  data: GraphqlExplorerData | undefined;
  onChange: (next: GraphqlExplorerData) => void;
}) => {
  const url = data?.url ?? '';
  const query = data?.query ?? '';
  const variables = data?.variables ?? '';
  const response = data?.response ?? '';
  const error = data?.error ?? '';

  const handleRun = async () => {
    const vars = variables.trim() ? safeParseJson(variables) : { value: {}, error: null };
    if (vars.error) {
      onChange({ url, query, variables, response: '', error: vars.error });
      return;
    }
    const result = await chrome.runtime.sendMessage({
      type: 'xcalibr-http-request',
      payload: {
        url,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query, variables: vars.value })
      }
    });
    if (result?.error) {
      onChange({ url, query, variables, response: '', error: result.error });
      return;
    }
    onChange({
      url,
      query,
      variables,
      response: result.body ?? '',
      error: ''
    });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">GraphQL Explorer</div>
      <input
        type="text"
        value={url}
        onChange={(event) => onChange({ url: event.target.value, query, variables, response, error })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="https://api.example.com/graphql"
      />
      <textarea
        value={query}
        onChange={(event) => onChange({ url, query: event.target.value, variables, response, error })}
        rows={4}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder="GraphQL query..."
      />
      <textarea
        value={variables}
        onChange={(event) => onChange({ url, query, variables: event.target.value, response, error })}
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder="Variables JSON..."
      />
      {error ? <div className="text-[11px] text-rose-300">{error}</div> : null}
      <button
        type="button"
        onClick={handleRun}
        disabled={!url.trim() || !query.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Run Query
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
export class GraphqlExplorerTool {
  static Component = GraphqlExplorerToolComponent;
}
