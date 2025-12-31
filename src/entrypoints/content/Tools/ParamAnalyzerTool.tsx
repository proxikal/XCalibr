import React from 'react';
import {
  buildUrlWithParams
} from './helpers';
import type {
  ParamAnalyzerData,
  ParamEntry,
  ParamTypeHint
} from './tool-types';

const FUZZ_PRESETS: { label: string; payloads: string[] }[] = [
  { label: 'XSS', payloads: ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "'-alert(1)-'"] },
  { label: 'SQLi', payloads: ["' OR '1'='1", "1' AND '1'='1", "'; DROP TABLE users;--"] },
  { label: 'Path', payloads: ['../../../etc/passwd', '....//....//....//etc/passwd', '/etc/passwd'] },
  { label: 'IDOR', payloads: ['1', '0', '-1', '9999999', 'admin'] },
  { label: 'Null', payloads: ['null', 'undefined', 'NaN', '', '0'] },
];

const TYPE_HINTS: { type: ParamTypeHint; label: string; color: string }[] = [
  { type: 'int', label: 'INT', color: 'text-blue-300 bg-blue-500/20' },
  { type: 'uuid', label: 'UUID', color: 'text-purple-300 bg-purple-500/20' },
  { type: 'bool', label: 'BOOL', color: 'text-amber-300 bg-amber-500/20' },
  { type: 'email', label: 'EMAIL', color: 'text-emerald-300 bg-emerald-500/20' },
  { type: 'date', label: 'DATE', color: 'text-cyan-300 bg-cyan-500/20' },
  { type: 'json', label: 'JSON', color: 'text-rose-300 bg-rose-500/20' },
  { type: 'base64', label: 'B64', color: 'text-orange-300 bg-orange-500/20' },
  { type: 'string', label: 'STR', color: 'text-slate-300 bg-slate-500/20' },
];

const detectType = (value: string): ParamTypeHint => {
  if (value === '') return 'unknown';
  if (value === 'true' || value === 'false' || value === '1' || value === '0') return 'bool';
  if (/^-?\d+$/.test(value)) return 'int';
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return 'uuid';
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return 'email';
  if (/^\d{4}-\d{2}-\d{2}/.test(value) || /^\d{2}\/\d{2}\/\d{4}/.test(value)) return 'date';
  if (/^[A-Za-z0-9+/]+=*$/.test(value) && value.length > 8 && value.length % 4 === 0) {
    try {
      atob(value);
      return 'base64';
    } catch { /* not base64 */ }
  }
  try {
    JSON.parse(value);
    return 'json';
  } catch { /* not json */ }
  return 'string';
};

const decodeValue = (value: string): string => {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
};

const encodeValue = (value: string): string => {
  try {
    return encodeURIComponent(value);
  } catch {
    return value;
  }
};

const parseImportText = (text: string): ParamEntry[] => {
  const params: ParamEntry[] = [];
  const lines = text.trim().split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Try key=value format
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex > 0) {
      const key = trimmed.slice(0, eqIndex);
      const value = trimmed.slice(eqIndex + 1);
      const decodedValue = decodeValue(value);
      params.push({
        key,
        value,
        decodedValue,
        typeHint: detectType(decodedValue)
      });
    } else if (trimmed.startsWith('?') || trimmed.includes('&')) {
      // URL query string format
      const queryString = trimmed.startsWith('?') ? trimmed.slice(1) : trimmed;
      const pairs = queryString.split('&');
      for (const pair of pairs) {
        const idx = pair.indexOf('=');
        if (idx > 0) {
          const key = pair.slice(0, idx);
          const value = pair.slice(idx + 1);
          const decodedValue = decodeValue(value);
          params.push({
            key,
            value,
            decodedValue,
            typeHint: detectType(decodedValue)
          });
        }
      }
    }
  }

  return params;
};

const exportParams = (params: ParamEntry[], format: 'query' | 'lines' | 'json'): string => {
  switch (format) {
    case 'query':
      return params.map(p => `${encodeValue(p.key)}=${encodeValue(p.value)}`).join('&');
    case 'lines':
      return params.map(p => `${p.key}=${p.value}`).join('\n');
    case 'json':
      return JSON.stringify(
        params.reduce((acc, p) => ({ ...acc, [p.key]: p.decodedValue ?? p.value }), {}),
        null,
        2
      );
    default:
      return '';
  }
};

const ParamAnalyzerToolComponent = ({
  data,
  onChange,
  onRefresh
}: {
  data: ParamAnalyzerData | undefined;
  onChange: (next: ParamAnalyzerData) => void;
  onRefresh: () => Promise<void>;
}) => {
  const params = data?.params ?? [];
  const url = data?.url ?? window.location.href;
  const showDecoded = data?.showDecoded ?? true;
  const splitView = data?.splitView ?? false;
  const activeTab = data?.activeTab ?? 'params';
  const importText = data?.importText ?? '';

  const updateParams = (nextParams: ParamEntry[]) =>
    onChange({ ...data, url, params: nextParams });

  const applyUrl = (nextUrl: string) => {
    navigator.clipboard.writeText(nextUrl);
    window.location.href = nextUrl;
  };

  const addParam = () => {
    const newParam: ParamEntry = { key: '', value: '', decodedValue: '', typeHint: 'unknown' };
    updateParams([...params, newParam]);
  };

  const updateParamKey = (index: number, key: string) => {
    const next = [...params];
    next[index] = { ...next[index], key };
    updateParams(next);
  };

  const updateParamValue = (index: number, value: string, isDecoded: boolean) => {
    const next = [...params];
    if (isDecoded) {
      const encoded = encodeValue(value);
      next[index] = {
        ...next[index],
        value: encoded,
        decodedValue: value,
        typeHint: detectType(value)
      };
    } else {
      const decoded = decodeValue(value);
      next[index] = {
        ...next[index],
        value,
        decodedValue: decoded,
        typeHint: detectType(decoded)
      };
    }
    updateParams(next);
  };

  const deleteParam = (index: number) => {
    updateParams(params.filter((_, i) => i !== index));
  };

  const applyFuzzPayload = (payload: string) => {
    const next = params.map(p => ({
      ...p,
      value: payload,
      decodedValue: payload,
      typeHint: detectType(payload)
    }));
    updateParams(next);
  };

  const importParams = () => {
    const imported = parseImportText(importText);
    if (imported.length > 0) {
      updateParams([...params, ...imported]);
      onChange({ ...data, url, params: [...params, ...imported], importText: '', activeTab: 'params' });
    }
  };

  const previewUrl = buildUrlWithParams(url, params.map(p => ({ key: p.key, value: p.value })));

  const getTypeHintInfo = (hint: ParamTypeHint) =>
    TYPE_HINTS.find(t => t.type === hint) ?? { label: '?', color: 'text-slate-400 bg-slate-700' };

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs text-slate-200">Param Analyzer</div>
          <div className="text-[10px] text-slate-500 truncate max-w-[200px]" title={url}>
            {url}
          </div>
        </div>
        <div className="flex gap-1">
          <button
            type="button"
            onClick={() => onChange({ ...data, splitView: !splitView })}
            className={`rounded px-2 py-1 text-[10px] border transition-colors ${
              splitView
                ? 'bg-blue-500/20 border-blue-500/50 text-blue-300'
                : 'bg-slate-800 border-slate-700 text-slate-400'
            }`}
          >
            Split
          </button>
          <button
            type="button"
            onClick={onRefresh}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1">
        {(['params', 'import', 'fuzz'] as const).map(tab => (
          <button
            key={tab}
            type="button"
            onClick={() => onChange({ ...data, activeTab: tab })}
            className={`flex-1 rounded px-2 py-1 text-[10px] border transition-colors ${
              activeTab === tab
                ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-300'
                : 'bg-slate-800 border-slate-700 text-slate-400'
            }`}
          >
            {tab === 'params' ? 'Params' : tab === 'import' ? 'Import' : 'Fuzz'}
          </button>
        ))}
      </div>

      {/* Params Tab */}
      {activeTab === 'params' && (
        <>
          {/* Decoded/Encoded Toggle */}
          <div className="flex gap-1">
            <button
              type="button"
              onClick={() => onChange({ ...data, showDecoded: true })}
              className={`flex-1 rounded px-2 py-1 text-[10px] border transition-colors ${
                showDecoded
                  ? 'bg-amber-500/20 border-amber-500/50 text-amber-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400'
              }`}
            >
              Decoded
            </button>
            <button
              type="button"
              onClick={() => onChange({ ...data, showDecoded: false })}
              className={`flex-1 rounded px-2 py-1 text-[10px] border transition-colors ${
                !showDecoded
                  ? 'bg-amber-500/20 border-amber-500/50 text-amber-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400'
              }`}
            >
              Encoded
            </button>
          </div>

          {/* Split View or Regular View */}
          <div className={splitView ? 'grid grid-cols-2 gap-2' : ''}>
            {/* Params List */}
            <div className="space-y-2">
              {params.length === 0 ? (
                <div className="text-[11px] text-slate-500">
                  No query parameters detected.
                </div>
              ) : null}

              {params.map((param, index) => {
                const typeInfo = getTypeHintInfo(param.typeHint ?? 'unknown');
                const displayValue = showDecoded ? (param.decodedValue ?? param.value) : param.value;

                return (
                  <div key={`${param.key}-${index}`} className="flex gap-1 items-center">
                    <span
                      className={`rounded px-1 py-0.5 text-[8px] font-mono ${typeInfo.color}`}
                      title={`Type: ${param.typeHint ?? 'unknown'}`}
                    >
                      {typeInfo.label}
                    </span>
                    <input
                      type="text"
                      value={param.key}
                      onChange={(event) => updateParamKey(index, event.target.value)}
                      className="w-1/4 rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
                      placeholder="Key"
                    />
                    <input
                      type="text"
                      value={displayValue}
                      onChange={(event) => updateParamValue(index, event.target.value, showDecoded)}
                      className="flex-1 rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
                      placeholder="Value"
                    />
                    <button
                      type="button"
                      onClick={() => deleteParam(index)}
                      className="rounded bg-slate-800 px-2 text-[11px] text-slate-400 hover:text-slate-200"
                    >
                      x
                    </button>
                  </div>
                );
              })}
            </div>

            {/* URL Preview (in split view) */}
            {splitView && (
              <div className="rounded bg-slate-900 p-2 border border-slate-800">
                <div className="text-[10px] text-slate-500 mb-1">Preview URL:</div>
                <div className="text-[10px] font-mono text-emerald-300 break-all">
                  {previewUrl}
                </div>
              </div>
            )}
          </div>

          <button
            type="button"
            onClick={addParam}
            className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
          >
            Add Param
          </button>
        </>
      )}

      {/* Import Tab */}
      {activeTab === 'import' && (
        <div className="space-y-2">
          <div className="text-[10px] text-slate-400">
            Paste params (key=value per line, or query string, or JSON)
          </div>
          <textarea
            value={importText}
            onChange={(e) => onChange({ ...data, importText: e.target.value })}
            rows={4}
            className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500"
            placeholder="foo=bar&#10;baz=qux&#10;or ?foo=bar&baz=qux"
          />
          <button
            type="button"
            onClick={importParams}
            disabled={!importText.trim()}
            className="w-full rounded bg-emerald-600 px-2 py-1.5 text-xs text-white hover:bg-emerald-500 transition-colors disabled:opacity-50"
          >
            Import Params
          </button>
        </div>
      )}

      {/* Fuzz Tab */}
      {activeTab === 'fuzz' && (
        <div className="space-y-2">
          <div className="text-[10px] text-slate-400">
            Apply fuzz payloads to all param values:
          </div>
          <div className="grid grid-cols-2 gap-1">
            {FUZZ_PRESETS.map((preset) => (
              <div key={preset.label} className="space-y-1">
                <div className="text-[9px] text-slate-500 font-semibold">{preset.label}</div>
                {preset.payloads.map((payload, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => applyFuzzPayload(payload)}
                    className="w-full text-left rounded bg-slate-800 px-2 py-1 text-[9px] text-slate-300 hover:bg-slate-700 transition-colors truncate border border-slate-700"
                    title={payload}
                  >
                    {payload.length > 20 ? payload.slice(0, 20) + '...' : payload}
                  </button>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Export buttons */}
      {activeTab === 'params' && params.length > 0 && (
        <div className="flex gap-1">
          <button
            type="button"
            onClick={() => navigator.clipboard.writeText(exportParams(params, 'query'))}
            className="flex-1 rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Copy Query
          </button>
          <button
            type="button"
            onClick={() => navigator.clipboard.writeText(exportParams(params, 'json'))}
            className="flex-1 rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Copy JSON
          </button>
        </div>
      )}

      {/* Action buttons */}
      {activeTab === 'params' && (
        <>
          <button
            type="button"
            onClick={() => navigator.clipboard.writeText(previewUrl)}
            className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
          >
            Copy Updated URL
          </button>
          <button
            type="button"
            onClick={() => applyUrl(previewUrl)}
            className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
          >
            Open Updated URL
          </button>
        </>
      )}
    </div>
  );
};

export class ParamAnalyzerTool {
  static Component = ParamAnalyzerToolComponent;
}
