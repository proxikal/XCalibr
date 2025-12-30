import React from 'react';
import type {
  CookieManagerData
} from './tool-types';

const CookieManagerToolComponent = ({
  data,
  onChange,
  onRefresh
}: {
  data: CookieManagerData | undefined;
  onChange: (next: CookieManagerData) => void;
  onRefresh: () => void;
}) => {
  const name = data?.name ?? '';
  const value = data?.value ?? '';
  const cookies = data?.cookies ?? [];

  const handleSet = () => {
    if (!name.trim()) return;
    document.cookie = `${name}=${value}; path=/`;
    onRefresh();
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">Cookie Manager</div>
        <button
          type="button"
          onClick={onRefresh}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Refresh
        </button>
      </div>
      <div className="flex gap-2">
        <input
          type="text"
          value={name}
          onChange={(event) => onChange({ name: event.target.value, value, cookies })}
          className="w-1/2 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
          placeholder="Cookie name"
        />
        <input
          type="text"
          value={value}
          onChange={(event) => onChange({ name, value: event.target.value, cookies })}
          className="w-1/2 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
          placeholder="Value"
        />
      </div>
      <button
        type="button"
        onClick={handleSet}
        disabled={!name.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Set Cookie
      </button>
      <div className="max-h-32 overflow-y-auto no-scrollbar text-[11px] text-slate-300 space-y-1">
        {cookies.length === 0 ? 'No cookies.' : null}
        {cookies.map((cookie) => (
          <div key={cookie.name} className="break-words">
            {cookie.name}: {cookie.value}
          </div>
        ))}
      </div>
    </div>
  );
};
export class CookieManagerTool {
  static Component = CookieManagerToolComponent;
}
