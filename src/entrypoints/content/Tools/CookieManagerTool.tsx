import React, { useState } from 'react';
import type {
  CookieManagerData
} from './tool-types';

const ITEMS_PER_PAGE = 8;

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
  const [page, setPage] = useState(0);
  const [editingCookie, setEditingCookie] = useState<string | null>(null);
  const [editValue, setEditValue] = useState('');

  const totalPages = Math.ceil(cookies.length / ITEMS_PER_PAGE);
  const paginatedCookies = cookies.slice(
    page * ITEMS_PER_PAGE,
    (page + 1) * ITEMS_PER_PAGE
  );

  const handleSet = () => {
    if (!name.trim()) return;
    document.cookie = `${name}=${encodeURIComponent(value)}; path=/`;
    onRefresh();
    onChange({ ...data, name: '', value: '' });
  };

  const handleDelete = (cookieName: string) => {
    document.cookie = `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
    onRefresh();
  };

  const handleStartEdit = (cookie: { name: string; value: string }) => {
    setEditingCookie(cookie.name);
    setEditValue(cookie.value);
  };

  const handleSaveEdit = (cookieName: string) => {
    document.cookie = `${cookieName}=${encodeURIComponent(editValue)}; path=/`;
    setEditingCookie(null);
    setEditValue('');
    onRefresh();
  };

  const handleExportJSON = () => {
    const exportData = cookies.map((c) => ({ name: c.name, value: c.value }));
    const json = JSON.stringify(exportData, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cookies-${window.location.hostname}-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Cookie Manager</div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={handleExportJSON}
            disabled={cookies.length === 0}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors disabled:opacity-50"
          >
            Export JSON
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

      <div className="text-[10px] text-slate-500 mb-2">
        {cookies.length} cookie{cookies.length !== 1 ? 's' : ''} on {window.location.hostname}
      </div>

      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
        <div className="text-[10px] text-slate-500 mb-2">Add / Update Cookie</div>
        <div className="flex gap-2 mb-2">
          <input
            type="text"
            value={name}
            onChange={(event) => onChange({ ...data, name: event.target.value })}
            className="flex-1 rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
            placeholder="Name"
          />
          <input
            type="text"
            value={value}
            onChange={(event) => onChange({ ...data, value: event.target.value })}
            className="flex-1 rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
            placeholder="Value"
          />
        </div>
        <button
          type="button"
          onClick={handleSet}
          disabled={!name.trim()}
          className="w-full rounded bg-blue-600/20 border border-blue-500/30 px-2 py-1 text-[11px] text-blue-300 hover:bg-blue-600/30 transition-colors disabled:opacity-50"
        >
          Set Cookie
        </button>
      </div>

      <div className="flex-1 overflow-y-auto space-y-2 min-h-0">
        {paginatedCookies.length === 0 ? (
          <div className="text-[11px] text-slate-500 text-center py-4">
            No cookies found.
          </div>
        ) : (
          paginatedCookies.map((cookie) => (
            <div
              key={cookie.name}
              className="rounded border border-slate-700 bg-slate-800/50 p-2"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex-1 min-w-0">
                  <div className="text-[11px] font-medium text-blue-300 break-all">
                    {cookie.name}
                  </div>
                  {editingCookie === cookie.name ? (
                    <div className="flex gap-1 mt-1">
                      <input
                        type="text"
                        value={editValue}
                        onChange={(e) => setEditValue(e.target.value)}
                        className="flex-1 rounded bg-slate-700 text-slate-200 text-[10px] px-1.5 py-0.5 border border-slate-600 focus:outline-none"
                        autoFocus
                      />
                      <button
                        type="button"
                        onClick={() => handleSaveEdit(cookie.name)}
                        className="text-[9px] text-emerald-400 hover:text-emerald-300"
                      >
                        Save
                      </button>
                      <button
                        type="button"
                        onClick={() => setEditingCookie(null)}
                        className="text-[9px] text-slate-400 hover:text-slate-300"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <div className="text-[10px] text-slate-400 mt-0.5 break-all line-clamp-2">
                      {cookie.value}
                    </div>
                  )}
                </div>
                {editingCookie !== cookie.name && (
                  <div className="flex gap-1 flex-shrink-0">
                    <button
                      type="button"
                      onClick={() => handleStartEdit(cookie)}
                      className="text-[9px] text-slate-500 hover:text-slate-300"
                      title="Edit"
                    >
                      ✎
                    </button>
                    <button
                      type="button"
                      onClick={() => navigator.clipboard.writeText(cookie.value)}
                      className="text-[9px] text-slate-500 hover:text-slate-300"
                      title="Copy value"
                    >
                      ⧉
                    </button>
                    <button
                      type="button"
                      onClick={() => handleDelete(cookie.name)}
                      className="text-[9px] text-slate-500 hover:text-rose-400"
                      title="Delete"
                    >
                      ×
                    </button>
                  </div>
                )}
              </div>
            </div>
          ))
        )}
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-3 pt-2 border-t border-slate-700">
          <button
            type="button"
            onClick={() => setPage(Math.max(0, page - 1))}
            disabled={page === 0}
            className="text-[10px] text-slate-400 hover:text-slate-200 disabled:opacity-30"
          >
            ← Prev
          </button>
          <span className="text-[10px] text-slate-500">
            {page + 1} / {totalPages}
          </span>
          <button
            type="button"
            onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
            disabled={page >= totalPages - 1}
            className="text-[10px] text-slate-400 hover:text-slate-200 disabled:opacity-30"
          >
            Next →
          </button>
        </div>
      )}
    </div>
  );
};
export class CookieManagerTool {
  static Component = CookieManagerToolComponent;
}
