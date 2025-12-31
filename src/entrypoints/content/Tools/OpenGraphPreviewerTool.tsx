import React from 'react';
import type { OpenGraphPreviewerData } from './tool-types';

type Props = {
  data: OpenGraphPreviewerData | undefined;
  onChange: (next: OpenGraphPreviewerData) => void;
};

const OpenGraphPreviewerToolComponent = ({ data, onChange }: Props) => {
  const title = data?.title ?? '';
  const description = data?.description ?? '';
  const imageUrl = data?.imageUrl ?? '';
  const siteName = data?.siteName ?? '';
  const url = data?.url ?? '';
  const platform = data?.platform ?? 'facebook';

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Open Graph Preview</div>

      <div className="flex gap-1">
        {(['facebook', 'twitter', 'linkedin'] as const).map((p) => (
          <button
            key={p}
            type="button"
            onClick={() => onChange({ ...data, platform: p })}
            className={`px-3 py-1 text-[10px] rounded ${
              platform === p
                ? 'bg-emerald-600 text-white'
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
            }`}
          >
            {p === 'facebook' ? 'Facebook' : p === 'twitter' ? 'Twitter' : 'LinkedIn'}
          </button>
        ))}
      </div>

      <div className="space-y-2">
        <div className="space-y-1">
          <div className="text-[10px] text-slate-400">Title (og:title)</div>
          <input
            type="text"
            value={title}
            onChange={(e) => onChange({ ...data, title: e.target.value })}
            className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-emerald-500"
            placeholder="Page Title"
          />
        </div>

        <div className="space-y-1">
          <div className="text-[10px] text-slate-400">Description (og:description)</div>
          <textarea
            value={description}
            onChange={(e) => onChange({ ...data, description: e.target.value })}
            rows={2}
            className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-emerald-500"
            placeholder="Page description"
          />
        </div>

        <div className="grid grid-cols-2 gap-2">
          <div className="space-y-1">
            <div className="text-[10px] text-slate-400">Site Name</div>
            <input
              type="text"
              value={siteName}
              onChange={(e) => onChange({ ...data, siteName: e.target.value })}
              className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-emerald-500"
              placeholder="My Website"
            />
          </div>
          <div className="space-y-1">
            <div className="text-[10px] text-slate-400">URL</div>
            <input
              type="text"
              value={url}
              onChange={(e) => onChange({ ...data, url: e.target.value })}
              className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-emerald-500"
              placeholder="https://example.com"
            />
          </div>
        </div>

        <div className="space-y-1">
          <div className="text-[10px] text-slate-400">Image URL (og:image)</div>
          <input
            type="text"
            value={imageUrl}
            onChange={(e) => onChange({ ...data, imageUrl: e.target.value })}
            className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-emerald-500"
            placeholder="https://example.com/image.jpg"
          />
        </div>
      </div>

      <div className="text-[10px] text-slate-400 mb-1">Preview ({platform})</div>
      <div className="bg-slate-900 border border-slate-700 rounded overflow-hidden">
        {imageUrl && (
          <div className="h-32 bg-slate-800 flex items-center justify-center text-slate-500 text-[10px]">
            [Image: {imageUrl.slice(0, 40)}...]
          </div>
        )}
        <div className="p-3">
          {siteName && <div className="text-[10px] text-slate-500 uppercase">{siteName}</div>}
          <div className="text-[12px] text-slate-200 font-medium">{title || 'Page Title'}</div>
          <div className="text-[10px] text-slate-400 line-clamp-2">{description || 'Page description will appear here...'}</div>
          {url && <div className="text-[10px] text-slate-500 mt-1">{url}</div>}
        </div>
      </div>

      <div className="text-[10px] text-slate-500">
        Preview how your page appears when shared on social media.
      </div>
    </div>
  );
};

export class OpenGraphPreviewerTool {
  static Component = OpenGraphPreviewerToolComponent;
}
