import React, { useMemo, useState } from 'react';
import type { MetaTagGeneratorData } from './tool-types';

type Props = {
  data: MetaTagGeneratorData | undefined;
  onChange: (next: MetaTagGeneratorData) => void;
};

const MetaTagGeneratorToolComponent = ({ data, onChange }: Props) => {
  const title = data?.title ?? '';
  const description = data?.description ?? '';
  const keywords = data?.keywords ?? '';
  const author = data?.author ?? '';
  const viewport = data?.viewport ?? true;
  const robots = data?.robots ?? 'index, follow';
  const [copied, setCopied] = useState(false);

  const output = useMemo(() => {
    const tags: string[] = [];

    if (title) {
      tags.push(`<title>${title}</title>`);
    }

    if (description) {
      tags.push(`<meta name="description" content="${description}" />`);
    }

    if (keywords) {
      tags.push(`<meta name="keywords" content="${keywords}" />`);
    }

    if (author) {
      tags.push(`<meta name="author" content="${author}" />`);
    }

    if (viewport) {
      tags.push('<meta name="viewport" content="width=device-width, initial-scale=1.0" />');
    }

    if (robots) {
      tags.push(`<meta name="robots" content="${robots}" />`);
    }

    tags.push('<meta charset="UTF-8" />');

    return tags.join('\n');
  }, [title, description, keywords, author, viewport, robots]);

  const handleCopy = () => {
    navigator.clipboard.writeText(output);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Meta Tag Generator</div>

      <div className="space-y-2">
        <div className="space-y-1">
          <div className="text-[10px] text-slate-400">Title</div>
          <input
            type="text"
            value={title}
            onChange={(e) => onChange({ ...data, title: e.target.value })}
            className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-emerald-500"
            placeholder="Page Title"
          />
        </div>

        <div className="space-y-1">
          <div className="text-[10px] text-slate-400">Description</div>
          <textarea
            value={description}
            onChange={(e) => onChange({ ...data, description: e.target.value })}
            rows={2}
            className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-emerald-500"
            placeholder="Page description for SEO"
          />
        </div>

        <div className="space-y-1">
          <div className="text-[10px] text-slate-400">Keywords</div>
          <input
            type="text"
            value={keywords}
            onChange={(e) => onChange({ ...data, keywords: e.target.value })}
            className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-emerald-500"
            placeholder="keyword1, keyword2, keyword3"
          />
        </div>

        <div className="grid grid-cols-2 gap-2">
          <div className="space-y-1">
            <div className="text-[10px] text-slate-400">Author</div>
            <input
              type="text"
              value={author}
              onChange={(e) => onChange({ ...data, author: e.target.value })}
              className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-emerald-500"
              placeholder="Author name"
            />
          </div>
          <div className="space-y-1">
            <div className="text-[10px] text-slate-400">Robots</div>
            <select
              value={robots}
              onChange={(e) => onChange({ ...data, robots: e.target.value })}
              className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-emerald-500"
            >
              <option value="index, follow">index, follow</option>
              <option value="noindex, follow">noindex, follow</option>
              <option value="index, nofollow">index, nofollow</option>
              <option value="noindex, nofollow">noindex, nofollow</option>
            </select>
          </div>
        </div>

        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={viewport}
            onChange={(e) => onChange({ ...data, viewport: e.target.checked })}
            className="w-4 h-4 rounded"
          />
          <span className="text-[11px] text-slate-300">Include viewport meta tag</span>
        </label>
      </div>

      <div className="relative">
        <button
          type="button"
          onClick={handleCopy}
          className="absolute top-2 right-2 text-[10px] text-slate-400 hover:text-white"
        >
          {copied ? 'Copied!' : 'Copy'}
        </button>
        <pre className="bg-slate-900 border border-slate-700 rounded p-2 text-[10px] text-slate-300 font-mono overflow-x-auto max-h-40">
          {output}
        </pre>
      </div>

      <div className="text-[10px] text-slate-500">
        Generate common HTML meta tags for SEO and social sharing.
      </div>
    </div>
  );
};

export class MetaTagGeneratorTool {
  static Component = MetaTagGeneratorToolComponent;
}
