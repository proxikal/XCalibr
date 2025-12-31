import React, { useMemo } from 'react';
import type { HttpStatusReferenceData } from './tool-types';

const HTTP_CODES = [
  { code: 100, name: 'Continue', desc: 'Continue with request', cat: 'info' },
  { code: 101, name: 'Switching Protocols', desc: 'Upgrading to different protocol', cat: 'info' },
  { code: 200, name: 'OK', desc: 'Successful request', cat: 'success' },
  { code: 201, name: 'Created', desc: 'Resource created successfully', cat: 'success' },
  { code: 204, name: 'No Content', desc: 'Success with no response body', cat: 'success' },
  { code: 206, name: 'Partial Content', desc: 'Partial resource returned', cat: 'success' },
  { code: 301, name: 'Moved Permanently', desc: 'Resource moved to new URL', cat: 'redirect' },
  { code: 302, name: 'Found', desc: 'Temporary redirect', cat: 'redirect' },
  { code: 304, name: 'Not Modified', desc: 'Cached version is valid', cat: 'redirect' },
  { code: 307, name: 'Temporary Redirect', desc: 'Temp redirect, keep method', cat: 'redirect' },
  { code: 308, name: 'Permanent Redirect', desc: 'Perm redirect, keep method', cat: 'redirect' },
  { code: 400, name: 'Bad Request', desc: 'Invalid request syntax', cat: 'client' },
  { code: 401, name: 'Unauthorized', desc: 'Authentication required', cat: 'client' },
  { code: 403, name: 'Forbidden', desc: 'Server refuses to authorize', cat: 'client' },
  { code: 404, name: 'Not Found', desc: 'Resource not found', cat: 'client' },
  { code: 405, name: 'Method Not Allowed', desc: 'HTTP method not supported', cat: 'client' },
  { code: 408, name: 'Request Timeout', desc: 'Server timed out waiting', cat: 'client' },
  { code: 409, name: 'Conflict', desc: 'Request conflicts with state', cat: 'client' },
  { code: 410, name: 'Gone', desc: 'Resource no longer available', cat: 'client' },
  { code: 418, name: "I'm a Teapot", desc: 'April Fools joke (RFC 2324)', cat: 'client' },
  { code: 422, name: 'Unprocessable Entity', desc: 'Semantic errors in request', cat: 'client' },
  { code: 429, name: 'Too Many Requests', desc: 'Rate limit exceeded', cat: 'client' },
  { code: 500, name: 'Internal Server Error', desc: 'Generic server error', cat: 'server' },
  { code: 501, name: 'Not Implemented', desc: 'Method not supported', cat: 'server' },
  { code: 502, name: 'Bad Gateway', desc: 'Invalid upstream response', cat: 'server' },
  { code: 503, name: 'Service Unavailable', desc: 'Server overloaded/down', cat: 'server' },
  { code: 504, name: 'Gateway Timeout', desc: 'Upstream server timeout', cat: 'server' },
];

const getCatColor = (cat: string) => {
  switch (cat) {
    case 'info': return 'text-blue-400';
    case 'success': return 'text-emerald-400';
    case 'redirect': return 'text-yellow-400';
    case 'client': return 'text-orange-400';
    case 'server': return 'text-red-400';
    default: return 'text-slate-400';
  }
};

type Props = {
  data: HttpStatusReferenceData | undefined;
  onChange: (next: HttpStatusReferenceData) => void;
};

const HttpStatusReferenceToolComponent = ({ data, onChange }: Props) => {
  const search = data?.search ?? '';

  const filtered = useMemo(() => {
    if (!search.trim()) return HTTP_CODES;
    const q = search.toLowerCase();
    return HTTP_CODES.filter(h =>
      h.code.toString().includes(q) ||
      h.name.toLowerCase().includes(q) ||
      h.desc.toLowerCase().includes(q)
    );
  }, [search]);

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">HTTP Status Code Reference</div>

      <input
        type="text"
        value={search}
        onChange={(e) => onChange({ ...data, search: e.target.value })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500"
        placeholder="Search codes..."
      />

      <div className="overflow-y-auto max-h-56">
        {filtered.map((h) => (
          <div key={h.code} className="flex items-start gap-2 py-1.5 border-b border-slate-800 hover:bg-slate-800/50">
            <span className={`font-mono font-bold ${getCatColor(h.cat)}`}>{h.code}</span>
            <div className="flex-1 min-w-0">
              <div className="text-[11px] text-slate-200">{h.name}</div>
              <div className="text-[10px] text-slate-500">{h.desc}</div>
            </div>
          </div>
        ))}
      </div>

      <div className="text-[10px] text-slate-500">
        HTTP status codes: <span className="text-blue-400">1xx</span> Info, <span className="text-emerald-400">2xx</span> Success, <span className="text-yellow-400">3xx</span> Redirect, <span className="text-orange-400">4xx</span> Client Error, <span className="text-red-400">5xx</span> Server Error.
      </div>
    </div>
  );
};

export class HttpStatusReferenceTool {
  static Component = HttpStatusReferenceToolComponent;
}
