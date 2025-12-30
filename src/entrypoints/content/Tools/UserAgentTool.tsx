import React, { useState } from 'react';
import type { UserAgentData, UserAgentCategory } from './tool-types';

const USER_AGENTS: Record<UserAgentCategory, { name: string; agent: string }[]> = {
  chrome: [
    { name: 'Chrome 120 Windows', agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' },
    { name: 'Chrome 120 macOS', agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' },
    { name: 'Chrome 120 Linux', agent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' }
  ],
  firefox: [
    { name: 'Firefox 121 Windows', agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0' },
    { name: 'Firefox 121 macOS', agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0' },
    { name: 'Firefox 121 Linux', agent: 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0' }
  ],
  safari: [
    { name: 'Safari 17 macOS', agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15' },
    { name: 'Safari iPad', agent: 'Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1' }
  ],
  edge: [
    { name: 'Edge 120 Windows', agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0' },
    { name: 'Edge 120 macOS', agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0' }
  ],
  mobile: [
    { name: 'Chrome Android', agent: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36' },
    { name: 'Safari iPhone', agent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1' },
    { name: 'Samsung Browser', agent: 'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36' }
  ],
  bot: [
    { name: 'Googlebot', agent: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' },
    { name: 'Bingbot', agent: 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)' },
    { name: 'Googlebot Mobile', agent: 'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' }
  ]
};

const CATEGORIES: { id: UserAgentCategory; label: string }[] = [
  { id: 'chrome', label: 'Chrome' },
  { id: 'firefox', label: 'Firefox' },
  { id: 'safari', label: 'Safari' },
  { id: 'edge', label: 'Edge' },
  { id: 'mobile', label: 'Mobile' },
  { id: 'bot', label: 'Bots' }
];

type Props = {
  data: UserAgentData | undefined;
  onChange: (next: UserAgentData) => void;
};

const UserAgentToolComponent = ({ data, onChange }: Props) => {
  const category: UserAgentCategory = data?.category ?? 'chrome';
  const selectedAgent = data?.selectedAgent ?? '';
  const customAgent = data?.customAgent ?? '';
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    const agent = selectedAgent || customAgent;
    if (agent) {
      navigator.clipboard.writeText(agent);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">User-Agent Generator</div>

      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">Browser/Platform</div>
        <div className="flex flex-wrap gap-1">
          {CATEGORIES.map((cat) => (
            <button
              key={cat.id}
              type="button"
              onClick={() => onChange({ ...data, category: cat.id })}
              className={`rounded px-2 py-1 text-[10px] transition-colors ${
                category === cat.id ? 'bg-emerald-600 text-white' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-1 max-h-40 overflow-y-auto">
        {(USER_AGENTS[category] || []).map((ua, i) => (
          <div
            key={i}
            className="bg-slate-800 rounded p-2 cursor-pointer hover:bg-slate-700"
            onClick={() => onChange({ ...data, selectedAgent: ua.agent })}
          >
            <div className="text-[11px] text-emerald-400">{ua.name}</div>
            <div className="text-[9px] text-slate-500 truncate">{ua.agent.slice(0, 60)}...</div>
          </div>
        ))}
      </div>

      {selectedAgent && (
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <div className="text-[11px] text-slate-400">Selected User-Agent</div>
            <button type="button" onClick={handleCopy} className="text-[10px] text-slate-400 hover:text-white">
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <div className="bg-slate-900 border border-slate-700 rounded p-2 text-[10px] text-slate-200 font-mono break-all select-all" onClick={handleCopy}>
            {selectedAgent}
          </div>
        </div>
      )}

      <textarea
        value={customAgent}
        onChange={(e) => onChange({ ...data, customAgent: e.target.value })}
        rows={2}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 font-mono"
        placeholder="Custom user-agent..."
      />

      <div className="text-[10px] text-slate-500">
        Use different user-agents to test how sites respond to various browsers and devices.
      </div>
    </div>
  );
};

export class UserAgentTool {
  static Component = UserAgentToolComponent;
}
