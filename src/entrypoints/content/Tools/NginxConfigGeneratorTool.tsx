import React, { useMemo } from 'react';
import type { NginxConfigGeneratorData } from './tool-types';

type Props = {
  data: NginxConfigGeneratorData | undefined;
  onChange: (next: NginxConfigGeneratorData) => void;
};

const NginxConfigGeneratorToolComponent = ({ data, onChange }: Props) => {
  const serverName = data?.serverName ?? 'example.com';
  const port = data?.port ?? '80';
  const root = data?.root ?? '/var/www/html';
  const proxyPass = data?.proxyPass ?? '';
  const ssl = data?.ssl ?? false;

  const config = useMemo(() => {
    const lines: string[] = [];
    lines.push(`server {`);
    lines.push(`    listen ${ssl ? '443 ssl' : port};`);
    lines.push(`    server_name ${serverName};`);
    lines.push('');

    if (ssl) {
      lines.push(`    ssl_certificate /etc/nginx/ssl/${serverName}.crt;`);
      lines.push(`    ssl_certificate_key /etc/nginx/ssl/${serverName}.key;`);
      lines.push('');
    }

    if (proxyPass) {
      lines.push('    location / {');
      lines.push(`        proxy_pass ${proxyPass};`);
      lines.push('        proxy_http_version 1.1;');
      lines.push('        proxy_set_header Upgrade $http_upgrade;');
      lines.push('        proxy_set_header Connection "upgrade";');
      lines.push('        proxy_set_header Host $host;');
      lines.push('        proxy_set_header X-Real-IP $remote_addr;');
      lines.push('    }');
    } else {
      lines.push(`    root ${root};`);
      lines.push('    index index.html index.htm;');
      lines.push('');
      lines.push('    location / {');
      lines.push('        try_files $uri $uri/ =404;');
      lines.push('    }');
    }

    lines.push('}');

    if (ssl) {
      lines.push('');
      lines.push('# HTTP redirect to HTTPS');
      lines.push('server {');
      lines.push('    listen 80;');
      lines.push(`    server_name ${serverName};`);
      lines.push(`    return 301 https://$server_name$request_uri;`);
      lines.push('}');
    }

    return lines.join('\n');
  }, [serverName, port, root, proxyPass, ssl]);

  const handleCopy = () => {
    navigator.clipboard.writeText(config);
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Nginx Config Generator</div>

      <div className="grid grid-cols-2 gap-2">
        <div className="space-y-1">
          <div className="text-[10px] text-slate-400">Server Name</div>
          <input
            type="text"
            value={serverName}
            onChange={(e) => onChange({ ...data, serverName: e.target.value })}
            className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-emerald-500"
          />
        </div>
        <div className="space-y-1">
          <div className="text-[10px] text-slate-400">Port</div>
          <input
            type="text"
            value={port}
            onChange={(e) => onChange({ ...data, port: e.target.value })}
            className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-emerald-500"
          />
        </div>
      </div>

      <div className="space-y-1">
        <div className="text-[10px] text-slate-400">Document Root (leave empty for proxy)</div>
        <input
          type="text"
          value={root}
          onChange={(e) => onChange({ ...data, root: e.target.value })}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-emerald-500"
          placeholder="/var/www/html"
        />
      </div>

      <div className="space-y-1">
        <div className="text-[10px] text-slate-400">Proxy Pass URL (optional)</div>
        <input
          type="text"
          value={proxyPass}
          onChange={(e) => onChange({ ...data, proxyPass: e.target.value })}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1.5 border border-slate-700 focus:outline-none focus:border-emerald-500"
          placeholder="http://localhost:3000"
        />
      </div>

      <label className="flex items-center gap-2 cursor-pointer">
        <input
          type="checkbox"
          checked={ssl}
          onChange={(e) => onChange({ ...data, ssl: e.target.checked })}
          className="w-4 h-4 rounded"
        />
        <span className="text-[11px] text-slate-300">Enable SSL/HTTPS</span>
      </label>

      <div className="relative">
        <button
          type="button"
          onClick={handleCopy}
          className="absolute top-2 right-2 text-[10px] text-slate-400 hover:text-white"
        >
          Copy
        </button>
        <pre className="bg-slate-900 border border-slate-700 rounded p-2 text-[10px] text-slate-300 font-mono overflow-x-auto max-h-48">
          {config}
        </pre>
      </div>
    </div>
  );
};

export class NginxConfigGeneratorTool {
  static Component = NginxConfigGeneratorToolComponent;
}
