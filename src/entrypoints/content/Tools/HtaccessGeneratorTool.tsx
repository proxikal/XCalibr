import React, { useMemo, useState } from 'react';
import type { HtaccessGeneratorData } from './tool-types';

type Props = {
  data: HtaccessGeneratorData | undefined;
  onChange: (next: HtaccessGeneratorData) => void;
};

const HtaccessGeneratorToolComponent = ({ data, onChange }: Props) => {
  const redirects = data?.redirects ?? false;
  const compression = data?.compression ?? true;
  const caching = data?.caching ?? true;
  const [copied, setCopied] = useState(false);

  const config = useMemo(() => {
    const lines: string[] = [];

    if (redirects) {
      lines.push('# Force HTTPS');
      lines.push('RewriteEngine On');
      lines.push('RewriteCond %{HTTPS} off');
      lines.push('RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]');
      lines.push('');
      lines.push('# Remove www');
      lines.push('RewriteCond %{HTTP_HOST} ^www\\.(.*)$ [NC]');
      lines.push('RewriteRule ^(.*)$ https://%1/$1 [R=301,L]');
      lines.push('');
    }

    if (compression) {
      lines.push('# Enable compression');
      lines.push('<IfModule mod_deflate.c>');
      lines.push('  AddOutputFilterByType DEFLATE text/html text/plain text/xml');
      lines.push('  AddOutputFilterByType DEFLATE text/css text/javascript');
      lines.push('  AddOutputFilterByType DEFLATE application/javascript application/json');
      lines.push('  AddOutputFilterByType DEFLATE application/xml application/xhtml+xml');
      lines.push('</IfModule>');
      lines.push('');
    }

    if (caching) {
      lines.push('# Browser caching');
      lines.push('<IfModule mod_expires.c>');
      lines.push('  ExpiresActive On');
      lines.push('  ExpiresByType image/jpg "access plus 1 year"');
      lines.push('  ExpiresByType image/jpeg "access plus 1 year"');
      lines.push('  ExpiresByType image/png "access plus 1 year"');
      lines.push('  ExpiresByType image/gif "access plus 1 year"');
      lines.push('  ExpiresByType image/svg+xml "access plus 1 year"');
      lines.push('  ExpiresByType text/css "access plus 1 month"');
      lines.push('  ExpiresByType application/javascript "access plus 1 month"');
      lines.push('  ExpiresByType text/html "access plus 1 day"');
      lines.push('</IfModule>');
      lines.push('');
    }

    // Security headers
    lines.push('# Security headers');
    lines.push('<IfModule mod_headers.c>');
    lines.push('  Header set X-Content-Type-Options "nosniff"');
    lines.push('  Header set X-Frame-Options "SAMEORIGIN"');
    lines.push('  Header set X-XSS-Protection "1; mode=block"');
    lines.push('</IfModule>');

    return lines.join('\n');
  }, [redirects, compression, caching]);

  const handleCopy = () => {
    navigator.clipboard.writeText(config);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Apache .htaccess Generator</div>

      <div className="space-y-2 bg-slate-800 rounded p-3">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={redirects}
            onChange={(e) => onChange({ ...data, redirects: e.target.checked })}
            className="w-4 h-4 rounded"
          />
          <span className="text-[11px] text-slate-300">HTTPS & www redirect</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={compression}
            onChange={(e) => onChange({ ...data, compression: e.target.checked })}
            className="w-4 h-4 rounded"
          />
          <span className="text-[11px] text-slate-300">Gzip compression</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={caching}
            onChange={(e) => onChange({ ...data, caching: e.target.checked })}
            className="w-4 h-4 rounded"
          />
          <span className="text-[11px] text-slate-300">Browser caching</span>
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
        <pre className="bg-slate-900 border border-slate-700 rounded p-2 text-[10px] text-slate-300 font-mono overflow-x-auto max-h-56">
          {config}
        </pre>
      </div>

      <div className="text-[10px] text-slate-500">
        Generate common .htaccess rules for Apache web servers. Security headers always included.
      </div>
    </div>
  );
};

export class HtaccessGeneratorTool {
  static Component = HtaccessGeneratorToolComponent;
}
