import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSearch, faCopy, faKey, faComment, faExclamationTriangle } from '@fortawesome/free-solid-svg-icons';

export type CommentEntry = {
  type: 'html' | 'script';
  content: string;
  location?: string;
};

export type SecretEntry = {
  type: string;
  value: string;
  source: string;
  line?: number;
};

export type CommentSecretScraperData = {
  comments?: CommentEntry[];
  secrets?: SecretEntry[];
  scannedAt?: number;
  error?: string;
};

type Props = {
  data: CommentSecretScraperData | undefined;
  onChange: (data: CommentSecretScraperData) => void;
};

const SECRET_PATTERNS: { name: string; regex: RegExp }[] = [
  { name: 'API Key', regex: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{16,})["']?/gi },
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'AWS Secret Key', regex: /(?:aws[_-]?secret|secret[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9/+=]{40})["']?/gi },
  { name: 'JWT', regex: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g },
  { name: 'Bearer Token', regex: /Bearer\s+[a-zA-Z0-9_\-\.]+/gi },
  { name: 'Private Key', regex: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g },
  { name: 'Password', regex: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{4,})["']/gi },
  { name: 'Secret', regex: /(?:secret|token)\s*[:=]\s*["']([a-zA-Z0-9_\-]{8,})["']/gi },
  { name: 'GitHub Token', regex: /gh[pousr]_[a-zA-Z0-9]{36,}/g },
  { name: 'Slack Token', regex: /xox[baprs]-[a-zA-Z0-9-]+/g },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/g },
  { name: 'Stripe Key', regex: /(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{24,}/g }
];

const CommentSecretScraper: React.FC<Props> = ({ data, onChange }) => {
  const comments = data?.comments ?? [];
  const secrets = data?.secrets ?? [];
  const scannedAt = data?.scannedAt;
  const error = data?.error;
  const [scanning, setScanning] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const scanPage = () => {
    setScanning(true);
    try {
      const foundComments: CommentEntry[] = [];
      const foundSecrets: SecretEntry[] = [];

      // Scan HTML comments
      const html = document.documentElement.outerHTML;
      const commentRegex = /<!--([\s\S]*?)-->/g;
      let match;
      while ((match = commentRegex.exec(html)) !== null) {
        const content = match[1].trim();
        if (content.length > 0 && content.length < 2000) {
          foundComments.push({ type: 'html', content });
        }
      }

      // Scan inline scripts for comments and secrets
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach((script, idx) => {
        const scriptContent = script.textContent || '';

        // Single-line comments
        const singleLineComments = scriptContent.match(/\/\/[^\n]*/g) || [];
        singleLineComments.forEach(c => {
          if (c.length > 3 && c.length < 500) {
            foundComments.push({ type: 'script', content: c, location: `inline-script-${idx}` });
          }
        });

        // Multi-line comments
        const multiLineComments = scriptContent.match(/\/\*[\s\S]*?\*\//g) || [];
        multiLineComments.forEach(c => {
          if (c.length > 4 && c.length < 2000) {
            foundComments.push({ type: 'script', content: c, location: `inline-script-${idx}` });
          }
        });
      });

      // Scan for secrets in full page source
      SECRET_PATTERNS.forEach(pattern => {
        const matches = html.matchAll(pattern.regex);
        for (const m of matches) {
          const value = m[1] || m[0];
          if (!foundSecrets.some(s => s.value === value)) {
            foundSecrets.push({
              type: pattern.name,
              value: value.substring(0, 100),
              source: 'page source'
            });
          }
        }
      });

      // Scan external script URLs visible in page
      const externalScripts = document.querySelectorAll('script[src]');
      externalScripts.forEach((script) => {
        const src = script.getAttribute('src') || '';
        SECRET_PATTERNS.forEach(pattern => {
          const matches = src.matchAll(pattern.regex);
          for (const m of matches) {
            const value = m[1] || m[0];
            if (!foundSecrets.some(s => s.value === value)) {
              foundSecrets.push({
                type: pattern.name,
                value: value.substring(0, 100),
                source: `script src: ${src.substring(0, 50)}`
              });
            }
          }
        });
      });

      onChange({
        comments: foundComments,
        secrets: foundSecrets,
        scannedAt: Date.now(),
        error: undefined
      });
    } catch (e) {
      onChange({
        ...data,
        error: e instanceof Error ? e.message : 'Scan failed',
        scannedAt: Date.now()
      });
    } finally {
      setScanning(false);
    }
  };

  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 1500);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Comment & Secret Scraper</div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Scans page HTML comments and scripts for secrets, API keys, tokens, and passwords.
      </div>

      <button
        onClick={scanPage}
        disabled={scanning}
        className="w-full rounded bg-red-600/20 border border-red-500/30 px-2 py-1.5 text-[11px] text-red-300 hover:bg-red-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faSearch} className="w-3 h-3" />
        {scanning ? 'Scanning...' : 'Scan Page'}
      </button>

      {error && (
        <div className="rounded border border-red-500/30 bg-red-900/20 p-2 mb-3 text-[10px] text-red-400">
          {error}
        </div>
      )}

      {scannedAt && (
        <div className="text-[10px] text-slate-500 mb-2">
          Last scanned: {new Date(scannedAt).toLocaleTimeString()}
        </div>
      )}

      <div className="flex-1 overflow-y-auto space-y-3 min-h-0">
        {/* Secrets Section */}
        {secrets.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-yellow-400 text-[11px] font-medium">
              <FontAwesomeIcon icon={faExclamationTriangle} className="w-3 h-3" />
              Secrets Found ({secrets.length})
            </div>
            <div className="space-y-2">
              {secrets.map((secret, idx) => (
                <div key={idx} className="rounded border border-red-500/30 bg-red-900/20 p-2">
                  <div className="flex justify-between items-start">
                    <div>
                      <span className="text-red-400 text-[10px] font-medium flex items-center gap-1">
                        <FontAwesomeIcon icon={faKey} className="w-2.5 h-2.5" />
                        {secret.type}
                      </span>
                      <div className="text-slate-200 text-[10px] font-mono mt-1 break-all">
                        {secret.value}
                      </div>
                      <div className="text-slate-500 text-[9px] mt-1">
                        Source: {secret.source}
                      </div>
                    </div>
                    <button
                      onClick={() => copyToClipboard(secret.value, idx)}
                      className="text-[9px] text-slate-500 hover:text-slate-300"
                      title="Copy"
                    >
                      <FontAwesomeIcon icon={faCopy} className="w-2.5 h-2.5" />
                    </button>
                  </div>
                  {copiedIndex === idx && (
                    <span className="text-green-400 text-[9px]">Copied!</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Comments Section */}
        {comments.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-blue-400 text-[11px] font-medium">
              <FontAwesomeIcon icon={faComment} className="w-3 h-3" />
              Comments Found ({comments.length})
            </div>
            <div className="space-y-2">
              {comments.slice(0, 50).map((comment, idx) => (
                <div key={idx} className="rounded border border-slate-700 bg-slate-800/50 p-2">
                  <div className="flex justify-between items-start">
                    <div className="flex-1">
                      <span className={`text-[9px] px-1.5 py-0.5 rounded ${
                        comment.type === 'html' ? 'bg-blue-900/50 text-blue-300' : 'bg-purple-900/50 text-purple-300'
                      }`}>
                        {comment.type === 'html' ? 'HTML' : 'JS'}
                      </span>
                      <pre className="text-slate-300 text-[10px] mt-1 whitespace-pre-wrap break-all max-h-20 overflow-hidden">
                        {comment.content.substring(0, 300)}{comment.content.length > 300 ? '...' : ''}
                      </pre>
                    </div>
                    <button
                      onClick={() => copyToClipboard(comment.content, idx + 1000)}
                      className="text-[9px] text-slate-500 hover:text-slate-300 ml-2"
                      title="Copy"
                    >
                      <FontAwesomeIcon icon={faCopy} className="w-2.5 h-2.5" />
                    </button>
                  </div>
                </div>
              ))}
              {comments.length > 50 && (
                <div className="text-slate-500 text-[10px] text-center">
                  ...and {comments.length - 50} more comments
                </div>
              )}
            </div>
          </div>
        )}

        {scannedAt && secrets.length === 0 && comments.length === 0 && (
          <div className="text-[11px] text-green-400 text-center py-4">
            No secrets or comments found on this page.
          </div>
        )}

        {!scannedAt && (
          <div className="text-[11px] text-slate-500 text-center py-4">
            Click scan to search for secrets and comments.
          </div>
        )}
      </div>

      <div className="text-[10px] text-slate-500 border-t border-slate-700 pt-3 mt-3">
        <div><strong>Detected patterns:</strong></div>
        <div className="text-slate-600">API keys, AWS keys, JWTs, passwords, tokens, private keys, etc.</div>
      </div>
    </div>
  );
};

export class CommentSecretScraperTool {
  static Component = CommentSecretScraper;
}
