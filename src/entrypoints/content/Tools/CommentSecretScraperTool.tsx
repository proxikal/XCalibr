import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSearch, faCopy, faKey, faComment, faExclamationTriangle, faDownload, faFilter } from '@fortawesome/free-solid-svg-icons';

export type CommentEntry = {
  type: 'html' | 'script' | 'css';
  content: string;
  location?: string;
};

export type SecretEntry = {
  type: string;
  value: string;
  source: string;
  line?: number;
  confidence: 'high' | 'medium' | 'low';
  entropy?: number;
};

export type CommentSecretScraperData = {
  comments?: CommentEntry[];
  secrets?: SecretEntry[];
  scannedAt?: number;
  error?: string;
  filterConfidence?: 'all' | 'high' | 'medium';
};

type Props = {
  data: CommentSecretScraperData | undefined;
  onChange: (data: CommentSecretScraperData) => void;
};

// Calculate Shannon entropy for a string (higher = more random = more likely a secret)
const calculateEntropy = (str: string): number => {
  const len = str.length;
  if (len === 0) return 0;
  const freq: Record<string, number> = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
};

// 40+ secret patterns with confidence levels
const SECRET_PATTERNS: { name: string; regex: RegExp; confidence: 'high' | 'medium' | 'low' }[] = [
  // HIGH CONFIDENCE - Definitive patterns
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g, confidence: 'high' },
  { name: 'AWS Secret Key', regex: /(?:aws[_-]?secret|secret[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9/+=]{40})["']?/gi, confidence: 'high' },
  { name: 'AWS Session Token', regex: /(?:aws[_-]?session[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9/+=]{100,})["']?/gi, confidence: 'high' },
  { name: 'JWT', regex: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g, confidence: 'high' },
  { name: 'GitHub Token', regex: /gh[pousr]_[a-zA-Z0-9]{36,}/g, confidence: 'high' },
  { name: 'GitHub OAuth', regex: /gho_[a-zA-Z0-9]{36,}/g, confidence: 'high' },
  { name: 'GitLab Token', regex: /glpat-[a-zA-Z0-9_-]{20,}/g, confidence: 'high' },
  { name: 'Slack Token', regex: /xox[baprs]-[a-zA-Z0-9-]+/g, confidence: 'high' },
  { name: 'Slack Webhook', regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/g, confidence: 'high' },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/g, confidence: 'high' },
  { name: 'Google OAuth ID', regex: /[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com/g, confidence: 'high' },
  { name: 'Stripe Live Key', regex: /sk_live_[a-zA-Z0-9]{24,}/g, confidence: 'high' },
  { name: 'Stripe Test Key', regex: /sk_test_[a-zA-Z0-9]{24,}/g, confidence: 'high' },
  { name: 'Stripe Publishable', regex: /pk_(?:live|test)_[a-zA-Z0-9]{24,}/g, confidence: 'high' },
  { name: 'Private Key', regex: /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/g, confidence: 'high' },
  { name: 'Twilio API Key', regex: /SK[a-f0-9]{32}/g, confidence: 'high' },
  { name: 'Twilio Account SID', regex: /AC[a-f0-9]{32}/g, confidence: 'high' },
  { name: 'SendGrid API Key', regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, confidence: 'high' },
  { name: 'Mailgun API Key', regex: /key-[a-zA-Z0-9]{32}/g, confidence: 'high' },
  { name: 'Mailchimp API Key', regex: /[a-f0-9]{32}-us[0-9]{1,2}/g, confidence: 'high' },
  { name: 'Firebase API Key', regex: /AIza[0-9A-Za-z_-]{35}/g, confidence: 'high' },
  { name: 'Heroku API Key', regex: /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g, confidence: 'medium' },
  { name: 'NPM Token', regex: /npm_[a-zA-Z0-9]{36}/g, confidence: 'high' },
  { name: 'PyPI Token', regex: /pypi-[a-zA-Z0-9_-]{50,}/g, confidence: 'high' },
  { name: 'Discord Token', regex: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/g, confidence: 'high' },
  { name: 'Discord Webhook', regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+/g, confidence: 'high' },
  { name: 'Shopify Access Token', regex: /shpat_[a-fA-F0-9]{32}/g, confidence: 'high' },
  { name: 'Shopify Shared Secret', regex: /shpss_[a-fA-F0-9]{32}/g, confidence: 'high' },
  { name: 'Square Access Token', regex: /sq0atp-[a-zA-Z0-9_-]{22}/g, confidence: 'high' },
  { name: 'Square OAuth Secret', regex: /sq0csp-[a-zA-Z0-9_-]{43}/g, confidence: 'high' },
  { name: 'Azure Storage Key', regex: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/=]{88}/g, confidence: 'high' },
  { name: 'Azure SAS Token', regex: /[?&]sig=[a-zA-Z0-9%]+/g, confidence: 'medium' },
  { name: 'Dropbox Token', regex: /sl\.[a-zA-Z0-9_-]{130,}/g, confidence: 'high' },
  { name: 'Facebook Token', regex: /EAA[a-zA-Z0-9]+/g, confidence: 'high' },
  { name: 'Twitter Bearer', regex: /AAAAAAAAAAAAAAAAAAAAAA[a-zA-Z0-9%]+/g, confidence: 'high' },
  { name: 'LinkedIn Token', regex: /AQ[A-Za-z0-9_-]{50,}/g, confidence: 'medium' },

  // MEDIUM CONFIDENCE - Context-dependent patterns
  { name: 'Bearer Token', regex: /Bearer\s+[a-zA-Z0-9_\-\.]{20,}/gi, confidence: 'medium' },
  { name: 'API Key (generic)', regex: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,})["']?/gi, confidence: 'medium' },
  { name: 'Auth Token', regex: /(?:auth[_-]?token|authorization)\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{20,})["']?/gi, confidence: 'medium' },
  { name: 'Access Token', regex: /(?:access[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{20,})["']?/gi, confidence: 'medium' },
  { name: 'Refresh Token', regex: /(?:refresh[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{20,})["']?/gi, confidence: 'medium' },
  { name: 'Client Secret', regex: /(?:client[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{16,})["']?/gi, confidence: 'medium' },
  { name: 'Password', regex: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{6,})["']/gi, confidence: 'medium' },
  { name: 'Database URL', regex: /(?:mongodb|mysql|postgres|postgresql|redis):\/\/[^\s"'<>]+/gi, confidence: 'high' },
  { name: 'Connection String', regex: /(?:Server|Data Source)=[^;]+;(?:User Id|uid)=[^;]+;(?:Password|pwd)=[^;]+/gi, confidence: 'high' },

  // LOW CONFIDENCE - Requires entropy check
  { name: 'Secret (generic)', regex: /(?:secret|token|credential)\s*[:=]\s*["']([a-zA-Z0-9_\-]{12,})["']/gi, confidence: 'low' },
  { name: 'Hash-like', regex: /[a-f0-9]{32,64}/gi, confidence: 'low' }
];

const CommentSecretScraper: React.FC<Props> = ({ data, onChange }) => {
  const comments = data?.comments ?? [];
  const secrets = data?.secrets ?? [];
  const scannedAt = data?.scannedAt;
  const error = data?.error;
  const filterConfidence = data?.filterConfidence ?? 'all';
  const [scanning, setScanning] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const scanPage = () => {
    setScanning(true);
    try {
      const foundComments: CommentEntry[] = [];
      const foundSecrets: SecretEntry[] = [];
      const seenValues = new Set<string>();

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

      // Scan CSS comments
      const styles = document.querySelectorAll('style');
      styles.forEach((style, idx) => {
        const cssContent = style.textContent || '';
        const cssComments = cssContent.match(/\/\*[\s\S]*?\*\//g) || [];
        cssComments.forEach(c => {
          if (c.length > 4 && c.length < 2000) {
            foundComments.push({ type: 'css', content: c, location: `inline-style-${idx}` });
          }
        });
      });

      // Helper to add secret with deduplication and entropy
      const addSecret = (pattern: typeof SECRET_PATTERNS[0], value: string, source: string) => {
        const cleanValue = value.substring(0, 150);
        if (seenValues.has(cleanValue)) return;

        const entropy = calculateEntropy(cleanValue);

        // For low confidence patterns, require high entropy (> 3.5 bits)
        if (pattern.confidence === 'low' && entropy < 3.5) return;

        seenValues.add(cleanValue);
        foundSecrets.push({
          type: pattern.name,
          value: cleanValue,
          source,
          confidence: pattern.confidence,
          entropy
        });
      };

      // Scan for secrets in full page source
      SECRET_PATTERNS.forEach(pattern => {
        pattern.regex.lastIndex = 0; // Reset regex
        const matches = html.matchAll(pattern.regex);
        for (const m of matches) {
          const value = m[1] || m[0];
          addSecret(pattern, value, 'page source');
        }
      });

      // Scan external script URLs visible in page
      const externalScripts = document.querySelectorAll('script[src]');
      externalScripts.forEach((script) => {
        const src = script.getAttribute('src') || '';
        SECRET_PATTERNS.forEach(pattern => {
          pattern.regex.lastIndex = 0;
          const matches = src.matchAll(pattern.regex);
          for (const m of matches) {
            const value = m[1] || m[0];
            addSecret(pattern, value, `script: ${src.substring(0, 40)}...`);
          }
        });
      });

      // Scan link hrefs and img srcs
      document.querySelectorAll('a[href], link[href], img[src]').forEach((el) => {
        const attr = el.getAttribute('href') || el.getAttribute('src') || '';
        SECRET_PATTERNS.forEach(pattern => {
          pattern.regex.lastIndex = 0;
          const matches = attr.matchAll(pattern.regex);
          for (const m of matches) {
            const value = m[1] || m[0];
            addSecret(pattern, value, `attribute: ${attr.substring(0, 40)}...`);
          }
        });
      });

      // Sort secrets by confidence (high first)
      foundSecrets.sort((a, b) => {
        const order = { high: 0, medium: 1, low: 2 };
        return order[a.confidence] - order[b.confidence];
      });

      onChange({
        comments: foundComments,
        secrets: foundSecrets,
        scannedAt: Date.now(),
        error: undefined,
        filterConfidence
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

  const filteredSecrets = secrets.filter(s => {
    if (filterConfidence === 'all') return true;
    if (filterConfidence === 'high') return s.confidence === 'high';
    if (filterConfidence === 'medium') return s.confidence === 'high' || s.confidence === 'medium';
    return true;
  });

  const exportAsJson = () => {
    const exportData = {
      url: window.location.href,
      scannedAt: scannedAt ? new Date(scannedAt).toISOString() : null,
      secrets: filteredSecrets,
      comments: comments.slice(0, 100)
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `secrets-${window.location.hostname}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 1500);
  };

  const highCount = secrets.filter(s => s.confidence === 'high').length;
  const mediumCount = secrets.filter(s => s.confidence === 'medium').length;
  const lowCount = secrets.filter(s => s.confidence === 'low').length;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Comment & Secret Scraper</div>
        <div className="flex gap-1">
          {scannedAt && filteredSecrets.length > 0 && (
            <button
              onClick={exportAsJson}
              className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors flex items-center gap-1"
              title="Export as JSON"
            >
              <FontAwesomeIcon icon={faDownload} className="w-2.5 h-2.5" />
            </button>
          )}
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Scans page for secrets with 45+ patterns. Uses entropy scoring to reduce false positives.
      </div>

      <button
        onClick={scanPage}
        disabled={scanning}
        className="w-full rounded bg-red-600/20 border border-red-500/30 px-2 py-1.5 text-[11px] text-red-300 hover:bg-red-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faSearch} className="w-3 h-3" />
        {scanning ? 'Scanning...' : 'Scan Page'}
      </button>

      {/* Confidence Filter */}
      {scannedAt && secrets.length > 0 && (
        <div className="flex items-center gap-2 mb-3">
          <FontAwesomeIcon icon={faFilter} className="w-2.5 h-2.5 text-slate-500" />
          <div className="flex gap-1">
            {(['all', 'high', 'medium'] as const).map(level => (
              <button
                key={level}
                onClick={() => onChange({ ...data, filterConfidence: level })}
                className={`px-2 py-0.5 rounded text-[9px] transition-colors ${
                  filterConfidence === level
                    ? 'bg-red-600/30 text-red-300 border border-red-500/50'
                    : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-500'
                }`}
              >
                {level === 'all' ? 'All' : level === 'high' ? 'High' : 'High+Med'}
              </button>
            ))}
          </div>
          <div className="text-[9px] text-slate-500 ml-auto">
            {highCount > 0 && <span className="text-red-400 mr-1">{highCount}H</span>}
            {mediumCount > 0 && <span className="text-yellow-400 mr-1">{mediumCount}M</span>}
            {lowCount > 0 && <span className="text-blue-400">{lowCount}L</span>}
          </div>
        </div>
      )}

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
        {filteredSecrets.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-yellow-400 text-[11px] font-medium">
              <FontAwesomeIcon icon={faExclamationTriangle} className="w-3 h-3" />
              Secrets Found ({filteredSecrets.length}{filteredSecrets.length !== secrets.length ? `/${secrets.length}` : ''})
            </div>
            <div className="space-y-2">
              {filteredSecrets.map((secret, idx) => (
                <div key={idx} className={`rounded border p-2 ${
                  secret.confidence === 'high' ? 'border-red-500/50 bg-red-900/30' :
                  secret.confidence === 'medium' ? 'border-yellow-500/50 bg-yellow-900/20' :
                  'border-blue-500/50 bg-blue-900/20'
                }`}>
                  <div className="flex justify-between items-start">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-[10px] font-medium flex items-center gap-1 ${
                          secret.confidence === 'high' ? 'text-red-400' :
                          secret.confidence === 'medium' ? 'text-yellow-400' : 'text-blue-400'
                        }`}>
                          <FontAwesomeIcon icon={faKey} className="w-2.5 h-2.5" />
                          {secret.type}
                        </span>
                        <span className={`text-[8px] px-1.5 py-0.5 rounded uppercase ${
                          secret.confidence === 'high' ? 'bg-red-800/50 text-red-300' :
                          secret.confidence === 'medium' ? 'bg-yellow-800/50 text-yellow-300' :
                          'bg-blue-800/50 text-blue-300'
                        }`}>
                          {secret.confidence}
                        </span>
                        {secret.entropy !== undefined && (
                          <span className="text-[8px] text-slate-500" title="Shannon entropy (higher = more random)">
                            E:{secret.entropy}
                          </span>
                        )}
                      </div>
                      <div className="text-slate-200 text-[10px] font-mono mt-1 break-all">
                        {secret.value}
                      </div>
                      <div className="text-slate-500 text-[9px] mt-1">
                        {secret.source}
                      </div>
                    </div>
                    <button
                      onClick={() => copyToClipboard(secret.value, idx)}
                      className="text-[9px] text-slate-500 hover:text-slate-300 ml-2"
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
                        comment.type === 'html' ? 'bg-blue-900/50 text-blue-300' :
                        comment.type === 'css' ? 'bg-pink-900/50 text-pink-300' :
                        'bg-purple-900/50 text-purple-300'
                      }`}>
                        {comment.type === 'html' ? 'HTML' : comment.type === 'css' ? 'CSS' : 'JS'}
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

        {scannedAt && filteredSecrets.length === 0 && comments.length === 0 && (
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
        <div><strong>45+ patterns:</strong> AWS, GCP, Stripe, GitHub, Slack, Twilio, SendGrid, Discord, Shopify, Square, JWT, SSH keys, DB connection strings, and more.</div>
      </div>
    </div>
  );
};

export class CommentSecretScraperTool {
  static Component = CommentSecretScraper;
}
