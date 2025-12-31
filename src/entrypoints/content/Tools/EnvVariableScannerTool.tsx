import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faKey, faExclamationTriangle, faSearch, faCopy, faCheckCircle } from '@fortawesome/free-solid-svg-icons';

export type EnvVariableScannerData = {
  findings?: EnvFinding[];
  scannedAt?: number;
  error?: string;
};

export type EnvFinding = {
  key: string;
  value: string;
  source: 'window' | 'meta' | 'script' | 'data-attr';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description?: string;
};

type Props = {
  data: EnvVariableScannerData | undefined;
  onChange: (data: EnvVariableScannerData) => void;
};

const envPatterns = [
  { pattern: /API[_-]?KEY/i, severity: 'critical' as const, description: 'API Key' },
  { pattern: /SECRET[_-]?KEY/i, severity: 'critical' as const, description: 'Secret Key' },
  { pattern: /PRIVATE[_-]?KEY/i, severity: 'critical' as const, description: 'Private Key' },
  { pattern: /AWS[_-]?ACCESS/i, severity: 'critical' as const, description: 'AWS Credentials' },
  { pattern: /AWS[_-]?SECRET/i, severity: 'critical' as const, description: 'AWS Secret' },
  { pattern: /DATABASE[_-]?URL/i, severity: 'critical' as const, description: 'Database URL' },
  { pattern: /DB[_-]?PASSWORD/i, severity: 'critical' as const, description: 'Database Password' },
  { pattern: /MONGO[_-]?URI/i, severity: 'critical' as const, description: 'MongoDB URI' },
  { pattern: /REDIS[_-]?URL/i, severity: 'high' as const, description: 'Redis URL' },
  { pattern: /STRIPE[_-]?KEY/i, severity: 'critical' as const, description: 'Stripe Key' },
  { pattern: /GITHUB[_-]?TOKEN/i, severity: 'critical' as const, description: 'GitHub Token' },
  { pattern: /GOOGLE[_-]?API/i, severity: 'high' as const, description: 'Google API Key' },
  { pattern: /FIREBASE/i, severity: 'high' as const, description: 'Firebase Config' },
  { pattern: /SUPABASE/i, severity: 'high' as const, description: 'Supabase Config' },
  { pattern: /AUTH[_-]?TOKEN/i, severity: 'high' as const, description: 'Auth Token' },
  { pattern: /JWT[_-]?SECRET/i, severity: 'critical' as const, description: 'JWT Secret' },
  { pattern: /SESSION[_-]?SECRET/i, severity: 'critical' as const, description: 'Session Secret' },
  { pattern: /ENCRYPTION[_-]?KEY/i, severity: 'critical' as const, description: 'Encryption Key' },
  { pattern: /PASSWORD/i, severity: 'high' as const, description: 'Password' },
  { pattern: /SENDGRID/i, severity: 'high' as const, description: 'SendGrid Config' },
  { pattern: /TWILIO/i, severity: 'high' as const, description: 'Twilio Config' },
  { pattern: /SLACK[_-]?WEBHOOK/i, severity: 'medium' as const, description: 'Slack Webhook' },
  { pattern: /DISCORD[_-]?WEBHOOK/i, severity: 'medium' as const, description: 'Discord Webhook' },
  { pattern: /NEXT[_-]?PUBLIC/i, severity: 'low' as const, description: 'Next.js Public Env' },
  { pattern: /REACT[_-]?APP/i, severity: 'low' as const, description: 'React App Env' },
  { pattern: /VITE[_-]/i, severity: 'low' as const, description: 'Vite Env' },
  { pattern: /NODE[_-]?ENV/i, severity: 'low' as const, description: 'Node Environment' },
  { pattern: /DEBUG/i, severity: 'low' as const, description: 'Debug Flag' },
];

const scanForEnvVariables = (): EnvFinding[] => {
  const findings: EnvFinding[] = [];
  const seen = new Set<string>();

  // Scan window object for common env patterns
  const windowKeys = Object.keys(window).filter(key => {
    return envPatterns.some(p => p.pattern.test(key));
  });

  for (const key of windowKeys) {
    const value = (window as unknown as Record<string, unknown>)[key];
    if (value && typeof value === 'string' && !seen.has(`window:${key}`)) {
      const pattern = envPatterns.find(p => p.pattern.test(key));
      findings.push({
        key,
        value: value.length > 100 ? value.substring(0, 100) + '...' : value,
        source: 'window',
        severity: pattern?.severity ?? 'low',
        description: pattern?.description
      });
      seen.add(`window:${key}`);
    }
  }

  // Scan for __ENV__, process.env, etc.
  const commonEnvObjects = ['__ENV__', '__CONFIG__', '__RUNTIME_CONFIG__', 'env', 'ENV', 'config', 'CONFIG'];
  for (const objName of commonEnvObjects) {
    const obj = (window as unknown as Record<string, unknown>)[objName];
    if (obj && typeof obj === 'object') {
      for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
        if (typeof value === 'string' && !seen.has(`window:${objName}.${key}`)) {
          const pattern = envPatterns.find(p => p.pattern.test(key));
          if (pattern || key.includes('KEY') || key.includes('SECRET') || key.includes('TOKEN')) {
            findings.push({
              key: `${objName}.${key}`,
              value: value.length > 100 ? value.substring(0, 100) + '...' : value,
              source: 'window',
              severity: pattern?.severity ?? 'medium',
              description: pattern?.description
            });
            seen.add(`window:${objName}.${key}`);
          }
        }
      }
    }
  }

  // Scan meta tags
  document.querySelectorAll('meta').forEach(meta => {
    const name = meta.getAttribute('name') || meta.getAttribute('property') || '';
    const content = meta.getAttribute('content') || '';
    if (content && envPatterns.some(p => p.pattern.test(name))) {
      const pattern = envPatterns.find(p => p.pattern.test(name));
      if (!seen.has(`meta:${name}`)) {
        findings.push({
          key: name,
          value: content.length > 100 ? content.substring(0, 100) + '...' : content,
          source: 'meta',
          severity: pattern?.severity ?? 'medium',
          description: pattern?.description
        });
        seen.add(`meta:${name}`);
      }
    }
  });

  // Scan inline scripts for env patterns
  document.querySelectorAll('script:not([src])').forEach(script => {
    const content = script.textContent || '';

    // Look for patterns like: API_KEY = "value" or "API_KEY": "value"
    const matches = content.matchAll(/["']?([\w_]+(?:KEY|SECRET|TOKEN|PASSWORD|API|AUTH|PRIVATE|AWS|MONGO|REDIS|STRIPE|FIREBASE|SUPABASE)[\w_]*)["']?\s*[:=]\s*["']([^"']+)["']/gi);

    for (const match of matches) {
      const key = match[1];
      const value = match[2];
      if (!seen.has(`script:${key}`)) {
        const pattern = envPatterns.find(p => p.pattern.test(key));
        findings.push({
          key,
          value: value.length > 100 ? value.substring(0, 100) + '...' : value,
          source: 'script',
          severity: pattern?.severity ?? 'high',
          description: pattern?.description || 'Inline Script Variable'
        });
        seen.add(`script:${key}`);
      }
    }
  });

  // Scan data attributes
  document.querySelectorAll('[data-api-key], [data-secret], [data-token], [data-config]').forEach(el => {
    const attrs = el.attributes;
    for (const attr of Array.from(attrs)) {
      if (attr.name.startsWith('data-') && attr.value) {
        const key = attr.name;
        if (!seen.has(`data:${key}`)) {
          const pattern = envPatterns.find(p => p.pattern.test(key));
          if (pattern || key.includes('key') || key.includes('secret') || key.includes('token')) {
            findings.push({
              key,
              value: attr.value.length > 100 ? attr.value.substring(0, 100) + '...' : attr.value,
              source: 'data-attr',
              severity: pattern?.severity ?? 'medium',
              description: 'Data Attribute'
            });
            seen.add(`data:${key}`);
          }
        }
      }
    }
  });

  return findings.sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });
};

const EnvVariableScanner: React.FC<Props> = ({ data, onChange }) => {
  const findings = data?.findings ?? [];
  const scannedAt = data?.scannedAt;
  const error = data?.error ?? '';
  const [scanning, setScanning] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleScan = async () => {
    setScanning(true);
    onChange({ ...data, error: '' });

    try {
      const results = scanForEnvVariables();
      onChange({
        findings: results,
        scannedAt: Date.now(),
        error: results.length === 0 ? 'No exposed environment variables found' : ''
      });
    } catch (e) {
      onChange({
        ...data,
        error: e instanceof Error ? e.message : 'Failed to scan'
      });
    } finally {
      setScanning(false);
    }
  };

  const handleCopy = async (finding: EnvFinding) => {
    await navigator.clipboard.writeText(`${finding.key}=${finding.value}`);
    setCopiedKey(finding.key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const severityColors = {
    critical: 'border-red-500/50 bg-red-900/20 text-red-400',
    high: 'border-orange-500/50 bg-orange-900/20 text-orange-400',
    medium: 'border-yellow-500/50 bg-yellow-900/20 text-yellow-400',
    low: 'border-blue-500/50 bg-blue-900/20 text-blue-400'
  };

  const severityBadge = {
    critical: 'bg-red-600/30 text-red-300',
    high: 'bg-orange-600/30 text-orange-300',
    medium: 'bg-yellow-600/30 text-yellow-300',
    low: 'bg-blue-600/30 text-blue-300'
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Env Variable Scanner</div>
        <div className="flex gap-2">
          <button
            onClick={handleScan}
            disabled={scanning}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors flex items-center gap-1 disabled:opacity-50"
          >
            <FontAwesomeIcon icon={faSearch} className={`w-3 h-3 ${scanning ? 'animate-spin' : ''}`} />
            {scanning ? 'Scanning...' : 'Scan'}
          </button>
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Scans for exposed environment variables in page source, window object, and scripts.
      </div>

      <button
        onClick={handleScan}
        disabled={scanning}
        className="w-full rounded bg-orange-600/20 border border-orange-500/30 px-2 py-1.5 text-[11px] text-orange-300 hover:bg-orange-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faSearch} className={`w-3 h-3 ${scanning ? 'animate-spin' : ''}`} />
        {scanning ? 'Scanning...' : 'Scan for Env Variables'}
      </button>

      {error && (
        <div className="text-yellow-400 text-[10px] bg-yellow-900/20 border border-yellow-500/30 p-2 rounded flex items-center gap-2 mb-3">
          <FontAwesomeIcon icon={faExclamationTriangle} className="w-3 h-3" />
          {error}
        </div>
      )}

      {scannedAt && (
        <div className="text-[10px] text-slate-500 mb-2">
          Last scanned: {new Date(scannedAt).toLocaleTimeString()} - Found {findings.length} variable(s)
        </div>
      )}

      {findings.length > 0 && (
        <div className="flex-1 overflow-y-auto space-y-2 min-h-0">
          {findings.map((finding, index) => (
            <div
              key={index}
              className={`p-2 rounded border ${severityColors[finding.severity]}`}
            >
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2">
                  <FontAwesomeIcon icon={faKey} className="w-2.5 h-2.5" />
                  <span className="font-mono text-[10px] text-slate-200 font-medium">{finding.key}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`text-[9px] px-1.5 py-0.5 rounded ${severityBadge[finding.severity]}`}>
                    {finding.severity.toUpperCase()}
                  </span>
                  <button
                    onClick={() => handleCopy(finding)}
                    className="text-[9px] text-slate-500 hover:text-slate-300"
                    title="Copy"
                  >
                    <FontAwesomeIcon icon={copiedKey === finding.key ? faCheckCircle : faCopy} className="w-2.5 h-2.5" />
                  </button>
                </div>
              </div>
              <div className="font-mono text-[10px] bg-black/30 p-1 rounded truncate text-slate-300">
                {finding.value}
              </div>
              <div className="flex items-center justify-between mt-1 text-[10px] text-slate-500">
                <span>Source: {finding.source}</span>
                {finding.description && <span>{finding.description}</span>}
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="text-[10px] text-slate-500 space-y-0.5 border-t border-slate-700 pt-2 mt-3">
        <div><strong>Critical:</strong> Production secrets, database credentials</div>
        <div><strong>High:</strong> API keys, tokens that should be server-side</div>
        <div><strong>Medium:</strong> Configuration that may be intentionally public</div>
        <div><strong>Low:</strong> Public config (NEXT_PUBLIC_, REACT_APP_)</div>
      </div>
    </div>
  );
};

export class EnvVariableScannerTool {
  static Component = EnvVariableScanner;
}
