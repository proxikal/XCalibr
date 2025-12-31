import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSearch, faCopy, faKey, faDatabase, faExclamationTriangle, faTrash } from '@fortawesome/free-solid-svg-icons';

export type StorageFinding = {
  storage: 'localStorage' | 'sessionStorage';
  key: string;
  value: string;
  secretType: string;
  confidence: 'high' | 'medium' | 'low';
};

export type StorageSecretHunterData = {
  findings?: StorageFinding[];
  totalLocalItems?: number;
  totalSessionItems?: number;
  scannedAt?: number;
  error?: string;
};

type Props = {
  data: StorageSecretHunterData | undefined;
  onChange: (data: StorageSecretHunterData) => void;
};

const SECRET_PATTERNS: { name: string; regex: RegExp; confidence: 'high' | 'medium' | 'low' }[] = [
  // High confidence - definite secrets
  { name: 'JWT Token', regex: /^eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*$/, confidence: 'high' },
  { name: 'Bearer Token', regex: /^Bearer\s+[a-zA-Z0-9_\-\.]+$/i, confidence: 'high' },
  { name: 'AWS Access Key', regex: /^AKIA[0-9A-Z]{16}$/, confidence: 'high' },
  { name: 'GitHub Token', regex: /^gh[pousr]_[a-zA-Z0-9]{36,}$/, confidence: 'high' },
  { name: 'Stripe Key', regex: /^(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{24,}$/, confidence: 'high' },
  { name: 'Google API Key', regex: /^AIza[0-9A-Za-z_-]{35}$/, confidence: 'high' },
  { name: 'Slack Token', regex: /^xox[baprs]-[a-zA-Z0-9-]+$/, confidence: 'high' },
  { name: 'Private Key', regex: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/, confidence: 'high' },

  // Medium confidence - likely secrets based on key name patterns
  { name: 'API Key', regex: /^[a-zA-Z0-9_\-]{20,}$/, confidence: 'medium' },
  { name: 'Access Token', regex: /^[a-zA-Z0-9_\-\.]{30,}$/, confidence: 'medium' },

  // Low confidence - could be secrets
  { name: 'Possible Secret', regex: /^[a-zA-Z0-9+/=]{16,}$/, confidence: 'low' }
];

const SECRET_KEY_PATTERNS = [
  /token/i, /secret/i, /key/i, /api[_-]?key/i, /auth/i, /password/i, /passwd/i,
  /credential/i, /access/i, /bearer/i, /jwt/i, /session/i, /cookie/i, /private/i
];

const StorageSecretHunter: React.FC<Props> = ({ data, onChange }) => {
  const findings = data?.findings ?? [];
  const totalLocalItems = data?.totalLocalItems ?? 0;
  const totalSessionItems = data?.totalSessionItems ?? 0;
  const scannedAt = data?.scannedAt;
  const error = data?.error;
  const [scanning, setScanning] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [showValues, setShowValues] = useState(false);

  const detectSecretType = (key: string, value: string): { type: string; confidence: 'high' | 'medium' | 'low' } | null => {
    // First check if key name suggests a secret
    const keyIsSecretLike = SECRET_KEY_PATTERNS.some(pattern => pattern.test(key));

    // Check value against patterns
    for (const pattern of SECRET_PATTERNS) {
      if (pattern.regex.test(value)) {
        return { type: pattern.name, confidence: pattern.confidence };
      }
    }

    // If key suggests a secret but value didn't match high patterns
    if (keyIsSecretLike && value.length >= 8) {
      return { type: 'Possible Secret (key-based)', confidence: 'medium' };
    }

    return null;
  };

  const scanStorage = () => {
    setScanning(true);
    try {
      const foundSecrets: StorageFinding[] = [];

      // Scan localStorage
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (!key) continue;
        const value = localStorage.getItem(key) || '';

        const secretInfo = detectSecretType(key, value);
        if (secretInfo) {
          foundSecrets.push({
            storage: 'localStorage',
            key,
            value: value.substring(0, 500),
            secretType: secretInfo.type,
            confidence: secretInfo.confidence
          });
        }
      }

      // Scan sessionStorage
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (!key) continue;
        const value = sessionStorage.getItem(key) || '';

        const secretInfo = detectSecretType(key, value);
        if (secretInfo) {
          foundSecrets.push({
            storage: 'sessionStorage',
            key,
            value: value.substring(0, 500),
            secretType: secretInfo.type,
            confidence: secretInfo.confidence
          });
        }
      }

      // Sort by confidence
      foundSecrets.sort((a, b) => {
        const order = { high: 0, medium: 1, low: 2 };
        return order[a.confidence] - order[b.confidence];
      });

      onChange({
        findings: foundSecrets,
        totalLocalItems: localStorage.length,
        totalSessionItems: sessionStorage.length,
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

  const deleteItem = (finding: StorageFinding, index: number) => {
    if (finding.storage === 'localStorage') {
      localStorage.removeItem(finding.key);
    } else {
      sessionStorage.removeItem(finding.key);
    }

    const updatedFindings = findings.filter((_, i) => i !== index);
    onChange({
      ...data,
      findings: updatedFindings,
      totalLocalItems: localStorage.length,
      totalSessionItems: sessionStorage.length
    });
  };

  const getConfidenceColor = (confidence: string) => {
    switch (confidence) {
      case 'high': return 'text-red-400 bg-red-900/30 border-red-700/50';
      case 'medium': return 'text-yellow-400 bg-yellow-900/30 border-yellow-700/50';
      case 'low': return 'text-blue-400 bg-blue-900/30 border-blue-700/50';
      default: return 'text-slate-400 bg-slate-900/30 border-slate-700';
    }
  };

  const highConfidence = findings.filter(f => f.confidence === 'high');
  const mediumConfidence = findings.filter(f => f.confidence === 'medium');
  const lowConfidence = findings.filter(f => f.confidence === 'low');

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Storage Secret Hunter</div>
        <div className="flex gap-2">
          {scannedAt && (
            <label className="flex items-center gap-1.5 text-[10px] text-slate-400">
              <input
                type="checkbox"
                checked={showValues}
                onChange={(e) => setShowValues(e.target.checked)}
                className="rounded bg-slate-700 border-slate-600 w-3 h-3"
              />
              Show values
            </label>
          )}
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Scans localStorage and sessionStorage for secrets, tokens, API keys, and sensitive data.
      </div>

      <button
        onClick={scanStorage}
        disabled={scanning}
        className="w-full rounded bg-red-600/20 border border-red-500/30 px-2 py-1.5 text-[11px] text-red-300 hover:bg-red-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faSearch} className="w-3 h-3" />
        {scanning ? 'Scanning...' : 'Hunt for Secrets'}
      </button>

      {error && (
        <div className="text-red-400 text-[10px] bg-red-900/20 border border-red-700/50 p-2 rounded mb-3">
          {error}
        </div>
      )}

      {/* Statistics */}
      {scannedAt && (
        <div className="grid grid-cols-2 gap-2 mb-3">
          <div className="rounded border border-slate-700 bg-slate-800/50 p-2 text-center">
            <div className="flex items-center justify-center gap-2">
              <FontAwesomeIcon icon={faDatabase} className="text-blue-400 w-2.5 h-2.5" />
              <span className="text-slate-200 font-bold text-[11px]">{totalLocalItems}</span>
            </div>
            <div className="text-[10px] text-slate-500">localStorage</div>
          </div>
          <div className="rounded border border-slate-700 bg-slate-800/50 p-2 text-center">
            <div className="flex items-center justify-center gap-2">
              <FontAwesomeIcon icon={faDatabase} className="text-purple-400 w-2.5 h-2.5" />
              <span className="text-slate-200 font-bold text-[11px]">{totalSessionItems}</span>
            </div>
            <div className="text-[10px] text-slate-500">sessionStorage</div>
          </div>
        </div>
      )}

      {/* Summary */}
      {scannedAt && findings.length > 0 && (
        <div className="bg-red-900/20 border border-red-700/50 rounded p-2 mb-3">
          <div className="flex items-center gap-2 text-red-400 font-medium text-[11px]">
            <FontAwesomeIcon icon={faExclamationTriangle} className="w-3 h-3" />
            Found {findings.length} potential secret(s)
          </div>
          <div className="text-[10px] text-slate-400 mt-1">
            {highConfidence.length > 0 && <span className="text-red-400 mr-2">{highConfidence.length} high</span>}
            {mediumConfidence.length > 0 && <span className="text-yellow-400 mr-2">{mediumConfidence.length} medium</span>}
            {lowConfidence.length > 0 && <span className="text-blue-400">{lowConfidence.length} low</span>}
          </div>
        </div>
      )}

      {/* Findings */}
      <div className="flex-1 overflow-y-auto space-y-2 min-h-0">
        {findings.length > 0 ? (
          findings.map((finding, idx) => (
            <div key={idx} className={`rounded border p-2 ${getConfidenceColor(finding.confidence)}`}>
              <div className="flex justify-between items-start">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <FontAwesomeIcon icon={faKey} className="w-2.5 h-2.5" />
                    <span className="font-medium text-[11px] break-all">{finding.key}</span>
                    <span className={`text-[9px] px-1.5 py-0.5 rounded ${
                      finding.storage === 'localStorage' ? 'bg-blue-900/50 text-blue-300' : 'bg-purple-900/50 text-purple-300'
                    }`}>
                      {finding.storage}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                      {finding.secretType}
                    </span>
                    <span className={`text-[9px] px-1.5 py-0.5 rounded ${
                      finding.confidence === 'high' ? 'bg-red-800/50' :
                      finding.confidence === 'medium' ? 'bg-yellow-800/50' : 'bg-blue-800/50'
                    }`}>
                      {finding.confidence}
                    </span>
                  </div>
                  {showValues && (
                    <div className="text-[10px] font-mono mt-2 break-all bg-slate-900/50 p-1 rounded text-slate-400">
                      {finding.value.length > 100 ? finding.value.substring(0, 100) + '...' : finding.value}
                    </div>
                  )}
                </div>
                <div className="flex gap-1 ml-2 flex-shrink-0">
                  <button
                    onClick={() => copyToClipboard(finding.value, idx)}
                    className="text-[9px] text-slate-500 hover:text-slate-300 p-1"
                    title="Copy value"
                  >
                    <FontAwesomeIcon icon={faCopy} className="w-2.5 h-2.5" />
                  </button>
                  <button
                    onClick={() => deleteItem(finding, idx)}
                    className="text-[9px] text-slate-500 hover:text-rose-400 p-1"
                    title="Delete from storage"
                  >
                    <FontAwesomeIcon icon={faTrash} className="w-2.5 h-2.5" />
                  </button>
                </div>
              </div>
              {copiedIndex === idx && (
                <span className="text-green-400 text-[10px]">Copied!</span>
              )}
            </div>
          ))
        ) : scannedAt ? (
          <div className="text-[11px] text-green-400 text-center py-4">
            No secrets detected in storage.
          </div>
        ) : (
          <div className="text-[11px] text-slate-500 text-center py-4">
            Click "Hunt for Secrets" to scan storage.
          </div>
        )}
      </div>

      {scannedAt && (
        <div className="text-[10px] text-slate-500 mt-3 pt-2 border-t border-slate-700">
          Last scanned: {new Date(scannedAt).toLocaleTimeString()}
        </div>
      )}

      <div className="text-[10px] text-slate-500 border-t border-slate-700 pt-2 mt-2">
        <div><strong>Detected patterns:</strong></div>
        <div className="text-slate-600">JWTs, API keys, access tokens, OAuth tokens, AWS keys, private keys</div>
      </div>
    </div>
  );
};

export class StorageSecretHunterTool {
  static Component = StorageSecretHunter;
}
