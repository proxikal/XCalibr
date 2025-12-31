import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faSearch, faCopy, faKey, faDatabase, faExclamationTriangle, faTrash, faDownload, faFilter } from '@fortawesome/free-solid-svg-icons';

export type StorageType = 'localStorage' | 'sessionStorage' | 'indexedDB' | 'cacheAPI' | 'cookie';

export type StorageFinding = {
  storage: StorageType;
  key: string;
  value: string;
  secretType: string;
  confidence: 'high' | 'medium' | 'low';
  entropy?: number;
  dbName?: string;
  storeName?: string;
};

export type StorageSecretHunterData = {
  findings?: StorageFinding[];
  totalLocalItems?: number;
  totalSessionItems?: number;
  totalIndexedDBItems?: number;
  totalCacheItems?: number;
  totalCookies?: number;
  scannedAt?: number;
  error?: string;
  filterStorage?: StorageType | 'all';
  filterConfidence?: 'all' | 'high' | 'medium';
};

type Props = {
  data: StorageSecretHunterData | undefined;
  onChange: (data: StorageSecretHunterData) => void;
};

// Comprehensive secret patterns - 50+ patterns
const SECRET_PATTERNS: { name: string; regex: RegExp; confidence: 'high' | 'medium' | 'low' }[] = [
  // === HIGH CONFIDENCE - Definite Secrets ===
  // JWT/Auth Tokens
  { name: 'JWT Token', regex: /^eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*$/, confidence: 'high' },
  { name: 'Bearer Token', regex: /^Bearer\s+[a-zA-Z0-9_\-\.]{20,}$/i, confidence: 'high' },
  { name: 'OAuth Access Token', regex: /^ya29\.[a-zA-Z0-9_-]{50,}$/, confidence: 'high' },
  { name: 'OAuth Refresh Token', regex: /^1\/\/[a-zA-Z0-9_-]{40,}$/, confidence: 'high' },

  // Cloud Provider Keys
  { name: 'AWS Access Key', regex: /^AKIA[0-9A-Z]{16}$/, confidence: 'high' },
  { name: 'AWS Secret Key', regex: /^[a-zA-Z0-9+\/]{40}$/, confidence: 'high' },
  { name: 'AWS Session Token', regex: /^FwoGZXIvYXdz[a-zA-Z0-9\/+=]{100,}$/, confidence: 'high' },
  { name: 'Azure Storage Key', regex: /^[a-zA-Z0-9+\/]{86}==$/, confidence: 'high' },
  { name: 'Azure SAS Token', regex: /^sv=\d{4}-\d{2}-\d{2}&s[a-z]=/, confidence: 'high' },
  { name: 'GCP API Key', regex: /^AIza[0-9A-Za-z_-]{35}$/, confidence: 'high' },
  { name: 'GCP Service Account', regex: /"type":\s*"service_account"/, confidence: 'high' },

  // Version Control & CI/CD
  { name: 'GitHub Token', regex: /^gh[pousr]_[a-zA-Z0-9]{36,}$/, confidence: 'high' },
  { name: 'GitHub OAuth', regex: /^gho_[a-zA-Z0-9]{36,}$/, confidence: 'high' },
  { name: 'GitLab Token', regex: /^glpat-[a-zA-Z0-9_-]{20,}$/, confidence: 'high' },
  { name: 'Bitbucket Token', regex: /^[a-zA-Z0-9]{32}$/, confidence: 'high' },
  { name: 'CircleCI Token', regex: /^[a-f0-9]{40}$/, confidence: 'high' },
  { name: 'Travis CI Token', regex: /^[a-zA-Z0-9]{22}$/, confidence: 'high' },

  // Payment & Financial
  { name: 'Stripe Secret Key', regex: /^sk_(?:live|test)_[a-zA-Z0-9]{24,}$/, confidence: 'high' },
  { name: 'Stripe Publishable Key', regex: /^pk_(?:live|test)_[a-zA-Z0-9]{24,}$/, confidence: 'high' },
  { name: 'PayPal Token', regex: /^access_token\$production\$[a-z0-9]{13}\$[a-f0-9]{32}$/, confidence: 'high' },
  { name: 'Square Access Token', regex: /^sq0atp-[a-zA-Z0-9_-]{22}$/, confidence: 'high' },
  { name: 'Square OAuth Secret', regex: /^sq0csp-[a-zA-Z0-9_-]{43}$/, confidence: 'high' },

  // Communication & Messaging
  { name: 'Slack Token', regex: /^xox[baprs]-[a-zA-Z0-9-]+$/, confidence: 'high' },
  { name: 'Slack Webhook', regex: /^https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+$/, confidence: 'high' },
  { name: 'Discord Token', regex: /^[MN][a-zA-Z0-9]{23,28}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}$/, confidence: 'high' },
  { name: 'Discord Webhook', regex: /^https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[a-zA-Z0-9_-]+$/, confidence: 'high' },
  { name: 'Twilio API Key', regex: /^SK[a-f0-9]{32}$/, confidence: 'high' },
  { name: 'SendGrid API Key', regex: /^SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}$/, confidence: 'high' },
  { name: 'Mailchimp API Key', regex: /^[a-f0-9]{32}-us\d+$/, confidence: 'high' },
  { name: 'Mailgun API Key', regex: /^key-[a-f0-9]{32}$/, confidence: 'high' },

  // Database & Storage
  { name: 'MongoDB URI', regex: /^mongodb(\+srv)?:\/\/[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@/, confidence: 'high' },
  { name: 'PostgreSQL URI', regex: /^postgres(?:ql)?:\/\/[a-zA-Z0-9_-]+:[^@]+@/, confidence: 'high' },
  { name: 'MySQL URI', regex: /^mysql:\/\/[a-zA-Z0-9_-]+:[^@]+@/, confidence: 'high' },
  { name: 'Redis URI', regex: /^redis:\/\/:[^@]+@/, confidence: 'high' },
  { name: 'Firebase Key', regex: /^[a-zA-Z0-9_-]{40}$/, confidence: 'high' },

  // Crypto & Private Keys
  { name: 'RSA Private Key', regex: /-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----/, confidence: 'high' },
  { name: 'Private Key', regex: /-----BEGIN\s+PRIVATE\s+KEY-----/, confidence: 'high' },
  { name: 'EC Private Key', regex: /-----BEGIN\s+EC\s+PRIVATE\s+KEY-----/, confidence: 'high' },
  { name: 'PGP Private Key', regex: /-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/, confidence: 'high' },
  { name: 'SSH Private Key', regex: /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/, confidence: 'high' },

  // Analytics & Monitoring
  { name: 'Datadog API Key', regex: /^[a-f0-9]{32}$/, confidence: 'high' },
  { name: 'Sentry DSN', regex: /^https:\/\/[a-f0-9]{32}@[a-z0-9.]+\.ingest\.sentry\.io\/\d+$/, confidence: 'high' },
  { name: 'New Relic Key', regex: /^NRAK-[A-Z0-9]{27}$/, confidence: 'high' },
  { name: 'Algolia API Key', regex: /^[a-f0-9]{32}$/, confidence: 'high' },

  // Social & OAuth
  { name: 'Facebook Access Token', regex: /^EAA[a-zA-Z0-9]+$/, confidence: 'high' },
  { name: 'Twitter Bearer Token', regex: /^AAAA[a-zA-Z0-9%]+$/, confidence: 'high' },
  { name: 'LinkedIn Token', regex: /^AQV[a-zA-Z0-9_-]+$/, confidence: 'high' },

  // Other Services
  { name: 'Heroku API Key', regex: /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/, confidence: 'high' },
  { name: 'Dropbox Token', regex: /^sl\.[a-zA-Z0-9_-]{100,}$/, confidence: 'high' },
  { name: 'Shopify Token', regex: /^shpat_[a-f0-9]{32}$/, confidence: 'high' },
  { name: 'NPM Token', regex: /^npm_[a-zA-Z0-9]{36}$/, confidence: 'high' },

  // === MEDIUM CONFIDENCE ===
  { name: 'Generic API Key', regex: /^[a-zA-Z0-9_\-]{32,64}$/, confidence: 'medium' },
  { name: 'Access Token', regex: /^[a-zA-Z0-9_\-\.]{40,}$/, confidence: 'medium' },
  { name: 'Session ID', regex: /^[a-f0-9]{32,64}$/, confidence: 'medium' },
  { name: 'UUID Token', regex: /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/, confidence: 'medium' },

  // === LOW CONFIDENCE ===
  { name: 'Base64 Secret', regex: /^[a-zA-Z0-9+/=]{20,}$/, confidence: 'low' },
  { name: 'Hex String', regex: /^[a-fA-F0-9]{16,}$/, confidence: 'low' }
];

const SECRET_KEY_PATTERNS = [
  /token/i, /secret/i, /key/i, /api[_-]?key/i, /auth/i, /password/i, /passwd/i,
  /credential/i, /access/i, /bearer/i, /jwt/i, /session/i, /cookie/i, /private/i,
  /apikey/i, /api_secret/i, /client_secret/i, /oauth/i, /refresh/i, /id_token/i,
  /access_token/i, /auth_token/i, /x-api-key/i, /authorization/i
];

const STORAGE_COLORS: Record<StorageType, { bg: string; text: string; label: string }> = {
  localStorage: { bg: 'bg-blue-900/50', text: 'text-blue-300', label: 'Local' },
  sessionStorage: { bg: 'bg-purple-900/50', text: 'text-purple-300', label: 'Session' },
  indexedDB: { bg: 'bg-green-900/50', text: 'text-green-300', label: 'IndexedDB' },
  cacheAPI: { bg: 'bg-orange-900/50', text: 'text-orange-300', label: 'Cache' },
  cookie: { bg: 'bg-yellow-900/50', text: 'text-yellow-300', label: 'Cookie' }
};

// Calculate Shannon entropy
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

const StorageSecretHunter: React.FC<Props> = ({ data, onChange }) => {
  const findings = data?.findings ?? [];
  const totalLocalItems = data?.totalLocalItems ?? 0;
  const totalSessionItems = data?.totalSessionItems ?? 0;
  const totalIndexedDBItems = data?.totalIndexedDBItems ?? 0;
  const totalCacheItems = data?.totalCacheItems ?? 0;
  const totalCookies = data?.totalCookies ?? 0;
  const scannedAt = data?.scannedAt;
  const error = data?.error;
  const filterStorage = data?.filterStorage ?? 'all';
  const filterConfidence = data?.filterConfidence ?? 'all';
  const [scanning, setScanning] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [showValues, setShowValues] = useState(false);

  const detectSecretType = (key: string, value: string): { type: string; confidence: 'high' | 'medium' | 'low'; entropy: number } | null => {
    const entropy = calculateEntropy(value);
    const keyIsSecretLike = SECRET_KEY_PATTERNS.some(pattern => pattern.test(key));

    // Check value against patterns
    for (const pattern of SECRET_PATTERNS) {
      if (pattern.regex.test(value)) {
        return { type: pattern.name, confidence: pattern.confidence, entropy };
      }
    }

    // If key suggests a secret and has high entropy
    if (keyIsSecretLike && value.length >= 8 && entropy > 3.5) {
      return { type: 'Possible Secret (key-based)', confidence: 'medium', entropy };
    }

    // High entropy strings with secret-like keys
    if (keyIsSecretLike && value.length >= 16 && entropy > 4.0) {
      return { type: 'High Entropy Secret', confidence: 'medium', entropy };
    }

    return null;
  };

  const scanIndexedDB = async (): Promise<{ findings: StorageFinding[]; count: number }> => {
    const dbFindings: StorageFinding[] = [];
    let totalCount = 0;

    try {
      const databases = await indexedDB.databases();

      for (const dbInfo of databases) {
        if (!dbInfo.name) continue;

        try {
          const db = await new Promise<IDBDatabase>((resolve, reject) => {
            const request = indexedDB.open(dbInfo.name!);
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
          });

          const storeNames = Array.from(db.objectStoreNames);

          for (const storeName of storeNames) {
            try {
              const transaction = db.transaction(storeName, 'readonly');
              const store = transaction.objectStore(storeName);

              const items = await new Promise<unknown[]>((resolve, reject) => {
                const request = store.getAll();
                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve(request.result);
              });

              totalCount += items.length;

              for (const item of items) {
                const itemStr = typeof item === 'string' ? item : JSON.stringify(item);

                // Scan the stringified item for secrets
                const secretInfo = detectSecretType(storeName, itemStr);
                if (secretInfo) {
                  dbFindings.push({
                    storage: 'indexedDB',
                    key: storeName,
                    value: itemStr.substring(0, 500),
                    secretType: secretInfo.type,
                    confidence: secretInfo.confidence,
                    entropy: secretInfo.entropy,
                    dbName: dbInfo.name,
                    storeName
                  });
                }
              }
            } catch {
              // Skip inaccessible stores
            }
          }

          db.close();
        } catch {
          // Skip inaccessible databases
        }
      }
    } catch {
      // IndexedDB not available
    }

    return { findings: dbFindings, count: totalCount };
  };

  const scanCacheAPI = async (): Promise<{ findings: StorageFinding[]; count: number }> => {
    const cacheFindings: StorageFinding[] = [];
    let totalCount = 0;

    try {
      const cacheNames = await caches.keys();

      for (const cacheName of cacheNames) {
        try {
          const cache = await caches.open(cacheName);
          const requests = await cache.keys();
          totalCount += requests.length;

          for (const request of requests) {
            const url = request.url;

            // Check URL for secrets in query params
            const urlSecretInfo = detectSecretType('cache-url', url);
            if (urlSecretInfo) {
              cacheFindings.push({
                storage: 'cacheAPI',
                key: cacheName,
                value: url.substring(0, 500),
                secretType: urlSecretInfo.type,
                confidence: urlSecretInfo.confidence,
                entropy: urlSecretInfo.entropy
              });
            }
          }
        } catch {
          // Skip inaccessible caches
        }
      }
    } catch {
      // Cache API not available
    }

    return { findings: cacheFindings, count: totalCount };
  };

  const scanCookies = (): { findings: StorageFinding[]; count: number } => {
    const cookieFindings: StorageFinding[] = [];
    const cookies = document.cookie.split(';').filter(c => c.trim());

    for (const cookie of cookies) {
      const [name, ...valueParts] = cookie.trim().split('=');
      const value = valueParts.join('=');

      const secretInfo = detectSecretType(name, value);
      if (secretInfo) {
        cookieFindings.push({
          storage: 'cookie',
          key: name,
          value: value.substring(0, 500),
          secretType: secretInfo.type,
          confidence: secretInfo.confidence,
          entropy: secretInfo.entropy
        });
      }
    }

    return { findings: cookieFindings, count: cookies.length };
  };

  const scanStorage = async () => {
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
            confidence: secretInfo.confidence,
            entropy: secretInfo.entropy
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
            confidence: secretInfo.confidence,
            entropy: secretInfo.entropy
          });
        }
      }

      // Scan IndexedDB
      const indexedDBResult = await scanIndexedDB();
      foundSecrets.push(...indexedDBResult.findings);

      // Scan Cache API
      const cacheResult = await scanCacheAPI();
      foundSecrets.push(...cacheResult.findings);

      // Scan Cookies
      const cookieResult = scanCookies();
      foundSecrets.push(...cookieResult.findings);

      // Sort by confidence then entropy
      foundSecrets.sort((a, b) => {
        const order = { high: 0, medium: 1, low: 2 };
        const confDiff = order[a.confidence] - order[b.confidence];
        if (confDiff !== 0) return confDiff;
        return (b.entropy || 0) - (a.entropy || 0);
      });

      onChange({
        findings: foundSecrets,
        totalLocalItems: localStorage.length,
        totalSessionItems: sessionStorage.length,
        totalIndexedDBItems: indexedDBResult.count,
        totalCacheItems: cacheResult.count,
        totalCookies: cookieResult.count,
        scannedAt: Date.now(),
        error: undefined,
        filterStorage,
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

  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 1500);
  };

  const deleteItem = (finding: StorageFinding, index: number) => {
    if (finding.storage === 'localStorage') {
      localStorage.removeItem(finding.key);
    } else if (finding.storage === 'sessionStorage') {
      sessionStorage.removeItem(finding.key);
    } else if (finding.storage === 'cookie') {
      document.cookie = `${finding.key}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
    }
    // Note: IndexedDB and CacheAPI deletion would require more complex handling

    const updatedFindings = findings.filter((_, i) => i !== index);
    onChange({
      ...data,
      findings: updatedFindings,
      totalLocalItems: localStorage.length,
      totalSessionItems: sessionStorage.length
    });
  };

  const exportAsJson = () => {
    const exportData = {
      url: window.location.href,
      scannedAt: scannedAt ? new Date(scannedAt).toISOString() : null,
      summary: {
        totalFindings: findings.length,
        highConfidence: findings.filter(f => f.confidence === 'high').length,
        mediumConfidence: findings.filter(f => f.confidence === 'medium').length,
        lowConfidence: findings.filter(f => f.confidence === 'low').length,
        storageStats: {
          localStorage: totalLocalItems,
          sessionStorage: totalSessionItems,
          indexedDB: totalIndexedDBItems,
          cacheAPI: totalCacheItems,
          cookies: totalCookies
        }
      },
      findings: filteredFindings
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `storage-secrets-${window.location.hostname}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getConfidenceColor = (confidence: string) => {
    switch (confidence) {
      case 'high': return 'text-red-400 bg-red-900/30 border-red-700/50';
      case 'medium': return 'text-yellow-400 bg-yellow-900/30 border-yellow-700/50';
      case 'low': return 'text-blue-400 bg-blue-900/30 border-blue-700/50';
      default: return 'text-slate-400 bg-slate-900/30 border-slate-700';
    }
  };

  // Apply filters
  const filteredFindings = findings.filter(f => {
    if (filterStorage !== 'all' && f.storage !== filterStorage) return false;
    if (filterConfidence === 'high' && f.confidence !== 'high') return false;
    if (filterConfidence === 'medium' && f.confidence === 'low') return false;
    return true;
  });

  const highConfidence = filteredFindings.filter(f => f.confidence === 'high');
  const mediumConfidence = filteredFindings.filter(f => f.confidence === 'medium');
  const lowConfidence = filteredFindings.filter(f => f.confidence === 'low');

  const storageCounts = findings.reduce((acc, f) => {
    acc[f.storage] = (acc[f.storage] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="flex flex-col h-full text-xs">
      <div className="flex items-center justify-between mb-2">
        <div className="text-slate-200 font-medium">Storage Secret Hunter</div>
        <div className="flex gap-1 items-center">
          {scannedAt && findings.length > 0 && (
            <button
              onClick={exportAsJson}
              className="rounded bg-slate-800 px-1.5 py-0.5 text-[9px] text-slate-300 hover:bg-slate-700 transition-colors"
              title="Export as JSON"
            >
              <FontAwesomeIcon icon={faDownload} className="w-2 h-2" />
            </button>
          )}
          {scannedAt && (
            <label className="flex items-center gap-1 text-[9px] text-slate-400 ml-1">
              <input
                type="checkbox"
                checked={showValues}
                onChange={(e) => setShowValues(e.target.checked)}
                className="rounded bg-slate-700 border-slate-600 w-2.5 h-2.5"
              />
              Values
            </label>
          )}
        </div>
      </div>

      <div className="text-[9px] text-slate-500 mb-2">
        Scan all browser storage for secrets (50+ patterns)
      </div>

      <button
        onClick={scanStorage}
        disabled={scanning}
        className="w-full rounded bg-red-600/20 border border-red-500/30 px-2 py-1 text-[10px] text-red-300 hover:bg-red-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-1.5 mb-2"
      >
        <FontAwesomeIcon icon={faSearch} className="w-2.5 h-2.5" />
        {scanning ? 'Scanning...' : 'Hunt for Secrets'}
      </button>

      {error && (
        <div className="text-red-400 text-[9px] bg-red-900/20 border border-red-700/50 p-1.5 rounded mb-2">
          {error}
        </div>
      )}

      {/* Statistics - Compact with full labels */}
      {scannedAt && (
        <div className="flex gap-1 mb-2">
          {[
            { color: 'blue', count: totalLocalItems, label: 'Local' },
            { color: 'purple', count: totalSessionItems, label: 'Session' },
            { color: 'green', count: totalIndexedDBItems, label: 'IndexedDB' },
            { color: 'orange', count: totalCacheItems, label: 'Cache' },
            { color: 'yellow', count: totalCookies, label: 'Cookies' }
          ].map((stat, idx) => (
            <div key={idx} className="flex-1 rounded border border-slate-700 bg-slate-800/50 px-1.5 py-0.5 text-center">
              <span className={`text-${stat.color}-400 font-bold text-[9px]`}>{stat.count}</span>
              <span className="text-[8px] text-slate-500 ml-1">{stat.label}</span>
            </div>
          ))}
        </div>
      )}

      {/* Filters - Full labels, always show all storage types */}
      {scannedAt && findings.length > 0 && (
        <div className="flex flex-wrap items-center gap-1 mb-2">
          <FontAwesomeIcon icon={faFilter} className="w-2.5 h-2.5 text-slate-500" />
          {(['all', 'localStorage', 'sessionStorage', 'indexedDB', 'cookie'] as const).map(storage => {
            const count = storage === 'all' ? findings.length : (storageCounts[storage] || 0);
            const hasFindings = count > 0;
            return (
              <button
                key={storage}
                onClick={() => onChange({ ...data, filterStorage: storage })}
                disabled={storage !== 'all' && !hasFindings}
                className={`px-1.5 py-0.5 rounded text-[8px] transition-colors ${
                  filterStorage === storage
                    ? 'bg-red-600/30 text-red-300 border border-red-500/50'
                    : hasFindings || storage === 'all'
                      ? 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-500'
                      : 'bg-slate-800/50 text-slate-600 border border-slate-700/50 cursor-not-allowed'
                }`}
              >
                {storage === 'all' ? 'All' : STORAGE_COLORS[storage]?.label || storage}
              </button>
            );
          })}
          <span className="text-slate-600 text-[9px] mx-0.5">|</span>
          {(['all', 'high', 'medium'] as const).map(conf => (
            <button
              key={conf}
              onClick={() => onChange({ ...data, filterConfidence: conf })}
              className={`px-1.5 py-0.5 rounded text-[8px] transition-colors ${
                filterConfidence === conf
                  ? 'bg-red-600/30 text-red-300 border border-red-500/50'
                  : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-500'
              }`}
            >
              {conf === 'all' ? 'All' : conf.charAt(0).toUpperCase() + conf.slice(1)}+
            </button>
          ))}
        </div>
      )}

      {/* Summary - Compact single line */}
      {scannedAt && filteredFindings.length > 0 && (
        <div className="flex items-center gap-2 bg-red-900/20 border border-red-700/50 rounded px-2 py-1.5 mb-2">
          <FontAwesomeIcon icon={faExclamationTriangle} className="w-3 h-3 text-red-400 flex-shrink-0" />
          <span className="text-red-400 font-medium text-[10px]">Found {filteredFindings.length}</span>
          <span className="text-slate-500 text-[9px]">|</span>
          {highConfidence.length > 0 && <span className="text-red-400 text-[9px]">{highConfidence.length}H</span>}
          {mediumConfidence.length > 0 && <span className="text-yellow-400 text-[9px]">{mediumConfidence.length}M</span>}
          {lowConfidence.length > 0 && <span className="text-blue-400 text-[9px]">{lowConfidence.length}L</span>}
        </div>
      )}

      {/* Findings */}
      <div className="flex-1 overflow-y-auto space-y-2 min-h-0">
        {filteredFindings.length > 0 ? (
          filteredFindings.map((finding, idx) => (
            <div key={idx} className={`rounded border p-2 ${getConfidenceColor(finding.confidence)}`}>
              <div className="flex justify-between items-start">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <FontAwesomeIcon icon={faKey} className="w-2.5 h-2.5" />
                    <span className="font-medium text-[10px] break-all">{finding.key}</span>
                    <span className={`text-[8px] px-1 py-0.5 rounded ${STORAGE_COLORS[finding.storage].bg} ${STORAGE_COLORS[finding.storage].text}`}>
                      {STORAGE_COLORS[finding.storage].label}
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5 mt-1 flex-wrap">
                    <span className="text-[8px] px-1 py-0.5 rounded bg-slate-800 text-slate-300">
                      {finding.secretType}
                    </span>
                    <span className={`text-[8px] px-1 py-0.5 rounded ${
                      finding.confidence === 'high' ? 'bg-red-800/50 text-red-300' :
                      finding.confidence === 'medium' ? 'bg-yellow-800/50 text-yellow-300' : 'bg-blue-800/50 text-blue-300'
                    }`}>
                      {finding.confidence}
                    </span>
                    {finding.entropy !== undefined && (
                      <span className="text-[8px] px-1 py-0.5 rounded bg-slate-700 text-slate-400">
                        H: {finding.entropy.toFixed(2)}
                      </span>
                    )}
                  </div>
                  {finding.dbName && (
                    <div className="text-[8px] text-slate-500 mt-1">
                      DB: {finding.dbName} / {finding.storeName}
                    </div>
                  )}
                  {showValues && (
                    <div className="text-[9px] font-mono mt-2 break-all bg-slate-900/50 p-1 rounded text-slate-400">
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
                  {(finding.storage === 'localStorage' || finding.storage === 'sessionStorage' || finding.storage === 'cookie') && (
                    <button
                      onClick={() => deleteItem(finding, idx)}
                      className="text-[9px] text-slate-500 hover:text-rose-400 p-1"
                      title="Delete from storage"
                    >
                      <FontAwesomeIcon icon={faTrash} className="w-2.5 h-2.5" />
                    </button>
                  )}
                </div>
              </div>
              {copiedIndex === idx && (
                <span className="text-green-400 text-[9px]">Copied!</span>
              )}
            </div>
          ))
        ) : scannedAt ? (
          <div className="text-[11px] text-green-400 text-center py-4">
            No secrets detected in storage.
          </div>
        ) : (
          <div className="text-[11px] text-slate-500 text-center py-4">
            Click "Hunt for Secrets" to scan all storage.
          </div>
        )}
      </div>

      {/* Footer - Compact */}
      <div className="flex items-center justify-between text-[8px] text-slate-500 mt-2 pt-1 border-t border-slate-700">
        {scannedAt && <span>Scanned: {new Date(scannedAt).toLocaleTimeString()}</span>}
        <span className="text-slate-600">50+ patterns</span>
      </div>
    </div>
  );
};

export class StorageSecretHunterTool {
  static Component = StorageSecretHunter;
}
