import React, { useState, useRef, useCallback } from 'react';
import type { JwtCrackerData } from './tool-types';

const COMMON_SECRETS = [
  'secret',
  'password',
  '123456',
  'admin',
  'jwt',
  'token',
  'key',
  'private',
  'public',
  'test',
  'development',
  'production',
  'supersecret',
  'mypassword',
  'changeme',
  'letmein',
  'welcome',
  'qwerty',
  'default',
  'guest',
  'root',
  'master',
  'example',
  'demo',
  'jwt_secret',
  'auth_secret',
  'api_key',
  'secret_key',
  'signing_key',
  'HS256',
  'your-256-bit-secret',
  'your-384-bit-secret',
  'your-512-bit-secret',
  'gZH75aKtMN3Yj0iPS7eEW5v1Qb3cF8uXp',
  'shhhhh',
  'shhhhhared-secret'
];

const parseJwt = (token: string): { header: Record<string, unknown>; payload: Record<string, unknown>; signature: string } | null => {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    return { header, payload, signature: parts[2] };
  } catch {
    return null;
  }
};

const getAlgorithm = (token: string): string | null => {
  const parsed = parseJwt(token);
  return parsed?.header?.alg as string || null;
};

const base64UrlEncode = (data: ArrayBuffer): string => {
  const bytes = new Uint8Array(data);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const verifySignature = async (
  token: string,
  secret: string,
  algorithm: 'HS256' | 'HS384' | 'HS512'
): Promise<boolean> => {
  const parts = token.split('.');
  if (parts.length !== 3) return false;

  const signingInput = `${parts[0]}.${parts[1]}`;
  const signature = parts[2];

  const algorithmMap: Record<string, string> = {
    HS256: 'SHA-256',
    HS384: 'SHA-384',
    HS512: 'SHA-512'
  };

  try {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: algorithmMap[algorithm] },
      false,
      ['sign']
    );

    const signatureBuffer = await crypto.subtle.sign('HMAC', key, encoder.encode(signingInput));
    const computedSignature = base64UrlEncode(signatureBuffer);

    return computedSignature === signature;
  } catch {
    return false;
  }
};

type Props = {
  data: JwtCrackerData | undefined;
  onChange: (next: JwtCrackerData) => void;
};

const JwtCrackerToolComponent = ({ data, onChange }: Props) => {
  const token = data?.token ?? '';
  const wordlist = data?.wordlist ?? '';
  const cracking = data?.cracking ?? false;
  const progress = data?.progress ?? 0;
  const foundSecret = data?.foundSecret ?? '';
  const cracked = data?.cracked ?? false;
  const error = data?.error ?? '';

  const [copied, setCopied] = useState(false);
  const abortRef = useRef<boolean>(false);

  const detectedAlgorithm = token ? getAlgorithm(token) : null;
  const isValidJwt = token ? parseJwt(token) !== null : true;
  const isHmacAlgorithm = detectedAlgorithm?.startsWith('HS');

  const handleCopy = useCallback(() => {
    if (foundSecret) {
      navigator.clipboard.writeText(foundSecret);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  }, [foundSecret]);

  const handleCrack = useCallback(async () => {
    if (!token || cracking) return;

    const parsed = parseJwt(token);
    if (!parsed) {
      onChange({ ...data, error: 'Invalid JWT format' });
      return;
    }

    const alg = parsed.header.alg as string;
    if (!alg?.startsWith('HS')) {
      onChange({ ...data, error: `Algorithm ${alg} is not supported. Only HMAC algorithms (HS256, HS384, HS512) can be cracked.` });
      return;
    }

    const algorithm = alg as 'HS256' | 'HS384' | 'HS512';

    // Build wordlist from common secrets + custom wordlist
    const customWords = wordlist.split('\n').map(w => w.trim()).filter(Boolean);
    const allSecrets = [...COMMON_SECRETS, ...customWords];
    const total = allSecrets.length;

    abortRef.current = false;
    onChange({
      ...data,
      cracking: true,
      progress: 0,
      attemptCount: 0,
      foundSecret: '',
      cracked: false,
      error: ''
    });

    for (let i = 0; i < allSecrets.length; i++) {
      if (abortRef.current) {
        onChange({ ...data, cracking: false, error: 'Stopped by user' });
        return;
      }

      const secret = allSecrets[i];
      const valid = await verifySignature(token, secret, algorithm);

      if (valid) {
        onChange({
          ...data,
          cracking: false,
          progress: 100,
          attemptCount: i + 1,
          foundSecret: secret,
          cracked: true,
          error: ''
        });
        return;
      }

      // Update progress every 5 attempts or on last attempt
      if (i % 5 === 0 || i === total - 1) {
        onChange({
          ...data,
          cracking: true,
          progress: Math.round(((i + 1) / total) * 100),
          attemptCount: i + 1
        });
      }
    }

    onChange({
      ...data,
      cracking: false,
      progress: 100,
      attemptCount: total,
      error: `No secret found after ${total} attempts. Try adding more secrets to the wordlist.`
    });
  }, [token, wordlist, cracking, data, onChange]);

  const handleStop = useCallback(() => {
    abortRef.current = true;
  }, []);

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">JWT Cracker</div>

      <div className="bg-amber-900/30 border border-amber-700 rounded p-2 text-[10px] text-amber-300">
        For educational and authorized security testing purposes only. Attempting to crack JWTs without authorization may be illegal.
      </div>

      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">JWT Token</div>
        <textarea
          value={token}
          onChange={(e) => onChange({ ...data, token: e.target.value, error: '' })}
          rows={3}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 font-mono"
          placeholder="Paste JWT token here (eyJ...)"
          disabled={cracking}
        />
        {!isValidJwt && (
          <div className="text-[10px] text-red-400">Invalid JWT format</div>
        )}
      </div>

      {detectedAlgorithm && (
        <div className="flex items-center gap-2">
          <span className="text-[11px] text-slate-400">Algorithm:</span>
          <span className={`text-[11px] font-mono ${isHmacAlgorithm ? 'text-emerald-400' : 'text-red-400'}`}>
            {detectedAlgorithm}
          </span>
          {!isHmacAlgorithm && (
            <span className="text-[10px] text-red-400">(Not crackable - HMAC only)</span>
          )}
        </div>
      )}

      <div className="space-y-1">
        <div className="flex items-center justify-between">
          <div className="text-[11px] text-slate-400">Custom Wordlist</div>
          <div className="text-[10px] text-slate-500">{COMMON_SECRETS.length} common secrets built-in</div>
        </div>
        <textarea
          value={wordlist}
          onChange={(e) => onChange({ ...data, wordlist: e.target.value })}
          rows={3}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 font-mono"
          placeholder="Add custom secrets (one per line)..."
          disabled={cracking}
        />
      </div>

      <div className="flex gap-2">
        {!cracking ? (
          <button
            type="button"
            onClick={handleCrack}
            disabled={!token || !isValidJwt || !isHmacAlgorithm}
            className="flex-1 rounded bg-emerald-600 text-white text-xs py-2 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Crack JWT
          </button>
        ) : (
          <button
            type="button"
            onClick={handleStop}
            className="flex-1 rounded bg-red-600 text-white text-xs py-2 hover:bg-red-500"
          >
            Stop
          </button>
        )}
      </div>

      {cracking && (
        <div className="space-y-1">
          <div className="flex items-center justify-between text-[10px] text-slate-400">
            <span>Cracking... {data?.attemptCount ?? 0} attempts</span>
            <span>{progress}%</span>
          </div>
          <div className="w-full bg-slate-800 rounded-full h-2">
            <div
              className="bg-emerald-500 h-2 rounded-full transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      {cracked && foundSecret && (
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <div className="text-[11px] text-emerald-400">Secret Found!</div>
            <button
              type="button"
              onClick={handleCopy}
              className="text-[10px] text-slate-400 hover:text-white"
            >
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <div className="bg-emerald-900/30 border border-emerald-700 rounded p-2 text-xs text-emerald-200 font-mono break-all">
            {foundSecret}
          </div>
        </div>
      )}

      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded p-2 text-[10px] text-red-300">
          {error}
        </div>
      )}

      <div className="text-[10px] text-slate-500">
        Common secrets include: secret, password, 123456, jwt, token, key, and more.
        HMAC algorithms (HS256, HS384, HS512) use symmetric keys that can be brute-forced.
      </div>
    </div>
  );
};

export class JwtCrackerTool {
  static Component = JwtCrackerToolComponent;
}
