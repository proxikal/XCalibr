import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCookie, faShieldAlt, faExclamationTriangle, faCheckCircle, faSync } from '@fortawesome/free-solid-svg-icons';

export type CookieSecurityAuditorData = {
  cookies?: CookieAuditResult[];
  scannedAt?: number;
  error?: string;
};

export type CookieAuditResult = {
  name: string;
  value: string;
  domain?: string;
  path?: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'Strict' | 'Lax' | 'None' | 'Unknown';
  expires?: string;
  issues: string[];
};

type Props = {
  data: CookieSecurityAuditorData | undefined;
  onChange: (data: CookieSecurityAuditorData) => void;
};

const parseCookies = (): CookieAuditResult[] => {
  const cookieString = document.cookie;
  if (!cookieString) return [];

  const cookies: CookieAuditResult[] = [];
  const pairs = cookieString.split(';');

  for (const pair of pairs) {
    const [name, ...valueParts] = pair.trim().split('=');
    const value = valueParts.join('=');
    if (!name) continue;

    const issues: string[] = [];
    // Note: We can only access non-HttpOnly cookies from JS
    // HttpOnly cookies are not visible to document.cookie
    issues.push('HttpOnly flag cannot be verified (cookie visible to JS)');

    // Check if we're on HTTPS
    const isSecureContext = window.location.protocol === 'https:';
    if (!isSecureContext) {
      issues.push('Page not served over HTTPS - Secure flag effectiveness limited');
    }

    cookies.push({
      name: name.trim(),
      value: value || '',
      httpOnly: false, // If we can read it, it's not HttpOnly
      secure: false, // Cannot determine from JS
      sameSite: 'Unknown', // Cannot determine from JS
      issues
    });
  }

  return cookies;
};

const CookieSecurityAuditor: React.FC<Props> = ({ data, onChange }) => {
  const cookies = data?.cookies ?? [];
  const scannedAt = data?.scannedAt;
  const error = data?.error ?? '';
  const [scanning, setScanning] = useState(false);

  const handleScan = async () => {
    setScanning(true);
    onChange({ ...data, error: '' });

    try {
      const parsedCookies = parseCookies();
      onChange({
        cookies: parsedCookies,
        scannedAt: Date.now(),
        error: parsedCookies.length === 0 ? 'No cookies found accessible via JavaScript' : ''
      });
    } catch (e) {
      onChange({
        ...data,
        error: e instanceof Error ? e.message : 'Failed to scan cookies'
      });
    } finally {
      setScanning(false);
    }
  };

  const getSecurityScore = (cookie: CookieAuditResult): 'good' | 'warning' | 'bad' => {
    if (cookie.issues.length === 0) return 'good';
    if (cookie.issues.length <= 1) return 'warning';
    return 'bad';
  };

  const scoreColors = {
    good: 'border-green-500/30 bg-green-900/20',
    warning: 'border-yellow-500/30 bg-yellow-900/20',
    bad: 'border-red-500/30 bg-red-900/20'
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Cookie Security Auditor</div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Analyzes cookies for security flags (HttpOnly, Secure, SameSite). Note: HttpOnly cookies are not visible to JavaScript.
      </div>

      <button
        onClick={handleScan}
        disabled={scanning}
        className="w-full rounded bg-purple-600/20 border border-purple-500/30 px-2 py-1.5 text-[11px] text-purple-300 hover:bg-purple-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faSync} className={`w-3 h-3 ${scanning ? 'animate-spin' : ''}`} />
        {scanning ? 'Scanning...' : 'Scan Cookies'}
      </button>

      {error && (
        <div className="rounded border border-yellow-500/30 bg-yellow-900/20 p-2 mb-3 flex items-center gap-2 text-[10px] text-yellow-400">
          <FontAwesomeIcon icon={faExclamationTriangle} className="w-3 h-3" />
          {error}
        </div>
      )}

      {scannedAt && (
        <div className="text-[10px] text-slate-500 mb-2">
          Last scanned: {new Date(scannedAt).toLocaleTimeString()}
        </div>
      )}

      {cookies.length > 0 && (
        <div className="flex-1 overflow-y-auto space-y-2 min-h-0">
          <div className="text-[10px] text-slate-400 font-medium mb-2">
            Found {cookies.length} cookie(s) accessible via JavaScript:
          </div>

          {cookies.map((cookie, index) => {
            const score = getSecurityScore(cookie);
            return (
              <div
                key={index}
                className={`rounded border p-2 ${scoreColors[score]}`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <FontAwesomeIcon icon={faCookie} className="text-slate-400 w-2.5 h-2.5" />
                    <span className="font-medium text-slate-200 text-[11px]">{cookie.name}</span>
                  </div>
                  <FontAwesomeIcon
                    icon={score === 'good' ? faCheckCircle : faExclamationTriangle}
                    className={`w-3 h-3 ${score === 'good' ? 'text-green-400' : score === 'warning' ? 'text-yellow-400' : 'text-red-400'}`}
                  />
                </div>

                <div className="text-[10px] mb-2 font-mono bg-black/30 p-1 rounded truncate text-slate-300">
                  {cookie.value.substring(0, 50)}{cookie.value.length > 50 ? '...' : ''}
                </div>

                <div className="grid grid-cols-3 gap-2 text-[9px] mb-2">
                  <div className="flex items-center gap-1">
                    <FontAwesomeIcon
                      icon={faShieldAlt}
                      className={`w-2.5 h-2.5 ${cookie.httpOnly ? 'text-green-400' : 'text-red-400'}`}
                    />
                    <span className="text-slate-300">HttpOnly: {cookie.httpOnly ? 'Yes' : 'No'}</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <FontAwesomeIcon
                      icon={faShieldAlt}
                      className={`w-2.5 h-2.5 ${cookie.secure ? 'text-green-400' : 'text-slate-500'}`}
                    />
                    <span className="text-slate-300">Secure: {cookie.secure ? 'Yes' : '?'}</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <FontAwesomeIcon
                      icon={faShieldAlt}
                      className={`w-2.5 h-2.5 ${cookie.sameSite === 'Strict' ? 'text-green-400' : 'text-slate-500'}`}
                    />
                    <span className="text-slate-300">SameSite: {cookie.sameSite}</span>
                  </div>
                </div>

                {cookie.issues.length > 0 && (
                  <div className="text-[9px] text-slate-400 space-y-0.5">
                    {cookie.issues.map((issue, i) => (
                      <div key={i} className="flex items-start gap-1">
                        <span className="text-yellow-400">!</span>
                        <span>{issue}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {cookies.length === 0 && !scannedAt && (
        <div className="text-[11px] text-slate-500 text-center py-4">
          Click scan to analyze cookie security flags.
        </div>
      )}

      <div className="text-[10px] text-slate-500 space-y-1 border-t border-slate-700 pt-3 mt-3">
        <div><strong>HttpOnly:</strong> Prevents JavaScript access (XSS protection)</div>
        <div><strong>Secure:</strong> Only sent over HTTPS</div>
        <div><strong>SameSite:</strong> Controls cross-site request behavior (CSRF protection)</div>
      </div>
    </div>
  );
};

export class CookieSecurityAuditorTool {
  static Component = CookieSecurityAuditor;
}
