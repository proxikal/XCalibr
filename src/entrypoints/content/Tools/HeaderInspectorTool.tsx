import React, { useState, useMemo } from 'react';
import type {
  HeaderInspectorData,
  HeaderFinding,
  HeaderSeverity
} from './tool-types';

const SECURITY_HEADERS = new Set([
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'x-xss-protection',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-embedder-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy'
]);

const CACHING_HEADERS = new Set([
  'cache-control',
  'expires',
  'etag',
  'last-modified',
  'age',
  'vary',
  'pragma'
]);

const COOKIE_HEADERS = new Set(['set-cookie']);

type HeaderCategory = 'security' | 'caching' | 'cookie' | 'general';

const analyzeHeaders = (headers: { name: string; value: string }[]): HeaderFinding[] => {
  const findings: HeaderFinding[] = [];
  const headerMap = new Map<string, string>();

  headers.forEach(h => headerMap.set(h.name.toLowerCase(), h.value));

  // HSTS Analysis
  const hsts = headerMap.get('strict-transport-security');
  if (!hsts) {
    findings.push({
      header: 'Strict-Transport-Security',
      severity: 'fail',
      message: 'HSTS header is missing',
      recommendation: 'Add Strict-Transport-Security header with max-age of at least 31536000 (1 year)'
    });
  } else {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
    const hasPreload = hsts.toLowerCase().includes('preload');
    const hasIncludeSubDomains = hsts.toLowerCase().includes('includesubdomains');

    if (maxAge < 31536000) {
      findings.push({
        header: 'Strict-Transport-Security',
        severity: 'warn',
        message: `HSTS max-age is ${maxAge}s (less than 1 year)`,
        value: hsts,
        recommendation: 'Increase max-age to at least 31536000 (1 year)'
      });
    } else if (!hasIncludeSubDomains) {
      findings.push({
        header: 'Strict-Transport-Security',
        severity: 'warn',
        message: 'HSTS missing includeSubDomains directive',
        value: hsts,
        recommendation: 'Add includeSubDomains to protect all subdomains'
      });
    } else if (!hasPreload && maxAge >= 31536000) {
      findings.push({
        header: 'Strict-Transport-Security',
        severity: 'info',
        message: 'HSTS is configured but not preload-ready',
        value: hsts,
        recommendation: 'Consider adding preload directive for browser preload list'
      });
    } else {
      findings.push({
        header: 'Strict-Transport-Security',
        severity: 'pass',
        message: 'HSTS properly configured' + (hasPreload ? ' with preload' : ''),
        value: hsts
      });
    }
  }

  // CSP Analysis
  const csp = headerMap.get('content-security-policy');
  if (!csp) {
    findings.push({
      header: 'Content-Security-Policy',
      severity: 'fail',
      message: 'CSP header is missing',
      recommendation: 'Implement a Content-Security-Policy to prevent XSS and data injection attacks'
    });
  } else {
    const issues: string[] = [];
    if (csp.includes("'unsafe-inline'")) issues.push("uses 'unsafe-inline'");
    if (csp.includes("'unsafe-eval'")) issues.push("uses 'unsafe-eval'");
    if (csp.includes('*') && !csp.includes('*.')) issues.push('uses wildcard (*)');
    if (!csp.includes('default-src')) issues.push("missing 'default-src'");

    if (issues.length > 0) {
      findings.push({
        header: 'Content-Security-Policy',
        severity: 'warn',
        message: `CSP ${issues.join(', ')}`,
        value: csp.length > 100 ? csp.slice(0, 100) + '...' : csp,
        recommendation: 'Remove unsafe directives and wildcards for stronger protection'
      });
    } else {
      findings.push({
        header: 'Content-Security-Policy',
        severity: 'pass',
        message: 'CSP is configured without major issues',
        value: csp.length > 100 ? csp.slice(0, 100) + '...' : csp
      });
    }
  }

  // X-Frame-Options Analysis
  const xfo = headerMap.get('x-frame-options');
  const cspFrameAncestors = csp?.includes('frame-ancestors');

  if (!xfo && !cspFrameAncestors) {
    findings.push({
      header: 'X-Frame-Options',
      severity: 'fail',
      message: 'No clickjacking protection (XFO or CSP frame-ancestors)',
      recommendation: "Add X-Frame-Options: DENY or CSP with frame-ancestors 'none'"
    });
  } else if (xfo && cspFrameAncestors) {
    findings.push({
      header: 'X-Frame-Options',
      severity: 'info',
      message: 'Both XFO and CSP frame-ancestors present (CSP takes precedence)',
      value: xfo
    });
  } else if (xfo) {
    const xfoUpper = xfo.toUpperCase();
    if (xfoUpper === 'DENY' || xfoUpper === 'SAMEORIGIN') {
      findings.push({
        header: 'X-Frame-Options',
        severity: 'pass',
        message: `Clickjacking protection enabled (${xfoUpper})`,
        value: xfo
      });
    } else {
      findings.push({
        header: 'X-Frame-Options',
        severity: 'warn',
        message: 'X-Frame-Options has non-standard value',
        value: xfo,
        recommendation: 'Use DENY or SAMEORIGIN'
      });
    }
  }

  // X-Content-Type-Options
  const xcto = headerMap.get('x-content-type-options');
  if (!xcto) {
    findings.push({
      header: 'X-Content-Type-Options',
      severity: 'fail',
      message: 'X-Content-Type-Options header is missing',
      recommendation: 'Add X-Content-Type-Options: nosniff to prevent MIME sniffing'
    });
  } else if (xcto.toLowerCase() === 'nosniff') {
    findings.push({
      header: 'X-Content-Type-Options',
      severity: 'pass',
      message: 'MIME sniffing protection enabled',
      value: xcto
    });
  } else {
    findings.push({
      header: 'X-Content-Type-Options',
      severity: 'warn',
      message: 'X-Content-Type-Options has unexpected value',
      value: xcto,
      recommendation: "Value should be 'nosniff'"
    });
  }

  // Referrer-Policy
  const referrer = headerMap.get('referrer-policy');
  if (!referrer) {
    findings.push({
      header: 'Referrer-Policy',
      severity: 'warn',
      message: 'Referrer-Policy header is missing',
      recommendation: 'Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer'
    });
  } else {
    const safeValues = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin', 'same-origin'];
    const isStrict = safeValues.some(v => referrer.toLowerCase().includes(v));
    findings.push({
      header: 'Referrer-Policy',
      severity: isStrict ? 'pass' : 'warn',
      message: isStrict ? 'Referrer-Policy is configured securely' : 'Referrer-Policy may leak sensitive data',
      value: referrer,
      recommendation: isStrict ? undefined : 'Consider strict-origin-when-cross-origin'
    });
  }

  // Permissions-Policy
  const permissions = headerMap.get('permissions-policy');
  if (!permissions) {
    findings.push({
      header: 'Permissions-Policy',
      severity: 'info',
      message: 'Permissions-Policy header is missing',
      recommendation: 'Consider adding Permissions-Policy to control browser features'
    });
  } else {
    findings.push({
      header: 'Permissions-Policy',
      severity: 'pass',
      message: 'Permissions-Policy is configured',
      value: permissions.length > 80 ? permissions.slice(0, 80) + '...' : permissions
    });
  }

  // Set-Cookie Analysis
  const cookies = headers.filter(h => h.name.toLowerCase() === 'set-cookie');
  cookies.forEach((cookie, idx) => {
    const issues: string[] = [];
    const val = cookie.value.toLowerCase();
    if (!val.includes('httponly')) issues.push('missing HttpOnly');
    if (!val.includes('secure')) issues.push('missing Secure');
    if (!val.includes('samesite')) issues.push('missing SameSite');

    if (issues.length > 0) {
      findings.push({
        header: `Set-Cookie #${idx + 1}`,
        severity: 'warn',
        message: `Cookie ${issues.join(', ')}`,
        value: cookie.value.split(';')[0] + '...',
        recommendation: 'Add HttpOnly, Secure, and SameSite attributes'
      });
    }
  });

  // Server header disclosure
  const server = headerMap.get('server');
  if (server && server.match(/[\d.]+/)) {
    findings.push({
      header: 'Server',
      severity: 'info',
      message: 'Server header discloses version information',
      value: server,
      recommendation: 'Consider hiding server version to reduce attack surface'
    });
  }

  // X-Powered-By disclosure
  const poweredBy = headerMap.get('x-powered-by');
  if (poweredBy) {
    findings.push({
      header: 'X-Powered-By',
      severity: 'info',
      message: 'X-Powered-By header discloses technology stack',
      value: poweredBy,
      recommendation: 'Remove this header to reduce information disclosure'
    });
  }

  return findings;
};

const detectDuplicateHeaders = (headers: { name: string; value: string }[]): string[] => {
  const counts = new Map<string, number>();
  headers.forEach(h => {
    const name = h.name.toLowerCase();
    counts.set(name, (counts.get(name) || 0) + 1);
  });
  return Array.from(counts.entries())
    .filter(([, count]) => count > 1)
    .map(([name]) => name);
};

const HeaderInspectorToolComponent = ({
  data,
  onChange,
  onRefresh
}: {
  data: HeaderInspectorData | undefined;
  onChange: (next: HeaderInspectorData) => void;
  onRefresh: () => Promise<void>;
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  const headers = data?.headers ?? [];
  const activeTab = data?.activeTab ?? 'findings';
  const updatedAt = data?.updatedAt;

  const findings = useMemo(() => analyzeHeaders(headers), [headers]);
  const duplicates = useMemo(() => detectDuplicateHeaders(headers), [headers]);

  const categorizeHeader = (name: string): HeaderCategory => {
    const lower = name.toLowerCase();
    if (SECURITY_HEADERS.has(lower)) return 'security';
    if (CACHING_HEADERS.has(lower)) return 'caching';
    if (COOKIE_HEADERS.has(lower)) return 'cookie';
    return 'general';
  };

  const categorizedHeaders = useMemo(() => {
    const security = headers.filter((h) => categorizeHeader(h.name) === 'security');
    const caching = headers.filter((h) => categorizeHeader(h.name) === 'caching');
    const cookie = headers.filter((h) => categorizeHeader(h.name) === 'cookie');
    const general = headers.filter((h) => categorizeHeader(h.name) === 'general');
    return { security, caching, cookie, general };
  }, [headers]);

  const findingStats = useMemo(() => {
    const pass = findings.filter(f => f.severity === 'pass').length;
    const warn = findings.filter(f => f.severity === 'warn').length;
    const fail = findings.filter(f => f.severity === 'fail').length;
    const info = findings.filter(f => f.severity === 'info').length;
    return { pass, warn, fail, info };
  }, [findings]);

  const handleRefresh = async () => {
    setIsLoading(true);
    await onRefresh();
    setIsLoading(false);
  };

  const handleExportJSON = () => {
    const exportData = {
      url: data?.url,
      finalUrl: data?.finalUrl,
      status: data?.status,
      headers: headers.map((h) => ({ name: h.name, value: h.value })),
      findings,
      duplicateHeaders: duplicates,
      capturedAt: updatedAt ? new Date(updatedAt).toISOString() : null
    };
    const json = JSON.stringify(exportData, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `headers-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getSeverityStyle = (severity: HeaderSeverity) => {
    switch (severity) {
      case 'pass': return 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300';
      case 'warn': return 'border-amber-500/40 bg-amber-500/10 text-amber-300';
      case 'fail': return 'border-rose-500/40 bg-rose-500/10 text-rose-300';
      case 'info': return 'border-blue-500/40 bg-blue-500/10 text-blue-300';
    }
  };

  const getSeverityIcon = (severity: HeaderSeverity) => {
    switch (severity) {
      case 'pass': return '✓';
      case 'warn': return '⚠';
      case 'fail': return '✗';
      case 'info': return 'ℹ';
    }
  };

  const getCategoryStyle = (category: HeaderCategory) => {
    switch (category) {
      case 'security': return 'border-emerald-500/40 bg-emerald-500/10';
      case 'caching': return 'border-amber-500/40 bg-amber-500/10';
      case 'cookie': return 'border-purple-500/40 bg-purple-500/10';
      default: return 'border-slate-700 bg-slate-800/50';
    }
  };

  const getCategoryLabel = (category: HeaderCategory) => {
    switch (category) {
      case 'security': return { text: 'Security', color: 'text-emerald-400' };
      case 'caching': return { text: 'Cache', color: 'text-amber-400' };
      case 'cookie': return { text: 'Cookie', color: 'text-purple-400' };
      default: return { text: 'General', color: 'text-slate-500' };
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-2">
        <div className="text-xs text-slate-200">Header Inspector</div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={handleExportJSON}
            disabled={headers.length === 0}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors disabled:opacity-50"
          >
            Export
          </button>
          <button
            type="button"
            onClick={handleRefresh}
            disabled={isLoading}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors disabled:opacity-50"
          >
            {isLoading ? 'Loading...' : 'Refresh'}
          </button>
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-1 truncate" title={data?.url}>
        {data?.url ?? 'No data yet'}
        {data?.status && <span className="ml-2 text-slate-400">Status: {data.status}</span>}
      </div>

      {data?.finalUrl && data.finalUrl !== data.url && (
        <div className="text-[9px] text-blue-400 mb-1 truncate" title={data.finalUrl}>
          → Redirected to: {data.finalUrl}
        </div>
      )}

      {data?.error && (
        <div className="rounded border border-rose-500/30 bg-rose-500/10 px-2 py-1 text-[11px] text-rose-200 mb-2">
          {data.error}
        </div>
      )}

      {duplicates.length > 0 && (
        <div className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-[10px] text-amber-200 mb-2">
          ⚠ Duplicate headers: {duplicates.join(', ')}
        </div>
      )}

      <div className="flex gap-1 mb-2">
        <button
          type="button"
          onClick={() => onChange({ ...data, activeTab: 'findings' })}
          className={`flex-1 rounded px-1.5 py-0.5 text-[9px] border transition-colors ${
            activeTab === 'findings'
              ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
              : 'bg-slate-800 border-slate-700 text-slate-400'
          }`}
        >
          Findings ({findings.length})
        </button>
        <button
          type="button"
          onClick={() => onChange({ ...data, activeTab: 'raw' })}
          className={`flex-1 rounded px-1.5 py-0.5 text-[9px] border transition-colors ${
            activeTab === 'raw'
              ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
              : 'bg-slate-800 border-slate-700 text-slate-400'
          }`}
        >
          Raw ({headers.length})
        </button>
      </div>

      {activeTab === 'findings' && findings.length > 0 && (
        <div className="flex gap-2 mb-2 text-[9px]">
          <span className="text-emerald-400">✓ {findingStats.pass}</span>
          <span className="text-amber-400">⚠ {findingStats.warn}</span>
          <span className="text-rose-400">✗ {findingStats.fail}</span>
          <span className="text-blue-400">ℹ {findingStats.info}</span>
        </div>
      )}

      {updatedAt && (
        <div className="text-[9px] text-slate-500 mb-2">
          Updated {new Date(updatedAt).toLocaleTimeString()}
        </div>
      )}

      <div className="flex-1 overflow-y-auto space-y-1.5 min-h-0">
        {activeTab === 'findings' ? (
          findings.length === 0 ? (
            <div className="text-[11px] text-slate-500 text-center py-4">
              No headers to analyze yet.
            </div>
          ) : (
            findings.map((finding, idx) => (
              <div
                key={`${finding.header}-${idx}`}
                className={`rounded border p-2 cursor-pointer transition-colors ${getSeverityStyle(finding.severity)}`}
                onClick={() => setExpandedFinding(expandedFinding === `${finding.header}-${idx}` ? null : `${finding.header}-${idx}`)}
              >
                <div className="flex items-center gap-2">
                  <span className="text-[11px]">{getSeverityIcon(finding.severity)}</span>
                  <span className="text-[10px] font-medium flex-1">{finding.header}</span>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      if (finding.value) navigator.clipboard.writeText(finding.value);
                    }}
                    className="text-[9px] opacity-60 hover:opacity-100"
                    title="Copy value"
                  >
                    ⧉
                  </button>
                </div>
                <div className="text-[10px] mt-1 opacity-90">{finding.message}</div>
                {expandedFinding === `${finding.header}-${idx}` && (
                  <div className="mt-2 pt-2 border-t border-current/20 space-y-1">
                    {finding.value && (
                      <div className="text-[9px] font-mono break-all opacity-70">
                        Value: {finding.value}
                      </div>
                    )}
                    {finding.recommendation && (
                      <div className="text-[9px] opacity-80">
                        💡 {finding.recommendation}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))
          )
        ) : (
          <>
            {(['security', 'caching', 'cookie', 'general'] as const).map(category => {
              const categoryHeaders = categorizedHeaders[category];
              if (categoryHeaders.length === 0) return null;
              const label = getCategoryLabel(category);
              return (
                <div key={category} className="mb-2">
                  <div className={`text-[9px] uppercase tracking-widest mb-1 ${label.color}`}>
                    {label.text} ({categoryHeaders.length})
                  </div>
                  <div className="space-y-1">
                    {categoryHeaders.map((header, idx) => (
                      <div
                        key={`${header.name}-${idx}`}
                        className={`rounded border p-2 ${getCategoryStyle(category)}`}
                      >
                        <div className="flex items-center justify-between gap-2 mb-1">
                          <div className="text-[10px] font-medium text-slate-200 break-all">
                            {header.name}
                          </div>
                          <button
                            type="button"
                            onClick={() => navigator.clipboard.writeText(header.value)}
                            className="text-[9px] text-slate-500 hover:text-slate-300 flex-shrink-0"
                            title="Copy value"
                          >
                            ⧉
                          </button>
                        </div>
                        <div className="text-[10px] text-slate-400 break-all line-clamp-3">
                          {header.value}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
            {headers.length === 0 && (
              <div className="text-[11px] text-slate-500 text-center py-4">
                No headers captured yet.
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};
export class HeaderInspectorTool {
  static Component = HeaderInspectorToolComponent;
}
