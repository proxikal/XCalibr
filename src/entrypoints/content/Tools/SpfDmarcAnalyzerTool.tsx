import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faEnvelope, faShieldAlt, faExclamationTriangle, faCheckCircle, faSearch, faGlobe } from '@fortawesome/free-solid-svg-icons';

export type SpfDmarcAnalyzerData = {
  domain?: string;
  spfRecord?: string;
  dmarcRecord?: string;
  spfAnalysis?: SpfAnalysis;
  dmarcAnalysis?: DmarcAnalysis;
  loading?: boolean;
  error?: string;
  analyzedAt?: number;
};

export type SpfAnalysis = {
  valid: boolean;
  version?: string;
  mechanisms: string[];
  modifiers: string[];
  includes: string[];
  allQualifier?: string;
  warnings: string[];
};

export type DmarcAnalysis = {
  valid: boolean;
  version?: string;
  policy?: string;
  subdomainPolicy?: string;
  percentage?: number;
  reportUri?: string;
  reportUriAggregate?: string;
  warnings: string[];
};

type Props = {
  data: SpfDmarcAnalyzerData | undefined;
  onChange: (data: SpfDmarcAnalyzerData) => void;
};

const parseSpf = (record: string): SpfAnalysis => {
  const warnings: string[] = [];
  const mechanisms: string[] = [];
  const modifiers: string[] = [];
  const includes: string[] = [];
  let version: string | undefined;
  let allQualifier: string | undefined;

  if (!record.startsWith('v=spf1')) {
    return { valid: false, mechanisms: [], modifiers: [], includes: [], warnings: ['Invalid SPF: must start with v=spf1'] };
  }

  version = 'spf1';
  const parts = record.split(' ').filter(Boolean);

  for (const part of parts) {
    if (part.startsWith('v=')) continue;

    if (part.startsWith('include:')) {
      includes.push(part.replace('include:', ''));
      mechanisms.push(part);
    } else if (part.startsWith('redirect=')) {
      modifiers.push(part);
    } else if (part.startsWith('exp=')) {
      modifiers.push(part);
    } else if (part === 'all' || part === '+all' || part === '-all' || part === '~all' || part === '?all') {
      allQualifier = part;
    } else {
      mechanisms.push(part);
    }
  }

  if (allQualifier === '+all') {
    warnings.push('CRITICAL: +all allows any server to send email (very permissive)');
  } else if (allQualifier === '?all') {
    warnings.push('WARNING: ?all is neutral - does not provide protection');
  } else if (!allQualifier) {
    warnings.push('No "all" mechanism found - implicit ?all');
  }

  if (includes.length > 10) {
    warnings.push('WARNING: Too many includes may cause DNS lookup limits');
  }

  return { valid: true, version, mechanisms, modifiers, includes, allQualifier, warnings };
};

const parseDmarc = (record: string): DmarcAnalysis => {
  const warnings: string[] = [];
  let valid = false;
  let version: string | undefined;
  let policy: string | undefined;
  let subdomainPolicy: string | undefined;
  let percentage: number | undefined;
  let reportUri: string | undefined;
  let reportUriAggregate: string | undefined;

  if (!record.startsWith('v=DMARC1')) {
    return { valid: false, warnings: ['Invalid DMARC: must start with v=DMARC1'] };
  }

  valid = true;
  version = 'DMARC1';

  const parts = record.split(';').map(p => p.trim()).filter(Boolean);

  for (const part of parts) {
    const [key, value] = part.split('=').map(s => s.trim());

    switch (key) {
      case 'p':
        policy = value;
        break;
      case 'sp':
        subdomainPolicy = value;
        break;
      case 'pct':
        percentage = parseInt(value);
        break;
      case 'ruf':
        reportUri = value;
        break;
      case 'rua':
        reportUriAggregate = value;
        break;
    }
  }

  if (policy === 'none') {
    warnings.push('WARNING: p=none only monitors, does not reject spoofed emails');
  }

  if (!reportUriAggregate) {
    warnings.push('No aggregate reporting (rua) configured');
  }

  if (percentage && percentage < 100) {
    warnings.push(`Only ${percentage}% of messages are subject to DMARC policy`);
  }

  return { valid, version, policy, subdomainPolicy, percentage, reportUri, reportUriAggregate, warnings };
};

const SpfDmarcAnalyzer: React.FC<Props> = ({ data, onChange }) => {
  const domain = data?.domain ?? '';
  const spfRecord = data?.spfRecord ?? '';
  const dmarcRecord = data?.dmarcRecord ?? '';
  const spfAnalysis = data?.spfAnalysis;
  const dmarcAnalysis = data?.dmarcAnalysis;
  const loading = data?.loading ?? false;
  const error = data?.error ?? '';
  const analyzedAt = data?.analyzedAt;

  const handleUseCurrentDomain = () => {
    onChange({ ...data, domain: window.location.hostname });
  };

  const handleAnalyze = async () => {
    if (!domain.trim()) return;

    onChange({ ...data, loading: true, error: '' });

    try {
      // Try to fetch DNS records via a DNS API
      const dnsResponse = await chrome.runtime.sendMessage({
        type: 'xcalibr-dns-lookup',
        payload: { domain, type: 'TXT' }
      });

      let spf = '';
      let dmarc = '';

      if (dnsResponse?.records) {
        for (const record of dnsResponse.records) {
          if (record.startsWith('v=spf1')) {
            spf = record;
          }
        }
      }

      // Check DMARC subdomain
      const dmarcResponse = await chrome.runtime.sendMessage({
        type: 'xcalibr-dns-lookup',
        payload: { domain: `_dmarc.${domain}`, type: 'TXT' }
      });

      if (dmarcResponse?.records) {
        for (const record of dmarcResponse.records) {
          if (record.startsWith('v=DMARC1')) {
            dmarc = record;
          }
        }
      }

      const spfAnalysisResult = spf ? parseSpf(spf) : undefined;
      const dmarcAnalysisResult = dmarc ? parseDmarc(dmarc) : undefined;

      onChange({
        ...data,
        spfRecord: spf || 'No SPF record found',
        dmarcRecord: dmarc || 'No DMARC record found',
        spfAnalysis: spfAnalysisResult,
        dmarcAnalysis: dmarcAnalysisResult,
        loading: false,
        analyzedAt: Date.now(),
        error: (!spf && !dmarc) ? 'Could not retrieve DNS records. Try using an external DNS lookup service.' : ''
      });
    } catch (e) {
      onChange({
        ...data,
        loading: false,
        error: e instanceof Error ? e.message : 'Failed to analyze domain'
      });
    }
  };

  const handleManualInput = (field: 'spf' | 'dmarc', value: string) => {
    if (field === 'spf') {
      const analysis = value.trim() ? parseSpf(value.trim()) : undefined;
      onChange({ ...data, spfRecord: value, spfAnalysis: analysis });
    } else {
      const analysis = value.trim() ? parseDmarc(value.trim()) : undefined;
      onChange({ ...data, dmarcRecord: value, dmarcAnalysis: analysis });
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">SPF/DMARC Analyzer</div>
        <div className="flex gap-2">
          <button
            onClick={handleUseCurrentDomain}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Current Domain
          </button>
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Checks domain SPF and DMARC DNS records for email security configuration.
      </div>

      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
        <div className="text-[10px] text-slate-500 mb-1">Domain</div>
        <div className="flex gap-2">
          <input
            type="text"
            value={domain}
            onChange={(e) => onChange({ ...data, domain: e.target.value })}
            placeholder="example.com"
            className="flex-1 rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
          />
        </div>
      </div>

      <button
        onClick={handleAnalyze}
        disabled={!domain.trim() || loading}
        className="w-full rounded bg-blue-600/20 border border-blue-500/30 px-2 py-1.5 text-[11px] text-blue-300 hover:bg-blue-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2 mb-3"
      >
        <FontAwesomeIcon icon={faSearch} className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
        {loading ? 'Analyzing...' : 'Analyze DNS Records'}
      </button>

      {error && (
        <div className="text-yellow-400 text-[10px] bg-yellow-900/20 border border-yellow-700/50 p-2 rounded flex items-center gap-2 mb-3">
          <FontAwesomeIcon icon={faExclamationTriangle} className="w-3 h-3" />
          {error}
        </div>
      )}

      <div className="flex-1 overflow-y-auto space-y-3 min-h-0">
        <div className="rounded border border-slate-700 bg-slate-800/30 p-2">
          <div className="text-[10px] text-slate-500 mb-1 flex items-center gap-2">
            <FontAwesomeIcon icon={faEnvelope} className="w-2.5 h-2.5" />
            SPF Record
          </div>
          <textarea
            value={spfRecord}
            onChange={(e) => handleManualInput('spf', e.target.value)}
            placeholder="v=spf1 include:_spf.google.com ~all"
            className="w-full rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono h-14 resize-none"
          />
          {spfAnalysis && (
            <div className={`mt-2 p-2 rounded text-[10px] ${spfAnalysis.valid ? 'bg-green-900/20 border border-green-700/50' : 'bg-red-900/20 border border-red-700/50'}`}>
              <div className="flex items-center gap-2 mb-1">
                <FontAwesomeIcon icon={spfAnalysis.valid ? faCheckCircle : faExclamationTriangle} className={`w-2.5 h-2.5 ${spfAnalysis.valid ? 'text-green-400' : 'text-red-400'}`} />
                <span className={spfAnalysis.valid ? 'text-green-400' : 'text-red-400'}>
                  {spfAnalysis.valid ? 'Valid SPF' : 'Invalid SPF'}
                </span>
              </div>
              {spfAnalysis.allQualifier && (
                <div className="text-slate-300">All qualifier: <code className="bg-black/30 px-1 rounded">{spfAnalysis.allQualifier}</code></div>
              )}
              {spfAnalysis.includes.length > 0 && (
                <div className="text-slate-300">Includes: {spfAnalysis.includes.join(', ')}</div>
              )}
              {spfAnalysis.warnings.map((w, i) => (
                <div key={i} className="text-yellow-400 mt-1">! {w}</div>
              ))}
            </div>
          )}
        </div>

        <div className="rounded border border-slate-700 bg-slate-800/30 p-2">
          <div className="text-[10px] text-slate-500 mb-1 flex items-center gap-2">
            <FontAwesomeIcon icon={faShieldAlt} className="w-2.5 h-2.5" />
            DMARC Record
          </div>
          <textarea
            value={dmarcRecord}
            onChange={(e) => handleManualInput('dmarc', e.target.value)}
            placeholder="v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
            className="w-full rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono h-14 resize-none"
          />
          {dmarcAnalysis && (
            <div className={`mt-2 p-2 rounded text-[10px] ${dmarcAnalysis.valid ? 'bg-green-900/20 border border-green-700/50' : 'bg-red-900/20 border border-red-700/50'}`}>
              <div className="flex items-center gap-2 mb-1">
                <FontAwesomeIcon icon={dmarcAnalysis.valid ? faCheckCircle : faExclamationTriangle} className={`w-2.5 h-2.5 ${dmarcAnalysis.valid ? 'text-green-400' : 'text-red-400'}`} />
                <span className={dmarcAnalysis.valid ? 'text-green-400' : 'text-red-400'}>
                  {dmarcAnalysis.valid ? 'Valid DMARC' : 'Invalid DMARC'}
                </span>
              </div>
              {dmarcAnalysis.policy && (
                <div className="text-slate-300">Policy: <code className="bg-black/30 px-1 rounded">{dmarcAnalysis.policy}</code></div>
              )}
              {dmarcAnalysis.reportUriAggregate && (
                <div className="text-slate-300 truncate">Reports to: {dmarcAnalysis.reportUriAggregate}</div>
              )}
              {dmarcAnalysis.warnings.map((w, i) => (
                <div key={i} className="text-yellow-400 mt-1">! {w}</div>
              ))}
            </div>
          )}
        </div>
      </div>

      {analyzedAt && (
        <div className="text-[10px] text-slate-500 mt-3 pt-2 border-t border-slate-700">
          Analyzed: {new Date(analyzedAt).toLocaleTimeString()}
        </div>
      )}

      <div className="text-[10px] text-slate-500 space-y-1 border-t border-slate-700 pt-2 mt-2">
        <div><strong>SPF:</strong> Specifies which servers can send email for the domain</div>
        <div><strong>DMARC:</strong> Tells receivers what to do with failed SPF/DKIM checks</div>
      </div>
    </div>
  );
};

export class SpfDmarcAnalyzerTool {
  static Component = SpfDmarcAnalyzer;
}
