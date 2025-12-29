import React, { useEffect, useMemo, useRef, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faBolt,
  faChevronLeft,
  faChevronRight,
  faCode,
  faCompress,
  faExpand,
  faEyeDropper,
  faFileCode,
  faFingerprint,
  faFlask,
  faBug,
  faGear,
  faGlobe,
  faLink,
  faRobot,
  faSliders,
  faSitemap,
  faShieldHalved,
  faSearch,
  faTable,
  faWaveSquare
} from '@fortawesome/free-solid-svg-icons';
import { defineContentScript } from 'wxt/sandbox';
import tailwindStyles from '../styles/index.css?inline';
import { DEFAULT_STATE, getState, subscribeState, updateState } from '../shared/state';
import {
  ScraperDefinition,
  ScraperDraft,
  ScraperField,
  buildScraperId,
  buildCsvFromResults,
  extractScraperResults,
  getRegexMatchCount,
  generateCssSelector,
  generateXPath
} from '../shared/scraper';

const ROOT_ID = 'xcalibr-root';

const baseMenuBarItems = [
  {
    label: 'File',
    items: ['Help', 'Settings']
  },
  {
    label: 'Web Dev',
    items: [
      { label: 'Code Injector', toolId: 'codeInjector' },
      'Debugger',
      'Performance Timeline',
      'Storage Explorer',
      'Console Snippet Runner',
      'Lighthouse Snapshot',
      {
        label: 'Front End',
        items: [
          { label: 'Color Picker', toolId: 'colorPicker' },
          'CSS Grid Generator',
          'Flexbox Inspector',
          'Font Identifier',
          'Contrast Checker',
          'Responsive Preview',
          'Animation Preview',
          'SVG Optimizer',
          'Accessibility Audit'
        ]
      },
      {
        label: 'Back End',
        items: [
          'JWT Debugger',
          'Regex Tester',
          'API Response Viewer',
          'GraphQL Explorer',
          'REST Client',
          'OAuth Token Inspector',
          'Webhook Tester',
          'Cookie Manager'
        ]
      }
    ]
  },
  {
    label: 'Database',
    items: [
      {
        label: 'JSON',
        items: [
          { label: 'JSON Minifier', toolId: 'jsonMinifier' },
          'JSON Prettifier',
          'JSON Schema Validator',
          'JSON Path Tester',
          'JSON Diff'
        ]
      },
      {
        label: 'SQL',
        items: [
          'SQL Formatter',
          'SQL Query Builder',
          'Explain Plan Viewer',
          'SQL to CSV',
          'Index Advisor'
        ]
      },
      {
        label: 'NoSQL',
        items: [
          'BSON Viewer',
          'Mongo Query Builder',
          'DynamoDB JSON Converter',
          'Firebase Rules Linter',
          'CouchDB Doc Explorer'
        ]
      }
    ]
  },
  {
    label: 'CyberSec',
    items: [
      {
        label: 'Recon',
        items: [
          { label: 'Header Inspector', toolId: 'headerInspector' },
          { label: 'Tech Fingerprint', toolId: 'techFingerprint' },
          { label: 'Robots.txt Viewer', toolId: 'robotsViewer' }
        ]
      },
      {
        label: 'Testing',
        items: [
          { label: 'Form Fuzzer', toolId: 'formFuzzer' },
          { label: 'URL Encoder/Decoder', toolId: 'urlCodec' },
          { label: 'Param Analyzer', toolId: 'paramAnalyzer' }
        ]
      },
      {
        label: 'Content',
        items: [
          { label: 'Link Extractor', toolId: 'linkExtractor' },
          { label: 'DOM Snapshot', toolId: 'domSnapshot' },
          { label: 'Asset Mapper', toolId: 'assetMapper' }
        ]
      },
      {
        label: 'Network',
        items: [
          { label: 'Request Log', toolId: 'requestLog' },
          { label: 'Payload Replay', toolId: 'payloadReplay' },
          { label: 'CORS Check', toolId: 'corsCheck' }
        ]
      }
    ]
  }
];

const TOOL_DEFAULT_POSITION = { x: 80, y: 140 };

type ToolRegistryEntry = {
  id: string;
  title: string;
  subtitle: string;
  category: string;
  icon: typeof faBolt;
  hover: string;
  render: (
    data: unknown,
    onChange: (next: unknown) => void
  ) => React.ReactNode;
};

const hexToRgb = (hex: string) => {
  const normalized = hex.replace('#', '').trim();
  if (![3, 6].includes(normalized.length)) return null;
  const expanded =
    normalized.length === 3
      ? normalized
          .split('')
          .map((char) => `${char}${char}`)
          .join('')
      : normalized;
  const int = Number.parseInt(expanded, 16);
  if (Number.isNaN(int)) return null;
  return {
    r: (int >> 16) & 255,
    g: (int >> 8) & 255,
    b: int & 255
  };
};

const ColorPickerTool = ({
  data,
  onChange
}: {
  data: { color?: string } | undefined;
  onChange: (next: { color: string }) => void;
}) => {
  const color = data?.color ?? '#2563eb';
  const rgb = hexToRgb(color);
  const rgbLabel = rgb ? `rgb(${rgb.r}, ${rgb.g}, ${rgb.b})` : 'Invalid HEX';
  const rgbaLabel = rgb
    ? `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, 1)`
    : 'Invalid HEX';
  const pickFromPage = async () => {
    if (!('EyeDropper' in window)) return;
    try {
      const dropper = new (window as Window & { EyeDropper: typeof EyeDropper })
        .EyeDropper();
      const result = await dropper.open();
      onChange({ color: result.sRGBHex });
    } catch {
      // User cancelled the eye dropper.
    }
  };
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <input
          type="color"
          value={color}
          onChange={(event) => onChange({ color: event.target.value })}
          className="h-10 w-10 rounded border border-slate-700 bg-slate-800"
        />
        <div className="text-xs text-slate-400">
          Pick a color to copy its hex value.
        </div>
      </div>
      <button
        type="button"
        className="w-full rounded bg-slate-800 px-2 py-1 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
        onClick={pickFromPage}
        disabled={!('EyeDropper' in window)}
      >
        {('EyeDropper' in window) ? 'Pick from page' : 'EyeDropper not supported'}
      </button>
      <div className="flex items-center gap-2">
        <input
          type="text"
          value={color}
          onChange={(event) => onChange({ color: event.target.value })}
          className="flex-1 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        />
        <button
          type="button"
          className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
          onClick={() => navigator.clipboard.writeText(color)}
        >
          Copy
        </button>
      </div>
      <div className="space-y-1 text-[11px] text-slate-400">
        <div>HEX: <span className="text-slate-200">{color}</span></div>
        <div>RGB: <span className="text-slate-200">{rgbLabel}</span></div>
        <div>RGBA: <span className="text-slate-200">{rgbaLabel}</span></div>
      </div>
    </div>
  );
};

type CodeInjectorData = {
  mode?: 'css' | 'js';
  scope?: 'current' | 'all';
  code?: string;
};

type HeaderInspectorData = {
  url?: string;
  status?: number;
  headers?: { name: string; value: string }[];
  error?: string;
  updatedAt?: number;
};

type TechFingerprintData = {
  url?: string;
  findings?: { label: string; value: string }[];
  updatedAt?: number;
};

type RobotsViewerData = {
  url?: string;
  content?: string;
  error?: string;
  updatedAt?: number;
};

type FormFuzzerData = {
  forms?: {
    index: number;
    action: string;
    method: string;
    inputs: { name: string; type: string; placeholder: string }[];
  }[];
  selectedFormIndex?: number;
  payloads?: string[];
  selectedPayload?: string;
  customPayload?: string;
  status?: string;
};

type UrlCodecData = {
  input?: string;
  output?: string;
  mode?: 'encode' | 'decode';
  error?: string;
};

type ParamAnalyzerData = {
  url?: string;
  params?: { key: string; value: string }[];
};

type LinkExtractorData = {
  internal?: string[];
  external?: string[];
  updatedAt?: number;
};

type DomSnapshotData = {
  html?: string;
  updatedAt?: number;
};

type AssetMapperData = {
  images?: string[];
  scripts?: string[];
  styles?: string[];
  updatedAt?: number;
};

type RequestLogData = {
  entries?: {
    name: string;
    initiatorType: string;
    duration: number;
    transferSize: number;
    startTime: number;
  }[];
};

type PayloadReplayData = {
  url?: string;
  method?: string;
  headers?: string;
  body?: string;
  responseStatus?: number;
  responseHeaders?: { name: string; value: string }[];
  responseBody?: string;
  error?: string;
};

type CorsCheckData = {
  url?: string;
  result?: {
    status?: number;
    acao?: string | null;
    acc?: string | null;
    methods?: string | null;
    headers?: string | null;
  };
  error?: string;
  updatedAt?: number;
};

type JsonMinifierData = {
  input?: string;
  output?: string;
  error?: string;
};

const defaultPayloads = [
  `"' OR '1'='1`,
  '<script>alert(1)</script>',
  '../../etc/passwd',
  '{{7*7}}',
  '${7*7}'
];

const parseHeadersInput = (value: string) =>
  value
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const index = line.indexOf(':');
      if (index === -1) return null;
      return {
        name: line.slice(0, index).trim(),
        value: line.slice(index + 1).trim()
      };
    })
    .filter(
      (entry): entry is { name: string; value: string } =>
        Boolean(entry?.name)
    );

const parseQueryParams = (url: string) => {
  try {
    const parsed = new URL(url);
    return Array.from(parsed.searchParams.entries()).map(([key, value]) => ({
      key,
      value
    }));
  } catch {
    return [];
  }
};

const buildUrlWithParams = (url: string, params: { key: string; value: string }[]) => {
  try {
    const parsed = new URL(url);
    parsed.search = '';
    params
      .filter((entry) => entry.key.trim().length > 0)
      .forEach((entry) => parsed.searchParams.append(entry.key, entry.value));
    return parsed.toString();
  } catch {
    return url;
  }
};

const extractLinksFromDocument = () => {
  const anchors = Array.from(document.querySelectorAll('a[href]'));
  const internal: string[] = [];
  const external: string[] = [];
  const origin = window.location.origin;
  const seen = new Set<string>();
  anchors.forEach((anchor) => {
    const href = anchor.getAttribute('href');
    if (!href) return;
    let absolute: string;
    try {
      absolute = new URL(href, origin).toString();
    } catch {
      return;
    }
    if (seen.has(absolute)) return;
    seen.add(absolute);
    if (absolute.startsWith(origin)) {
      internal.push(absolute);
    } else {
      external.push(absolute);
    }
  });
  return { internal, external };
};

const sanitizeHtmlSnapshot = (rawHtml: string) => {
  const parser = new DOMParser();
  const doc = parser.parseFromString(rawHtml, 'text/html');
  doc.querySelectorAll('script').forEach((script) => script.remove());
  return doc.documentElement.outerHTML;
};

const mapAssetsFromDocument = () => {
  const images = Array.from(document.images)
    .map((img) => img.currentSrc || img.src)
    .filter(Boolean);
  const scripts = Array.from(document.scripts)
    .map((script) => script.src)
    .filter(Boolean);
  const styles = Array.from(document.querySelectorAll('link[rel="stylesheet"]'))
    .map((link) => (link as HTMLLinkElement).href)
    .filter(Boolean);
  return { images, scripts, styles };
};

const detectTechnologies = () => {
  const findings: { label: string; value: string }[] = [];
  const generator = document
    .querySelector('meta[name="generator"]')
    ?.getAttribute('content');
  if (generator) {
    findings.push({ label: 'Meta Generator', value: generator });
  }
  if ((window as Window & { __REACT_DEVTOOLS_GLOBAL_HOOK__?: unknown })
    .__REACT_DEVTOOLS_GLOBAL_HOOK__) {
    findings.push({ label: 'Framework', value: 'React' });
  }
  if ((window as Window & { __VUE_DEVTOOLS_GLOBAL_HOOK__?: unknown })
    .__VUE_DEVTOOLS_GLOBAL_HOOK__) {
    findings.push({ label: 'Framework', value: 'Vue' });
  }
  if (document.querySelector('[ng-version]')) {
    findings.push({ label: 'Framework', value: 'Angular' });
  }
  const scriptSources = Array.from(document.scripts)
    .map((script) => script.src)
    .filter(Boolean);
  if (scriptSources.some((src) => src.includes('wp-content'))) {
    findings.push({ label: 'CMS', value: 'WordPress' });
  }
  if (scriptSources.some((src) => src.includes('shopify'))) {
    findings.push({ label: 'Platform', value: 'Shopify' });
  }
  if (scriptSources.some((src) => src.includes('cdn.jsdelivr.net/npm/bootstrap'))) {
    findings.push({ label: 'UI Library', value: 'Bootstrap' });
  }
  return findings;
};

const getFormsSnapshot = () =>
  Array.from(document.querySelectorAll('form')).map((form, index) => {
    const inputs = Array.from(
      form.querySelectorAll('input, textarea, select')
    ).map((input) => ({
      name: input.getAttribute('name') ?? '',
      type: input.getAttribute('type') ?? input.tagName.toLowerCase(),
      placeholder: input.getAttribute('placeholder') ?? ''
    }));
    return {
      index,
      action: form.getAttribute('action') ?? window.location.href,
      method: (form.getAttribute('method') ?? 'GET').toUpperCase(),
      inputs
    };
  });

const applyPayloadToForm = (formIndex: number, payload: string) => {
  const form = document.querySelectorAll('form')[formIndex];
  if (!form) return false;
  const fields = Array.from(
    form.querySelectorAll('input, textarea, select')
  ) as Array<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>;
  fields.forEach((field) => {
    if (field instanceof HTMLInputElement) {
      const type = field.type.toLowerCase();
      if (['checkbox', 'radio', 'submit', 'button', 'file'].includes(type)) {
        return;
      }
    }
    if (field instanceof HTMLSelectElement) {
      field.value = field.options[0]?.value ?? '';
    } else {
      field.value = payload;
    }
    field.dispatchEvent(new Event('input', { bubbles: true }));
    field.dispatchEvent(new Event('change', { bubbles: true }));
  });
  return true;
};
const CodeInjectorTool = ({
  data,
  onChange,
  onInject
}: {
  data: CodeInjectorData | undefined;
  onChange: (next: CodeInjectorData) => void;
  onInject: (payload: Required<CodeInjectorData>) => Promise<void>;
}) => {
  const [isInjecting, setIsInjecting] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const mode = data?.mode ?? 'css';
  const scope = data?.scope ?? 'current';
  const code = data?.code ?? '';
  const update = (next: Partial<CodeInjectorData>) =>
    onChange({ mode, scope, code, ...next });

  const handleInject = async () => {
    if (!code.trim()) {
      setStatus('Add some code to inject.');
      return;
    }
    setIsInjecting(true);
    setStatus(null);
    try {
      await onInject({ mode, scope, code });
      setStatus('Injection sent.');
    } catch {
      setStatus('Injection failed. Check permissions.');
    } finally {
      setIsInjecting(false);
    }
  };

  return (
    <div className="space-y-3">
      <div className="space-y-2">
        <div className="text-[11px] uppercase tracking-[0.2em] text-slate-500">
          Injection Type
        </div>
        <div className="flex gap-2">
          {(['css', 'js'] as const).map((value) => (
            <button
              key={value}
              type="button"
              onClick={() => update({ mode: value })}
              className={`flex-1 rounded px-2 py-1 text-[11px] border transition-colors ${
                mode === value
                  ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              {value.toUpperCase()}
            </button>
          ))}
        </div>
        {mode === 'js' ? (
          <div className="text-[11px] text-amber-300">
            Only inject JavaScript you fully understand and trust.
          </div>
        ) : null}
      </div>

      <div className="space-y-2">
        <div className="text-[11px] uppercase tracking-[0.2em] text-slate-500">
          Target
        </div>
        <div className="flex gap-2">
          {([
            { value: 'current', label: 'Current Tab' },
            { value: 'all', label: 'All Tabs' }
          ] as const).map((entry) => (
            <button
              key={entry.value}
              type="button"
              onClick={() => update({ scope: entry.value })}
              className={`flex-1 rounded px-2 py-1 text-[11px] border transition-colors ${
                scope === entry.value
                  ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              {entry.label}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-2">
        <textarea
          value={code}
          onChange={(event) => update({ code: event.target.value })}
          placeholder={mode === 'css' ? '/* Paste CSS here */' : '// Paste JS here'}
          rows={6}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors placeholder:text-slate-500 font-mono"
        />
        {status ? (
          <div className="text-[11px] text-slate-400">{status}</div>
        ) : null}
      </div>

      <button
        type="button"
        onClick={handleInject}
        disabled={isInjecting}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        {isInjecting ? 'Injecting...' : 'Inject Code'}
      </button>
    </div>
  );
};

const HeaderInspectorTool = ({
  data,
  onRefresh
}: {
  data: HeaderInspectorData | undefined;
  onRefresh: () => Promise<void>;
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const headers = data?.headers ?? [];
  const updatedAt = data?.updatedAt;
  const securityHeaders = new Set([
    'content-security-policy',
    'strict-transport-security',
    'x-frame-options'
  ]);

  const handleRefresh = async () => {
    setIsLoading(true);
    await onRefresh();
    setIsLoading(false);
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs text-slate-200">Current Tab Headers</div>
          <div className="text-[11px] text-slate-500">
            {data?.url ?? 'No data yet'}
          </div>
        </div>
        <button
          type="button"
          onClick={handleRefresh}
          disabled={isLoading}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          {isLoading ? 'Loading...' : 'Refresh'}
        </button>
      </div>

      {data?.error ? (
        <div className="rounded border border-rose-500/30 bg-rose-500/10 px-2 py-1 text-[11px] text-rose-200">
          {data.error}
        </div>
      ) : null}

      {updatedAt ? (
        <div className="text-[10px] text-slate-500">
          Updated {new Date(updatedAt).toLocaleTimeString()}
        </div>
      ) : null}

      <div className="space-y-2">
        {headers.length === 0 ? (
          <div className="text-[11px] text-slate-500">
            No headers captured yet.
          </div>
        ) : (
          headers.map((header) => {
            const isSecurity = securityHeaders.has(header.name.toLowerCase());
            return (
              <div
                key={`${header.name}-${header.value}`}
                className={`rounded border px-2 py-1 text-[11px] ${
                  isSecurity
                    ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
                    : 'border-slate-800 bg-slate-800/60 text-slate-300'
                }`}
              >
                <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                  {header.name}
                </div>
                <div className="break-words">{header.value}</div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

const TechFingerprintTool = ({
  data,
  onRefresh
}: {
  data: TechFingerprintData | undefined;
  onRefresh: () => Promise<void>;
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const findings = data?.findings ?? [];

  const handleRefresh = async () => {
    setIsLoading(true);
    await onRefresh();
    setIsLoading(false);
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs text-slate-200">Tech Fingerprint</div>
          <div className="text-[11px] text-slate-500">{data?.url ?? ''}</div>
        </div>
        <button
          type="button"
          onClick={handleRefresh}
          disabled={isLoading}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          {isLoading ? 'Scanning...' : 'Scan'}
        </button>
      </div>
      {findings.length === 0 ? (
        <div className="text-[11px] text-slate-500">
          No signals yet. Run a scan.
        </div>
      ) : (
        findings.map((finding, index) => (
          <div
            key={`${finding.label}-${finding.value}-${index}`}
            className="rounded border border-slate-800 bg-slate-800/60 px-2 py-1 text-[11px] text-slate-300"
          >
            <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
              {finding.label}
            </div>
            <div className="break-words">{finding.value}</div>
          </div>
        ))
      )}
    </div>
  );
};

const RobotsViewerTool = ({
  data,
  onRefresh
}: {
  data: RobotsViewerData | undefined;
  onRefresh: () => Promise<void>;
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const handleRefresh = async () => {
    setIsLoading(true);
    await onRefresh();
    setIsLoading(false);
  };
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs text-slate-200">Robots.txt Viewer</div>
          <div className="text-[11px] text-slate-500">{data?.url ?? ''}</div>
        </div>
        <button
          type="button"
          onClick={handleRefresh}
          disabled={isLoading}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          {isLoading ? 'Loading...' : 'Fetch'}
        </button>
      </div>
      {data?.error ? (
        <div className="rounded border border-rose-500/30 bg-rose-500/10 px-2 py-1 text-[11px] text-rose-200">
          {data.error}
        </div>
      ) : null}
      <textarea
        value={data?.content ?? ''}
        readOnly
        rows={8}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none"
        placeholder="robots.txt will appear here..."
      />
    </div>
  );
};

const FormFuzzerTool = ({
  data,
  onChange,
  onRefresh,
  onApply
}: {
  data: FormFuzzerData | undefined;
  onChange: (next: FormFuzzerData) => void;
  onRefresh: () => Promise<void>;
  onApply: (formIndex: number, payload: string) => Promise<boolean>;
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const payloads = data?.payloads ?? defaultPayloads;
  const selectedPayload = data?.selectedPayload ?? payloads[0] ?? '';
  const selectedFormIndex = data?.selectedFormIndex ?? 0;
  const forms = data?.forms ?? [];
  const customPayload = data?.customPayload ?? '';
  const update = (next: Partial<FormFuzzerData>) =>
    onChange({
      payloads,
      selectedPayload,
      selectedFormIndex,
      forms,
      customPayload,
      status: data?.status,
      ...next
    });

  const handleRefresh = async () => {
    setIsLoading(true);
    await onRefresh();
    setIsLoading(false);
  };

  const handleApply = async () => {
    const payload =
      selectedPayload === '__custom__' ? customPayload : selectedPayload;
    if (!payload) {
      update({ status: 'Choose a payload to apply.' });
      return;
    }
    const ok = await onApply(selectedFormIndex, payload);
    update({
      status: ok ? 'Payload applied.' : 'Could not apply payload.'
    });
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">Form Fuzzer</div>
        <button
          type="button"
          onClick={handleRefresh}
          disabled={isLoading}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          {isLoading ? 'Scanning...' : 'Refresh Forms'}
        </button>
      </div>

      {forms.length === 0 ? (
        <div className="text-[11px] text-slate-500">
          No forms detected on this page.
        </div>
      ) : (
        <div className="space-y-2">
          <div className="text-[11px] uppercase tracking-[0.2em] text-slate-500">
            Select Form
          </div>
          <div className="space-y-1">
            {forms.map((form) => (
              <button
                key={form.index}
                type="button"
                onClick={() => update({ selectedFormIndex: form.index })}
                className={`w-full rounded px-2 py-1 text-[11px] border text-left transition-colors ${
                  selectedFormIndex === form.index
                    ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                    : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                }`}
              >
                {form.method} • {form.action}
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="space-y-2">
        <div className="text-[11px] uppercase tracking-[0.2em] text-slate-500">
          Payload
        </div>
        <div className="space-y-1">
          {payloads.map((payload) => (
            <button
              key={payload}
              type="button"
              onClick={() => update({ selectedPayload: payload })}
              className={`w-full rounded px-2 py-1 text-[11px] border text-left transition-colors ${
                selectedPayload === payload
                  ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              {payload}
            </button>
          ))}
          <button
            type="button"
            onClick={() => update({ selectedPayload: '__custom__' })}
            className={`w-full rounded px-2 py-1 text-[11px] border text-left transition-colors ${
              selectedPayload === '__custom__'
                ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
            }`}
          >
            Custom Payload
          </button>
        </div>
        {selectedPayload === '__custom__' ? (
          <input
            type="text"
            value={customPayload}
            onChange={(event) => update({ customPayload: event.target.value })}
            className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
            placeholder="Enter custom payload"
          />
        ) : null}
      </div>

      {data?.status ? (
        <div className="text-[11px] text-slate-500">{data.status}</div>
      ) : null}

      <button
        type="button"
        onClick={handleApply}
        disabled={forms.length === 0}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Apply Payload
      </button>
    </div>
  );
};

const UrlCodecTool = ({
  data,
  onChange
}: {
  data: UrlCodecData | undefined;
  onChange: (next: UrlCodecData) => void;
}) => {
  const mode = data?.mode ?? 'encode';
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const error = data?.error;

  const updateInput = (value: string) => {
    try {
      const result = mode === 'encode' ? encodeURIComponent(value) : decodeURIComponent(value);
      onChange({ mode, input: value, output: result, error: undefined });
    } catch {
      onChange({ mode, input: value, output: '', error: 'Unable to decode input.' });
    }
  };

  const toggleMode = () => {
    const nextMode = mode === 'encode' ? 'decode' : 'encode';
    try {
      const result = nextMode === 'encode'
        ? encodeURIComponent(input)
        : decodeURIComponent(input);
      onChange({ mode: nextMode, input, output: result, error: undefined });
    } catch {
      onChange({ mode: nextMode, input, output: '', error: 'Unable to decode input.' });
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">URL Encoder / Decoder</div>
        <button
          type="button"
          onClick={toggleMode}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          {mode === 'encode' ? 'Encode' : 'Decode'}
        </button>
      </div>
      <textarea
        value={input}
        onChange={(event) => updateInput(event.target.value)}
        rows={4}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors"
        placeholder="Enter text to encode/decode"
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <textarea
        value={output}
        readOnly
        rows={4}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none"
        placeholder="Result"
      />
      <button
        type="button"
        onClick={() => navigator.clipboard.writeText(output)}
        disabled={!output}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Copy Result
      </button>
    </div>
  );
};

const ParamAnalyzerTool = ({
  data,
  onChange,
  onRefresh
}: {
  data: ParamAnalyzerData | undefined;
  onChange: (next: ParamAnalyzerData) => void;
  onRefresh: () => Promise<void>;
}) => {
  const params = data?.params ?? [];
  const url = data?.url ?? window.location.href;
  const updateParams = (nextParams: { key: string; value: string }[]) =>
    onChange({ url, params: nextParams });
  const applyUrl = (nextUrl: string) => {
    navigator.clipboard.writeText(nextUrl);
    window.location.href = nextUrl;
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs text-slate-200">Param Analyzer</div>
          <div className="text-[11px] text-slate-500">{url}</div>
        </div>
        <button
          type="button"
          onClick={onRefresh}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Refresh
        </button>
      </div>

      {params.length === 0 ? (
        <div className="text-[11px] text-slate-500">
          No query parameters detected.
        </div>
      ) : null}

      <div className="space-y-2">
        {params.map((param, index) => (
          <div key={`${param.key}-${index}`} className="flex gap-2">
            <input
              type="text"
              value={param.key}
              onChange={(event) => {
                const next = [...params];
                next[index] = { ...next[index], key: event.target.value };
                updateParams(next);
              }}
              className="w-1/3 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
              placeholder="Key"
            />
            <input
              type="text"
              value={param.value}
              onChange={(event) => {
                const next = [...params];
                next[index] = { ...next[index], value: event.target.value };
                updateParams(next);
              }}
              className="flex-1 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
              placeholder="Value"
            />
            <button
              type="button"
              onClick={() => updateParams(params.filter((_, i) => i !== index))}
              className="rounded bg-slate-800 px-2 text-[11px] text-slate-400 hover:text-slate-200"
            >
              ×
            </button>
          </div>
        ))}
      </div>

      <button
        type="button"
        onClick={() => updateParams([...params, { key: '', value: '' }])}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Add Param
      </button>

      <button
        type="button"
        onClick={() => {
          const nextUrl = buildUrlWithParams(url, params);
          navigator.clipboard.writeText(nextUrl);
        }}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Copy Updated URL
      </button>
      <button
        type="button"
        onClick={() => applyUrl(buildUrlWithParams(url, params))}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Open Updated URL
      </button>
    </div>
  );
};

const LinkExtractorTool = ({
  data,
  onRefresh
}: {
  data: LinkExtractorData | undefined;
  onRefresh: () => Promise<void>;
}) => {
  const internal = data?.internal ?? [];
  const external = data?.external ?? [];

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">Link Extractor</div>
        <button
          type="button"
          onClick={onRefresh}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Refresh
        </button>
      </div>
      <div className="text-[11px] text-slate-500">
        {internal.length} internal • {external.length} external
      </div>
      <div className="space-y-2 max-h-40 overflow-y-auto no-scrollbar">
        {internal.map((link) => (
          <div key={link} className="text-[11px] text-slate-300 break-words">
            {link}
          </div>
        ))}
        {external.map((link) => (
          <div key={link} className="text-[11px] text-slate-400 break-words">
            {link}
          </div>
        ))}
      </div>
      <div className="flex gap-2">
        <button
          type="button"
          onClick={() =>
            navigator.clipboard.writeText(
              JSON.stringify({ internal, external }, null, 2)
            )
          }
          className="flex-1 rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
        >
          Copy JSON
        </button>
        <button
          type="button"
          onClick={() => {
            const csv = [...internal, ...external].join('\n');
            navigator.clipboard.writeText(csv);
          }}
          className="flex-1 rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
        >
          Copy CSV
        </button>
      </div>
    </div>
  );
};

const DomSnapshotTool = ({
  data,
  onCapture
}: {
  data: DomSnapshotData | undefined;
  onCapture: () => Promise<void>;
}) => {
  const html = data?.html ?? '';
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">DOM Snapshot</div>
        <button
          type="button"
          onClick={onCapture}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Capture
        </button>
      </div>
      <textarea
        value={html}
        readOnly
        rows={6}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none"
        placeholder="Snapshot will appear here..."
      />
      <button
        type="button"
        onClick={() => navigator.clipboard.writeText(html)}
        disabled={!html}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Copy HTML
      </button>
    </div>
  );
};

const AssetMapperTool = ({
  data,
  onRefresh
}: {
  data: AssetMapperData | undefined;
  onRefresh: () => Promise<void>;
}) => {
  const images = data?.images ?? [];
  const scripts = data?.scripts ?? [];
  const styles = data?.styles ?? [];

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">Asset Mapper</div>
        <button
          type="button"
          onClick={onRefresh}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Refresh
        </button>
      </div>
      <div className="text-[11px] text-slate-500">
        {images.length} images • {scripts.length} scripts • {styles.length} styles
      </div>
      <div className="space-y-2 max-h-40 overflow-y-auto no-scrollbar text-[11px] text-slate-300">
        {images.map((asset) => (
          <div key={`img-${asset}`} className="break-words">
            {asset}
          </div>
        ))}
        {scripts.map((asset) => (
          <div key={`script-${asset}`} className="break-words text-slate-400">
            {asset}
          </div>
        ))}
        {styles.map((asset) => (
          <div key={`style-${asset}`} className="break-words text-slate-500">
            {asset}
          </div>
        ))}
      </div>
    </div>
  );
};

const RequestLogTool = ({
  data,
  onClear
}: {
  data: RequestLogData | undefined;
  onClear: () => Promise<void>;
}) => {
  const entries = data?.entries ?? [];
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">Request Log</div>
        <button
          type="button"
          onClick={onClear}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Clear
        </button>
      </div>
      {entries.length === 0 ? (
        <div className="text-[11px] text-slate-500">
          No requests captured yet.
        </div>
      ) : (
        <div className="max-h-40 overflow-y-auto no-scrollbar space-y-1">
          {entries.map((entry, index) => (
            <div
              key={`${entry.name}-${entry.startTime}-${index}`}
              className="rounded border border-slate-800 bg-slate-800/60 px-2 py-1 text-[11px] text-slate-300"
            >
              <div className="break-words">{entry.name}</div>
              <div className="text-[10px] text-slate-500">
                {entry.initiatorType} • {entry.duration.toFixed(1)}ms
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const PayloadReplayTool = ({
  data,
  onChange,
  onSend
}: {
  data: PayloadReplayData | undefined;
  onChange: (next: PayloadReplayData) => void;
  onSend: (payload: {
    url: string;
    method: string;
    headers: { name: string; value: string }[];
    body: string;
  }) => Promise<void>;
}) => {
  const url = data?.url ?? '';
  const method = data?.method ?? 'GET';
  const headers = data?.headers ?? '';
  const body = data?.body ?? '';
  const update = (next: Partial<PayloadReplayData>) => onChange({ ...data, ...next });

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Payload Replay</div>
      <input
        type="text"
        value={url}
        onChange={(event) => update({ url: event.target.value })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="https://example.com/api"
      />
      <div className="flex gap-2">
        {['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].map((option) => (
          <button
            key={option}
            type="button"
            onClick={() => update({ method: option })}
            className={`flex-1 rounded px-2 py-1 text-[11px] border transition-colors ${
              method === option
                ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
            }`}
          >
            {option}
          </button>
        ))}
      </div>
      <textarea
        value={headers}
        onChange={(event) => update({ headers: event.target.value })}
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Header: value"
      />
      <textarea
        value={body}
        onChange={(event) => update({ body: event.target.value })}
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Request body"
      />
      <button
        type="button"
        onClick={() =>
          onSend({
            url,
            method,
            headers: parseHeadersInput(headers),
            body
          })
        }
        disabled={!url}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Send Request
      </button>
      {data?.error ? (
        <div className="text-[11px] text-rose-300">{data.error}</div>
      ) : null}
      {typeof data?.responseStatus === 'number' ? (
        <div className="text-[11px] text-slate-500">
          Status: {data.responseStatus}
        </div>
      ) : null}
      {data?.responseHeaders?.length ? (
        <div className="space-y-1">
          {data.responseHeaders.map((header) => (
            <div key={`${header.name}-${header.value}`} className="text-[10px] text-slate-500">
              {header.name}: {header.value}
            </div>
          ))}
        </div>
      ) : null}
      {data?.responseBody ? (
        <textarea
          value={data.responseBody}
          readOnly
          rows={4}
          className="w-full rounded bg-slate-900 text-slate-200 text-xs px-2 py-2 border border-slate-800 focus:outline-none"
        />
      ) : null}
    </div>
  );
};

const CorsCheckTool = ({
  data,
  onChange,
  onCheck
}: {
  data: CorsCheckData | undefined;
  onChange: (next: CorsCheckData) => void;
  onCheck: (url: string) => Promise<void>;
}) => {
  const url = data?.url ?? '';
  const result = data?.result;
  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">CORS Check</div>
      <input
        type="text"
        value={url}
        onChange={(event) => onChange({ ...data, url: event.target.value })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="https://example.com"
      />
      <button
        type="button"
        onClick={() => onCheck(url)}
        disabled={!url}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Run Check
      </button>
      {data?.error ? (
        <div className="text-[11px] text-rose-300">{data.error}</div>
      ) : null}
      {result ? (
        <div className="space-y-2 text-[11px] text-slate-400">
          <div>Status: {result.status ?? 'Unknown'}</div>
          <div>ACAO: {result.acao ?? 'None'}</div>
          <div>ACAC: {result.acc ?? 'None'}</div>
          <div>Allow-Methods: {result.methods ?? 'None'}</div>
          <div>Allow-Headers: {result.headers ?? 'None'}</div>
        </div>
      ) : null}
    </div>
  );
};

const JsonMinifierTool = ({
  data,
  onChange
}: {
  data: JsonMinifierData | undefined;
  onChange: (next: JsonMinifierData) => void;
}) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handleMinify = () => {
    try {
      const parsed = JSON.parse(input);
      const minified = JSON.stringify(parsed);
      onChange({ input, output: minified, error: '' });
    } catch (err) {
      onChange({
        input,
        output: '',
        error: err instanceof Error ? err.message : 'Invalid JSON'
      });
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">JSON Minifier</div>
      <textarea
        value={input}
        onChange={(event) => onChange({ input: event.target.value, output, error })}
        rows={6}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Paste JSON here..."
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <div className="flex gap-2">
        <button
          type="button"
          onClick={handleMinify}
          disabled={!input.trim()}
          className="flex-1 rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          Minify
        </button>
        <button
          type="button"
          onClick={() => navigator.clipboard.writeText(output)}
          disabled={!output}
          className="flex-1 rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          Copy
        </button>
      </div>
      <textarea
        value={output}
        readOnly
        rows={6}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Minified output..."
      />
    </div>
  );
};

const toolRegistry: ToolRegistryEntry[] = [
  {
    id: 'codeInjector',
    title: 'Code Injector',
    subtitle: 'Inject CSS or JS',
    category: 'Web Dev',
    icon: faCode,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <CodeInjectorTool
        data={data as CodeInjectorData | undefined}
        onChange={(next) => onChange(next)}
        onInject={async (payload) => {
          await chrome.runtime.sendMessage({
            type: 'xcalibr-inject-code',
            payload
          });
        }}
      />
    )
  },
  {
    id: 'headerInspector',
    title: 'Header Inspector',
    subtitle: 'Security headers',
    category: 'CyberSec',
    icon: faShieldHalved,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <HeaderInspectorTool
        data={data as HeaderInspectorData | undefined}
        onRefresh={async () => {
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-fetch-headers'
          });
          onChange(result);
        }}
      />
    )
  },
  {
    id: 'techFingerprint',
    title: 'Tech Fingerprint',
    subtitle: 'Framework signals',
    category: 'CyberSec',
    icon: faFingerprint,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <TechFingerprintTool
        data={data as TechFingerprintData | undefined}
        onRefresh={async () => {
          const findings = detectTechnologies();
          onChange({
            url: window.location.href,
            findings,
            updatedAt: Date.now()
          });
        }}
      />
    )
  },
  {
    id: 'robotsViewer',
    title: 'Robots.txt Viewer',
    subtitle: 'Site crawl rules',
    category: 'CyberSec',
    icon: faRobot,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <RobotsViewerTool
        data={data as RobotsViewerData | undefined}
        onRefresh={async () => {
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-fetch-robots'
          });
          onChange(result);
        }}
      />
    )
  },
  {
    id: 'formFuzzer',
    title: 'Form Fuzzer',
    subtitle: 'Inject payloads',
    category: 'CyberSec',
    icon: faFlask,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <FormFuzzerTool
        data={data as FormFuzzerData | undefined}
        onChange={(next) => onChange(next)}
        onRefresh={async () => {
          const payloads = (data as FormFuzzerData | undefined)?.payloads ?? defaultPayloads;
          onChange({
            forms: getFormsSnapshot(),
            payloads,
            selectedFormIndex: 0,
            selectedPayload: payloads[0] ?? ''
          });
        }}
        onApply={async (formIndex, payload) =>
          applyPayloadToForm(formIndex, payload)
        }
      />
    )
  },
  {
    id: 'urlCodec',
    title: 'URL Encoder/Decoder',
    subtitle: 'Encode strings',
    category: 'CyberSec',
    icon: faWaveSquare,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <UrlCodecTool data={data as UrlCodecData | undefined} onChange={onChange} />
    )
  },
  {
    id: 'paramAnalyzer',
    title: 'Param Analyzer',
    subtitle: 'Edit query params',
    category: 'CyberSec',
    icon: faSliders,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <ParamAnalyzerTool
        data={data as ParamAnalyzerData | undefined}
        onChange={onChange}
        onRefresh={async () => {
          const url = window.location.href;
          onChange({ url, params: parseQueryParams(url) });
        }}
      />
    )
  },
  {
    id: 'linkExtractor',
    title: 'Link Extractor',
    subtitle: 'Internal vs external',
    category: 'CyberSec',
    icon: faLink,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <LinkExtractorTool
        data={data as LinkExtractorData | undefined}
        onRefresh={async () => {
          const links = extractLinksFromDocument();
          onChange({ ...links, updatedAt: Date.now() });
        }}
      />
    )
  },
  {
    id: 'domSnapshot',
    title: 'DOM Snapshot',
    subtitle: 'Capture HTML',
    category: 'CyberSec',
    icon: faFileCode,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <DomSnapshotTool
        data={data as DomSnapshotData | undefined}
        onCapture={async () => {
          const raw = document.documentElement.outerHTML;
          onChange({ html: sanitizeHtmlSnapshot(raw), updatedAt: Date.now() });
        }}
      />
    )
  },
  {
    id: 'assetMapper',
    title: 'Asset Mapper',
    subtitle: 'Images, scripts, CSS',
    category: 'CyberSec',
    icon: faSitemap,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <AssetMapperTool
        data={data as AssetMapperData | undefined}
        onRefresh={async () => {
          const assets = mapAssetsFromDocument();
          onChange({ ...assets, updatedAt: Date.now() });
        }}
      />
    )
  },
  {
    id: 'requestLog',
    title: 'Request Log',
    subtitle: 'Network activity',
    category: 'CyberSec',
    icon: faTable,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <RequestLogTool
        data={data as RequestLogData | undefined}
        onClear={async () => onChange({ entries: [] })}
      />
    )
  },
  {
    id: 'payloadReplay',
    title: 'Payload Replay',
    subtitle: 'Replay HTTP requests',
    category: 'CyberSec',
    icon: faBug,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <PayloadReplayTool
        data={data as PayloadReplayData | undefined}
        onChange={onChange}
        onSend={async (payload) => {
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-payload-replay',
            payload
          });
          onChange({ ...data, ...result });
        }}
      />
    )
  },
  {
    id: 'corsCheck',
    title: 'CORS Check',
    subtitle: 'Inspect CORS headers',
    category: 'CyberSec',
    icon: faGlobe,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <CorsCheckTool
        data={data as CorsCheckData | undefined}
        onChange={onChange}
        onCheck={async (url) => {
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-cors-check',
            payload: { url }
          });
          onChange({ url, ...result });
        }}
      />
    )
  },
  {
    id: 'jsonMinifier',
    title: 'JSON Minifier',
    subtitle: 'Compress JSON',
    category: 'Database',
    icon: faCompress,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <JsonMinifierTool
        data={data as JsonMinifierData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'colorPicker',
    title: 'Color Picker',
    subtitle: 'Grab hex/rgb',
    category: 'Front End',
    icon: faEyeDropper,
    hover: 'group-hover:border-blue-500 group-hover:text-blue-400',
    render: (data, onChange) => (
      <ColorPickerTool
        data={data as { color?: string } | undefined}
        onChange={(next) => onChange(next)}
      />
    )
  }
];

const getToolEntry = (toolId: string) =>
  toolRegistry.find((tool) => tool.id === toolId) ?? null;

const App = () => {
  const [state, setState] = useState(DEFAULT_STATE);
  const [dragOffsetY, setDragOffsetY] = useState<number | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [dragAnchored, setDragAnchored] = useState<boolean | null>(null);
  const [spotlightOpen, setSpotlightOpen] = useState(false);
  const [spotlightQuery, setSpotlightQuery] = useState('');
  const [pickerRect, setPickerRect] = useState<DOMRect | null>(null);
  const [pickerLabel, setPickerLabel] = useState('');
  const [pickerNotice, setPickerNotice] = useState<string | null>(null);
  const [showScraperHelp, setShowScraperHelp] = useState(false);
  const menuBarRef = useRef<HTMLDivElement | null>(null);
  const spotlightInputRef = useRef<HTMLInputElement | null>(null);
  const requestLogSeenRef = useRef<Set<string>>(new Set());
  const toolDragRef = useRef<{
    toolId: string;
    offsetX: number;
    offsetY: number;
    startX: number;
    startY: number;
    moved: boolean;
    windowEl: HTMLElement | null;
  } | null>(null);
  const dragStateRef = useRef({
    startY: 0,
    startOffset: 0,
    moved: false,
    lastOffset: 0,
    unanchored: false
  });
  const iconSizeClass = 'w-3 h-3';
  const menuHeight = 550;
  const menuBarHeight = 32;

  const menuItems = useMemo(() => {
    const scraperItems =
      state.scrapers.length > 0
        ? state.scrapers.map((scraper) => ({
            label: scraper.name,
            scraperId: scraper.id
          }))
        : ['No saved scrapers'];
    const scraperMenu = {
      label: 'Scraper',
      items: [
        { label: 'Make Scraper', action: 'makeScraper' },
        { label: 'Scraper List', items: scraperItems }
      ]
    };
    const items = [...baseMenuBarItems];
    const cyberIndex = items.findIndex((item) => item.label === 'CyberSec');
    if (cyberIndex === -1) {
      items.push(scraperMenu);
    } else {
      items.splice(cyberIndex + 1, 0, scraperMenu);
    }
    return items;
  }, [state.scrapers]);

  useEffect(() => {
    let mounted = true;
    getState().then((next) => {
      if (mounted) setState(next);
    });
    const unsubscribe = subscribeState(setState);
    return () => {
      mounted = false;
      unsubscribe();
    };
  }, []);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (!(event.metaKey && event.shiftKey)) return;
      if (event.key.toLowerCase() !== 'p') return;
      event.preventDefault();
      setSpotlightOpen(true);
      setSpotlightQuery('');
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  useEffect(() => {
    if (!spotlightOpen) return;
    requestAnimationFrame(() => spotlightInputRef.current?.focus());
  }, [spotlightOpen]);

  const searchableTools = useMemo(
    () =>
      toolRegistry.map((tool) => ({
        id: tool.id,
        label: tool.title,
        subtitle: tool.subtitle
      })),
    []
  );

  const spotlightMatches = useMemo(() => {
    const query = spotlightQuery.trim().toLowerCase();
    if (!query) return searchableTools;
    return searchableTools.filter((entry) => {
      const label = entry.label.toLowerCase();
      const subtitle = entry.subtitle?.toLowerCase() ?? '';
      return label.includes(query) || subtitle.includes(query);
    });
  }, [spotlightQuery, searchableTools]);

  useEffect(() => {
    const isOpen = state.toolWindows.requestLog?.isOpen;
    if (!isOpen) return;

    const observer = new PerformanceObserver((list) => {
      const entries = list.getEntries() as PerformanceResourceTiming[];
      if (!entries.length) return;
      updateState((current) => {
        const existing =
          (current.toolData.requestLog as RequestLogData | undefined)?.entries ?? [];
        const nextEntries = [...existing];
        entries.forEach((entry) => {
          const key = `${entry.name}-${entry.startTime}`;
          if (requestLogSeenRef.current.has(key)) return;
          requestLogSeenRef.current.add(key);
          nextEntries.unshift({
            name: entry.name,
            initiatorType: entry.initiatorType,
            duration: entry.duration,
            transferSize: entry.transferSize,
            startTime: entry.startTime
          });
        });
        return {
          ...current,
          toolData: {
            ...current.toolData,
            requestLog: { entries: nextEntries.slice(0, 200) }
          }
        };
      }).then(setState);
    });

    try {
      observer.observe({ type: 'resource', buffered: true });
    } catch {
      // PerformanceObserver might not support resource entries on all pages.
    }
    return () => observer.disconnect();
  }, [state.toolWindows.requestLog?.isOpen]);

  useEffect(() => {
    if (!state.scraperBuilderOpen || !state.scraperDraft.isPicking) return;

    const host = document.getElementById(ROOT_ID);

    const handleMove = (event: MouseEvent) => {
      const target = document.elementFromPoint(event.clientX, event.clientY);
      if (!target || (host && host.contains(target))) {
        setPickerRect(null);
        setPickerLabel('');
        return;
      }
      const rect = (target as Element).getBoundingClientRect();
      setPickerRect(rect);
      setPickerLabel(
        `${(target as Element).tagName.toLowerCase()}${(target as Element).id ? `#${(target as Element).id}` : ''}`
      );
    };

    const handleClick = (event: MouseEvent) => {
      const target = document.elementFromPoint(event.clientX, event.clientY);
      if (!target || (host && host.contains(target))) return;
      event.preventDefault();
      event.stopPropagation();
      const element = target as Element;
      const selector = generateCssSelector(element);
      const xpath = generateXPath(element);
      const isDuplicate = state.scraperDraft.fields.some(
        (field) => field.selector === selector || field.xpath === xpath
      );
      if (isDuplicate) {
        setPickerNotice('Element already added.');
        return;
      }
      const nextField: ScraperField = {
        id: `field_${Date.now()}_${Math.random().toString(16).slice(2)}`,
        name: `Field ${state.scraperDraft.fields.length + 1}`,
        selector,
        xpath,
        mode: 'single',
        source: 'text'
      };
      updateScraperDraft({ fields: [...state.scraperDraft.fields, nextField] });
      setPickerNotice('Element added.');
    };

    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        updateScraperDraft({ isPicking: false });
        setPickerRect(null);
        setPickerLabel('');
      }
    };

    document.addEventListener('mousemove', handleMove, true);
    document.addEventListener('click', handleClick, true);
    window.addEventListener('keydown', handleKey, true);

    return () => {
      document.removeEventListener('mousemove', handleMove, true);
      document.removeEventListener('click', handleClick, true);
      window.removeEventListener('keydown', handleKey, true);
    };
  }, [state.scraperBuilderOpen, state.scraperDraft.isPicking, state.scraperDraft.fields.length]);

  useEffect(() => {
    if (!pickerNotice) return;
    const timeout = window.setTimeout(() => setPickerNotice(null), 1400);
    return () => window.clearTimeout(timeout);
  }, [pickerNotice]);

  const panelWidth = useMemo(() => {
    if (!state.isOpen) return 0;
    return state.isWide ? 300 : 160;
  }, [state.isOpen, state.isWide]);

  const categoryBadge = (category: string) => {
    switch (category) {
      case 'Web Dev':
        return 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30';
      case 'Front End':
        return 'bg-blue-500/10 text-blue-300 border-blue-500/30';
      case 'CyberSec':
        return 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30';
      default:
        return 'bg-slate-500/10 text-slate-300 border-slate-500/30';
    }
  };

  const quickBarTools = useMemo(
    () =>
      state.quickBarToolIds
        .map((toolId) => getToolEntry(toolId))
        .filter((entry): entry is ToolRegistryEntry => Boolean(entry)),
    [state.quickBarToolIds]
  );

  const activeScraper = useMemo(
    () => state.scrapers.find((entry) => entry.id === state.scraperRunnerId) ?? null,
    [state.scrapers, state.scraperRunnerId]
  );

  const regexPreviewMap = useMemo(() => {
    const previews = new Map<string, { count: number; error: string | null; capped: boolean }>();
    if (!state.scraperBuilderOpen) return previews;
    const text = document.body?.innerText ?? '';
    state.scraperDraft.fields.forEach((field) => {
      if (field.source !== 'regex') return;
      previews.set(
        field.id,
        getRegexMatchCount(text, field.regex ?? '', field.regexFlags ?? '')
      );
    });
    return previews;
  }, [state.scraperBuilderOpen, state.scraperDraft.fields]);

  const clampTabOffset = (value: number, minOffset = 0) => {
    const maxOffset = Math.max(minOffset, window.innerHeight - tabHeight);
    return Math.min(Math.max(value, minOffset), maxOffset);
  };

  const toggleOpen = async () => {
    const next = await updateState((current) => ({
      ...current,
      isOpen: !current.isOpen
    }));
    setState(next);
  };

  const toggleWide = async () => {
    const next = await updateState((current) => ({
      ...current,
      isWide: !current.isWide
    }));
    setState(next);
  };

  const handleTabPointerDown = (event: React.PointerEvent<HTMLButtonElement>) => {
    event.preventDefault();
    event.stopPropagation();
    const startOffset = clampTabOffset(
      state.tabOffsetY,
      state.showMenuBar && !state.isAnchored ? menuBarHeight : 0
    );
    dragStateRef.current = {
      startY: event.clientY,
      startOffset,
      moved: false,
      lastOffset: startOffset,
      unanchored: false
    };
    setDragOffsetY(startOffset);
    setIsDragging(true);
    setDragAnchored(state.isAnchored);

    const handleMove = (moveEvent: PointerEvent) => {
      const delta = moveEvent.clientY - dragStateRef.current.startY;
      if (Math.abs(delta) > 3) {
        dragStateRef.current.moved = true;
      }
      if (
        state.showMenuBar &&
        state.isAnchored &&
        !dragStateRef.current.unanchored &&
        Math.abs(delta) > 3
      ) {
        dragStateRef.current.unanchored = true;
        dragStateRef.current.startOffset = menuBarHeight;
        setDragAnchored(false);
      }
      const nextOffset = clampTabOffset(
        dragStateRef.current.startOffset + delta,
        state.showMenuBar && !dragStateRef.current.unanchored ? menuBarHeight : 0
      );
      dragStateRef.current.lastOffset = nextOffset;
      setDragOffsetY(nextOffset);
    };

    const handleUp = async () => {
      window.removeEventListener('pointermove', handleMove);
      window.removeEventListener('pointerup', handleUp);

      const { moved, lastOffset } = dragStateRef.current;
      setIsDragging(false);
      setDragOffsetY(null);
      setDragAnchored(null);

      if (moved) {
        await updateState((current) => ({
          ...current,
          tabOffsetY: clampTabOffset(
            lastOffset,
            current.showMenuBar && !dragStateRef.current.unanchored
              ? menuBarHeight
              : 0
          ),
          isAnchored:
            current.showMenuBar && !dragStateRef.current.unanchored
              ? current.isAnchored
              : false
        }));
        return;
      }

      await toggleOpen();
    };

    window.addEventListener('pointermove', handleMove);
    window.addEventListener('pointerup', handleUp, { once: true });
  };

  const updateMenuBar = async (value: boolean) => {
    const next = await updateState((current) => ({
      ...current,
      showMenuBar: value
    }));
    setState(next);
  };

  const toggleQuickBarTool = async (toolId: string) => {
    const next = await updateState((current) => {
      const isPinned = current.quickBarToolIds.includes(toolId);
      return {
        ...current,
        quickBarToolIds: isPinned
          ? current.quickBarToolIds.filter((id) => id !== toolId)
          : [...current.quickBarToolIds, toolId]
      };
    });
    setState(next);
  };

  const updateScraperDraft = async (nextDraft: Partial<ScraperDraft>) => {
    const next = await updateState((current) => ({
      ...current,
      scraperDraft: {
        ...current.scraperDraft,
        ...nextDraft
      }
    }));
    setState(next);
  };

  const openScraperBuilder = async () => {
    const next = await updateState((current) => ({
      ...current,
      scraperBuilderOpen: true
    }));
    setState(next);
  };

  const closeScraperBuilder = async () => {
    const next = await updateState((current) => ({
      ...current,
      scraperBuilderOpen: false,
      scraperDraft: { ...current.scraperDraft, isPicking: false }
    }));
    setState(next);
    setPickerRect(null);
    setShowScraperHelp(false);
  };

  const saveScraperDraft = async () => {
    const draft = state.scraperDraft;
    if (!draft.name.trim() || draft.fields.length === 0) return;
    const now = Date.now();
    const newScraper: ScraperDefinition = {
      id: buildScraperId(),
      name: draft.name.trim(),
      fields: draft.fields,
      createdAt: now,
      updatedAt: now
    };
    const next = await updateState((current) => ({
      ...current,
      scrapers: [...current.scrapers, newScraper],
      scraperBuilderOpen: false,
      scraperDraft: { name: '', fields: [], isPicking: false }
    }));
    setState(next);
    setPickerRect(null);
  };

  const updateScraperField = async (fieldId: string, next: Partial<ScraperField>) => {
    const nextFields = state.scraperDraft.fields.map((field) =>
      field.id === fieldId ? { ...field, ...next } : field
    );
    await updateScraperDraft({ fields: nextFields });
  };

  const removeScraperField = async (fieldId: string) => {
    const nextFields = state.scraperDraft.fields.filter((field) => field.id !== fieldId);
    await updateScraperDraft({ fields: nextFields });
  };

  const openScraperRunner = async (scraperId: string) => {
    const scraper = state.scrapers.find((entry) => entry.id === scraperId);
    if (!scraper) return;
    const results = extractScraperResults(document, scraper);
    const next = await updateState((current) => ({
      ...current,
      scraperRunnerOpen: true,
      scraperRunnerId: scraperId,
      scraperRunnerResults: results,
      scraperRunnerError: null
    }));
    setState(next);
  };

  const rerunScraper = async () => {
    if (!state.scraperRunnerId) return;
    const scraper = state.scrapers.find((entry) => entry.id === state.scraperRunnerId);
    if (!scraper) return;
    const results = extractScraperResults(document, scraper);
    const next = await updateState((current) => ({
      ...current,
      scraperRunnerResults: results,
      scraperRunnerError: null
    }));
    setState(next);
  };

  const closeScraperRunner = async () => {
    const next = await updateState((current) => ({
      ...current,
      scraperRunnerOpen: false,
      scraperRunnerId: null,
      scraperRunnerError: null
    }));
    setState(next);
  };


  const openTool = async (toolId: string) => {
    const next = await updateState((current) => {
      const existing = current.toolWindows[toolId];
      return {
        ...current,
        toolWindows: {
          ...current.toolWindows,
          [toolId]: {
            isOpen: true,
            isMinimized: false,
            x: existing?.x ?? TOOL_DEFAULT_POSITION.x,
            y: existing?.y ?? TOOL_DEFAULT_POSITION.y
          }
        }
      };
    });
    setState(next);
  };

  const openToolFromSpotlight = async (toolId: string) => {
    await openTool(toolId);
    setSpotlightOpen(false);
    setSpotlightQuery('');
  };

  const closeTool = async (toolId: string) => {
    const next = await updateState((current) => {
      const existing = current.toolWindows[toolId];
      if (!existing) return current;
      return {
        ...current,
        toolWindows: {
          ...current.toolWindows,
          [toolId]: { ...existing, isOpen: false, isMinimized: false }
        }
      };
    });
    setState(next);
  };

  const minimizeTool = async (toolId: string) => {
    const next = await updateState((current) => {
      const existing = current.toolWindows[toolId];
      if (!existing) return current;
      return {
        ...current,
        toolWindows: {
          ...current.toolWindows,
          [toolId]: { ...existing, isMinimized: true, isOpen: true }
        }
      };
    });
    setState(next);
  };

  const restoreTool = async (toolId: string) => {
    const next = await updateState((current) => {
      const existing = current.toolWindows[toolId];
      if (!existing) return current;
      return {
        ...current,
        toolWindows: {
          ...current.toolWindows,
          [toolId]: { ...existing, isMinimized: false, isOpen: true }
        }
      };
    });
    setState(next);
  };

  const updateToolPosition = async (toolId: string, x: number, y: number) => {
    const next = await updateState((current) => {
      const existing = current.toolWindows[toolId];
      if (!existing) return current;
      return {
        ...current,
        toolWindows: {
          ...current.toolWindows,
          [toolId]: { ...existing, x, y }
        }
      };
    });
    setState(next);
  };

  const updateToolData = async (toolId: string, data: unknown) => {
    const next = await updateState((current) => ({
      ...current,
      toolData: {
        ...current.toolData,
        [toolId]: data
      }
    }));
    setState(next);
  };

  useEffect(() => {
    const handleDocumentClick = (event: MouseEvent) => {
      if (!menuBarRef.current) return;
      const path = typeof event.composedPath === 'function' ? event.composedPath() : [];
      if (path.includes(menuBarRef.current)) return;
      updateState((current) => ({
        ...current,
        menuBarActiveMenu: null,
        menuBarActiveSubmenu: null
      })).then(setState);
    };

    document.addEventListener('mousedown', handleDocumentClick);
    return () => document.removeEventListener('mousedown', handleDocumentClick);
  }, []);

  useEffect(() => {
    const entries =
      (state.toolData.requestLog as RequestLogData | undefined)?.entries ?? [];
    if (entries.length === 0) {
      requestLogSeenRef.current.clear();
    }
  }, [state.toolData.requestLog]);

  useEffect(() => {
    if (!state.showMenuBar) {
      updateState((current) => ({
        ...current,
        menuBarActiveMenu: null,
        menuBarActiveSubmenu: null
      })).then(setState);
      if (state.isAnchored) {
        updateState((current) => ({
          ...current,
          isAnchored: false
        })).then(setState);
      }
      return;
    }
    if (state.tabOffsetY <= menuBarHeight) {
      updateState((current) => ({
        ...current,
        tabOffsetY: 0,
        isAnchored: true
      })).then(setState);
    }
  }, [menuBarHeight, state.showMenuBar, state.tabOffsetY]);

  const handleMenuClick = (label: string) => {
    updateState((current) => ({
      ...current,
      menuBarActiveMenu: current.menuBarActiveMenu === label ? null : label,
      menuBarActiveSubmenu: null
    })).then(setState);
  };

  const handleScraperAction = async (action: string) => {
    if (action === 'makeScraper') {
      await openScraperBuilder();
      const next = await updateState((current) => ({
        ...current,
        menuBarActiveMenu: null,
        menuBarActiveSubmenu: null
      }));
      setState(next);
    }
  };

  if (!state.isVisible) {
    return null;
  }

  const isAnchoredEffective = state.showMenuBar && (dragAnchored ?? state.isAnchored);
  const tabHeight = isAnchoredEffective ? menuBarHeight : 48;
  const topInset = state.showMenuBar && !isAnchoredEffective ? menuBarHeight : 0;
  const effectiveOffset = clampTabOffset(
    isDragging && dragOffsetY !== null ? dragOffsetY : state.tabOffsetY,
    topInset
  );
  const viewportHeight = window.innerHeight;
  const tabCenter = effectiveOffset + tabHeight / 2;
  const transitionStart = viewportHeight * 0.5;
  const transitionEnd = viewportHeight * 0.85;
  const transitionRange = Math.max(1, transitionEnd - transitionStart);
  const transitionProgress = Math.min(
    Math.max((tabCenter - transitionStart) / transitionRange, 0),
    1
  );
  const anchorOffset = state.isOpen
    ? transitionProgress * (menuHeight - tabHeight)
    : 0;
  const maxPanelTop = Math.max(topInset, viewportHeight - menuHeight);
  const panelTop = isAnchoredEffective
    ? 0
    : Math.min(Math.max(effectiveOffset - anchorOffset, topInset), maxPanelTop);
  const tabTranslateY = Math.min(
    Math.max(effectiveOffset - panelTop, 0),
    menuHeight - tabHeight
  );

  return (
    <>
      {spotlightOpen ? (
        <div
          className="fixed inset-0 z-[90] flex items-start justify-center bg-slate-950/70 backdrop-blur-sm"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) {
              setSpotlightOpen(false);
            }
          }}
        >
          <div
            className="mt-24 w-full max-w-xl rounded-2xl border border-slate-700/80 bg-gradient-to-b from-slate-900 via-slate-900 to-slate-950 shadow-[0_24px_60px_rgba(0,0,0,0.55)]"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="flex items-center gap-3 border-b border-slate-800 px-5 py-4">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-slate-800/80 text-slate-300">
                <FontAwesomeIcon icon={faSearch} className="w-4 h-4" />
              </div>
              <div className="flex-1">
                <div className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                  XCalibr Spotlight
                </div>
                <input
                  ref={spotlightInputRef}
                  type="text"
                  value={spotlightQuery}
                  onChange={(event) => setSpotlightQuery(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key !== 'Enter') return;
                    event.preventDefault();
                    const match = spotlightMatches[0];
                    if (!match) return;
                    openToolFromSpotlight(match.id);
                  }}
                  placeholder="Search tools..."
                  className="mt-1 w-full bg-transparent text-lg text-slate-100 placeholder:text-slate-500 focus:outline-none"
                />
              </div>
              <div className="text-[10px] text-slate-500">Cmd+Shift+P</div>
            </div>
            <div className="max-h-72 overflow-y-auto p-2">
              {spotlightMatches.length === 0 ? (
                <div className="px-4 py-6 text-sm text-slate-400">
                  Nothing found. Try another keyword.
                </div>
              ) : (
                spotlightMatches.map((entry) => (
                  <button
                    key={entry.id}
                    type="button"
                    className="w-full rounded-xl px-4 py-3 text-left transition-colors hover:bg-slate-800/80"
                    onClick={() => openToolFromSpotlight(entry.id)}
                  >
                    <div className="text-sm text-slate-100">{entry.label}</div>
                    <div className="text-[11px] text-slate-500">
                      {entry.subtitle ?? 'Open tool'}
                    </div>
                  </button>
                ))
              )}
            </div>
          </div>
        </div>
      ) : null}
      {state.scraperBuilderOpen ? (
        state.scraperDraft.isPicking ? (
          <div className="fixed top-4 left-1/2 z-[95] -translate-x-1/2 space-y-2">
            <div className="rounded-full border border-slate-700 bg-slate-900/90 px-4 py-2 text-[11px] text-slate-200 shadow-lg">
              <span className="mr-3">Picker active. Click elements to add fields.</span>
              <button
                type="button"
                onClick={() => updateScraperDraft({ isPicking: false })}
                className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
              >
                Stop Picking
              </button>
            </div>
            {pickerNotice ? (
              <div className="rounded-full border border-slate-700 bg-slate-900/90 px-4 py-2 text-[11px] text-slate-200 shadow-lg">
                {pickerNotice}
              </div>
            ) : null}
          </div>
        ) : (
          <div
            className="fixed inset-0 z-[95] flex items-start justify-center bg-slate-950/70 backdrop-blur-sm"
            onMouseDown={(event) => {
              if (event.target === event.currentTarget) {
                closeScraperBuilder();
              }
            }}
          >
            <div
              className="mt-12 w-full max-w-2xl max-h-[85vh] rounded-2xl border border-slate-700/80 bg-gradient-to-b from-slate-900 via-slate-900 to-slate-950 shadow-[0_24px_60px_rgba(0,0,0,0.55)] flex flex-col"
              onMouseDown={(event) => event.stopPropagation()}
            >
              {showScraperHelp ? (
                <div className="absolute inset-0 z-[96] rounded-2xl bg-slate-950/90 backdrop-blur-sm">
                  <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
                    <div>
                      <div className="text-xs text-slate-200">Scraper Guide</div>
                      <div className="text-[11px] text-slate-500">
                        Learn how to build and run a scraper safely.
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => setShowScraperHelp(false)}
                      className="text-slate-400 hover:text-slate-200 transition-colors"
                    >
                      ×
                    </button>
                  </div>
                  <div className="max-h-[70vh] overflow-y-auto px-5 py-4 space-y-4 text-[11px] text-slate-300">
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        1. Name Your Scraper
                      </div>
                      <div>
                        Give the scraper a clear name so you can find it later in
                        the Scraper List.
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        2. Pick Elements
                      </div>
                      <div>
                        Click “Pick Elements” and hover the page. Click any element
                        you want to extract. Each click adds a field.
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        3. Rename Fields
                      </div>
                      <div>
                        Rename fields so the output makes sense (e.g. Price, Title,
                        Description).
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        4. Choose Mode
                      </div>
                      <div>
                        Use “Single” for one value, or “List” when you want all
                        matching elements on the page.
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        4b. Get Every Instance
                      </div>
                      <div>
                        Use List mode with a broad selector or Regex to capture all
                        matches like emails or URLs.
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        5. Choose Source
                      </div>
                      <div>
                        Pick Text, HTML, or Attribute. Attribute is useful for
                        links (href) or images (src).
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        5b. Regex Source
                      </div>
                      <div>
                        Add a Regex field to scan the entire page text. Start with
                        presets like Emails or URLs and tweak the pattern if needed.
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        6. Save Scraper
                      </div>
                      <div>
                        Save when you have at least one field. It will appear in
                        the Scraper List menu.
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        7. Run Scraper
                      </div>
                      <div>
                        Open Scraper List, choose your scraper, and review results.
                        Use Copy JSON or Copy CSV to export.
                      </div>
                    </div>
                  </div>
                </div>
              ) : null}
              <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
                <div>
                  <div className="text-xs text-slate-200">Build Scraper</div>
                  <div className="text-[11px] text-slate-500">
                    Click elements on the page to capture selectors.
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => setShowScraperHelp(true)}
                    className="text-[11px] text-blue-300 hover:text-blue-200 transition-colors"
                  >
                    Explain Scraper
                  </button>
                  <button
                    type="button"
                    onClick={closeScraperBuilder}
                    className="text-slate-400 hover:text-slate-200 transition-colors"
                  >
                    ×
                  </button>
                </div>
              </div>
              <div className="space-y-4 px-5 py-4">
                <div className="space-y-2">
                  <div className="text-[11px] uppercase tracking-[0.2em] text-slate-500">
                    Scraper Name
                  </div>
                  <input
                    type="text"
                    value={state.scraperDraft.name}
                    onChange={(event) =>
                      updateScraperDraft({ name: event.target.value })
                    }
                    className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
                    placeholder="e.g. Pricing Table"
                  />
                </div>
              </div>
              <div className="flex-1 overflow-y-auto px-5 pb-4 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="text-[11px] text-slate-500">Picker idle</div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        const nextField: ScraperField = {
                          id: `field_${Date.now()}_${Math.random().toString(16).slice(2)}`,
                          name: `Regex ${state.scraperDraft.fields.length + 1}`,
                          selector: 'document',
                          xpath: 'document',
                          mode: 'list',
                          source: 'regex',
                          regex: '',
                          regexFlags: 'gi'
                        };
                        updateScraperDraft({
                          fields: [...state.scraperDraft.fields, nextField]
                        });
                      }}
                      className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
                    >
                      Add Regex Field
                    </button>
                    <button
                      type="button"
                      onClick={() => updateScraperDraft({ isPicking: true })}
                      className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
                    >
                      Pick Elements
                    </button>
                  </div>
                </div>

                <div className="space-y-3">
                  {state.scraperDraft.fields.length === 0 ? (
                    <div className="text-[11px] text-slate-500">
                      No fields yet. Click “Pick Elements” and select elements on the page.
                    </div>
                  ) : (
                    state.scraperDraft.fields.map((field) => (
                      <div
                        key={field.id}
                        className="rounded border border-slate-800 bg-slate-900/60 p-3 space-y-2"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <input
                            type="text"
                            value={field.name}
                            onChange={(event) =>
                              updateScraperField(field.id, {
                                name: event.target.value
                              })
                            }
                            className="flex-1 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
                          />
                          <button
                            type="button"
                            onClick={() => removeScraperField(field.id)}
                            className="text-slate-500 hover:text-rose-300 transition-colors"
                          >
                            ×
                          </button>
                        </div>

                        <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                          Selector
                        </div>
                        <div className="text-[11px] text-slate-300 break-words">
                          {field.selector}
                        </div>
                        <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                          XPath
                        </div>
                        <div className="text-[11px] text-slate-400 break-words">
                          {field.xpath}
                        </div>

                        <div className="flex gap-2">
                          {(['single', 'list'] as const).map((mode) => (
                            <button
                              key={mode}
                              type="button"
                              onClick={() => updateScraperField(field.id, { mode })}
                              className={`flex-1 rounded px-2 py-1 text-[11px] border transition-colors ${
                                field.mode === mode
                                  ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                              }`}
                            >
                              {mode === 'single' ? 'Single' : 'List'}
                            </button>
                          ))}
                        </div>

                      <div className="flex gap-2">
                        {(['text', 'html', 'attr', 'regex'] as const).map((source) => (
                          <button
                            key={source}
                            type="button"
                            onClick={() =>
                              updateScraperField(field.id, {
                                source,
                                ...(source === 'regex'
                                  ? { selector: 'document', xpath: 'document', mode: 'list' }
                                  : {})
                              })
                            }
                            className={`flex-1 rounded px-2 py-1 text-[11px] border transition-colors ${
                              field.source === source
                                ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                                : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                            }`}
                          >
                            {source === 'attr'
                              ? 'Attribute'
                              : source === 'regex'
                                ? 'Regex'
                                : source.toUpperCase()}
                          </button>
                        ))}
                      </div>
                      {field.source === 'attr' ? (
                        <input
                          type="text"
                          value={field.attrName ?? ''}
                          onChange={(event) =>
                            updateScraperField(field.id, {
                              attrName: event.target.value
                            })
                          }
                          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
                          placeholder="Attribute name (e.g. href)"
                        />
                      ) : null}
                      {field.source === 'regex' ? (
                        <div className="space-y-2">
                          <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                            Regex Pattern
                          </div>
                          <input
                            type="text"
                            value={field.regex ?? ''}
                            onChange={(event) =>
                              updateScraperField(field.id, { regex: event.target.value })
                            }
                            className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
                            placeholder="e.g. [A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}"
                          />
                          <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                            Flags
                          </div>
                          <input
                            type="text"
                            value={field.regexFlags ?? 'gi'}
                            onChange={(event) =>
                              updateScraperField(field.id, {
                                regexFlags: event.target.value
                              })
                            }
                            className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
                            placeholder="e.g. gi"
                          />
                          <div className="flex gap-2">
                            <button
                              type="button"
                              onClick={() =>
                                updateScraperField(field.id, {
                                  regex:
                                    '[A-Z0-9._%+-]+@[A-Z0-9.-]+\\\\.[A-Z]{2,}',
                                  regexFlags: 'gi',
                                  mode: 'list'
                                })
                              }
                              className="flex-1 rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
                            >
                              Emails
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                updateScraperField(field.id, {
                                  regex: "https?://[^\\s\"'`<>]+",
                                  regexFlags: 'gi',
                                  mode: 'list'
                                })
                              }
                              className="flex-1 rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
                            >
                              URLs
                            </button>
                          </div>
                          {regexPreviewMap.get(field.id)?.error ? (
                            <div className="text-[11px] text-rose-300">
                              {regexPreviewMap.get(field.id)?.error}
                            </div>
                          ) : (
                            <div className="text-[11px] text-slate-500">
                              Matches on page:{' '}
                              {regexPreviewMap.get(field.id)?.count ?? 0}
                              {regexPreviewMap.get(field.id)?.capped ? '+' : ''}
                            </div>
                          )}
                          <div className="text-[11px] text-slate-500">
                            Regex runs against full page text.
                          </div>
                        </div>
                      ) : null}
                    </div>
                  ))
                )}
                </div>
              </div>
              <div className="flex items-center justify-end gap-2 border-t border-slate-800 px-5 py-4">
                <button
                  type="button"
                  onClick={closeScraperBuilder}
                  className="rounded bg-slate-800 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={saveScraperDraft}
                  disabled={
                    !state.scraperDraft.name.trim() ||
                    state.scraperDraft.fields.length === 0
                  }
                  className="rounded bg-blue-600 px-3 py-1.5 text-xs text-white hover:bg-blue-500 transition-colors disabled:opacity-50"
                >
                  Save Scraper
                </button>
              </div>
            </div>
          </div>
        )
      ) : null}
      {state.scraperRunnerOpen && activeScraper ? (
        <div
          className="fixed inset-0 z-[95] flex items-start justify-center bg-slate-950/70 backdrop-blur-sm"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) {
              closeScraperRunner();
            }
          }}
        >
          <div
            className="mt-12 w-full max-w-2xl max-h-[85vh] rounded-2xl border border-slate-700/80 bg-gradient-to-b from-slate-900 via-slate-900 to-slate-950 shadow-[0_24px_60px_rgba(0,0,0,0.55)] flex flex-col"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
              <div>
                <div className="text-xs text-slate-200">Run Scraper</div>
                <div className="text-[11px] text-slate-500">
                  {activeScraper.name}
                </div>
              </div>
              <button
                type="button"
                onClick={closeScraperRunner}
                className="text-slate-400 hover:text-slate-200 transition-colors"
              >
                ×
              </button>
            </div>
            <div className="space-y-4 px-5 py-4">
              <div className="flex items-center justify-between">
                <div className="text-[11px] text-slate-500">
                  {state.scraperRunnerResults ? 'Results ready.' : 'No results yet.'}
                </div>
                <button
                  type="button"
                  onClick={rerunScraper}
                  className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
                >
                  Run Again
                </button>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto px-5 pb-4">
              {state.scraperRunnerResults ? (
                <div className="rounded border border-slate-800 bg-slate-900/60 p-3 space-y-2 text-[11px] text-slate-300">
                  {Object.entries(state.scraperRunnerResults).map(([key, value]) => (
                    <div key={key}>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        {key}
                      </div>
                      <div className="break-words">
                        {Array.isArray(value) ? value.join(', ') : value}
                      </div>
                    </div>
                  ))}
                </div>
              ) : null}
            </div>
            <div className="flex items-center justify-end gap-2 border-t border-slate-800 px-5 py-4">
              <button
                type="button"
                onClick={() =>
                  navigator.clipboard.writeText(
                    JSON.stringify(state.scraperRunnerResults ?? {}, null, 2)
                  )
                }
                className="rounded bg-slate-800 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
              >
                Copy JSON
              </button>
              <button
                type="button"
                onClick={() =>
                  navigator.clipboard.writeText(
                    buildCsvFromResults(state.scraperRunnerResults ?? {})
                  )
                }
                className="rounded bg-slate-800 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
              >
                Copy CSV
              </button>
            </div>
          </div>
        </div>
      ) : null}
      {state.scraperDraft.isPicking && pickerRect ? (
        <div className="fixed inset-0 z-[96] pointer-events-none">
          <div
            className="absolute border-2 border-blue-500/80 bg-blue-500/10"
            style={{
              left: pickerRect.left,
              top: pickerRect.top,
              width: pickerRect.width,
              height: pickerRect.height
            }}
          />
          <div
            className="absolute rounded bg-slate-900/90 px-2 py-1 text-[10px] text-slate-200"
            style={{
              left: pickerRect.left,
              top: Math.max(0, pickerRect.top - 24)
            }}
          >
            {pickerLabel}
          </div>
        </div>
      ) : null}
      {state.showMenuBar ? (
        <div
          ref={menuBarRef}
          className="pointer-events-auto fixed top-0 left-0 right-0 z-50 bg-slate-900 border-b border-slate-800 text-slate-200 shadow-lg"
          style={{
            fontFamily: "'Inter', ui-sans-serif, system-ui, -apple-system",
            height: menuBarHeight
          }}
        >
          <div className="flex h-full items-center gap-1 px-3">
            <div className="flex items-center gap-2 mr-2">
              <div className="w-5 h-5 rounded bg-blue-600 flex items-center justify-center">
                <FontAwesomeIcon icon={faBolt} className="w-3 h-3 text-white" />
              </div>
              <span className="text-xs font-semibold text-slate-100">XCalibr</span>
            </div>
            {menuItems.map((item) => {
              const isOpen = state.menuBarActiveMenu === item.label;
              return (
                <div
                  key={item.label}
                  className="relative"
                >
                  <button
                    type="button"
                    onClick={() => handleMenuClick(item.label)}
                    className="px-2 py-1 text-xs text-slate-300 rounded hover:bg-slate-800 transition-colors"
                  >
                    {item.label}
                  </button>
                  <div
                    className={`absolute left-0 mt-1 w-44 bg-slate-900 border border-slate-700 rounded shadow-2xl transition-opacity ${
                      isOpen
                        ? 'opacity-100 pointer-events-auto'
                        : 'opacity-0 pointer-events-none'
                    }`}
                  >
                    <div className="py-1">
                      {item.items.map((entry) => {
                      if (typeof entry === 'string') {
                        return (
                          <button
                            key={entry}
                            type="button"
                            className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors"
                          >
                            {entry}
                          </button>
                        );
                      }
                      if ('toolId' in entry) {
                        return (
                          <button
                            key={entry.label}
                            type="button"
                            onClick={async () => {
                              await openTool(entry.toolId);
                              const next = await updateState((current) => ({
                                ...current,
                                menuBarActiveMenu: null,
                                menuBarActiveSubmenu: null
                              }));
                              setState(next);
                            }}
                            className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors"
                          >
                            {entry.label}
                          </button>
                        );
                      }
                      if ('scraperId' in entry) {
                        return (
                          <button
                            key={entry.label}
                            type="button"
                            onClick={async () => {
                              await openScraperRunner(entry.scraperId);
                              const next = await updateState((current) => ({
                                ...current,
                                menuBarActiveMenu: null,
                                menuBarActiveSubmenu: null
                              }));
                              setState(next);
                            }}
                            className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors"
                          >
                            {entry.label}
                          </button>
                        );
                      }
                      if ('action' in entry) {
                        return (
                          <button
                            key={entry.label}
                            type="button"
                            onClick={() => handleScraperAction(entry.action)}
                            className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors"
                          >
                            {entry.label}
                          </button>
                        );
                      }
                      return (
                        <div key={entry.label} className="relative group/menu">
                            <button
                              type="button"
                              onClick={() =>
                                updateState((current) => ({
                                  ...current,
                                  menuBarActiveSubmenu:
                                    current.menuBarActiveSubmenu ===
                                    `${item.label}:${entry.label}`
                                      ? null
                                      : `${item.label}:${entry.label}`
                                })).then(setState)
                              }
                              className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors flex items-center justify-between"
                            >
                              <span>{entry.label}</span>
                              <span className="text-slate-500">›</span>
                            </button>
                          <div
                            className={`absolute left-full top-0 -ml-px w-44 bg-slate-900 border border-slate-700 rounded shadow-2xl transition-opacity ${
                              state.menuBarActiveSubmenu ===
                              `${item.label}:${entry.label}`
                                ? 'opacity-100 pointer-events-auto'
                                : 'opacity-0 pointer-events-none'
                            }`}
                          >
                            <div className="py-1">
                              {entry.items.map((subItem) => {
                                if (typeof subItem === 'string') {
                                  return (
                                    <button
                                      key={subItem}
                                      type="button"
                                      className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors"
                                    >
                                      {subItem}
                                    </button>
                                  );
                                }
                                if ('toolId' in subItem) {
                                  return (
                                    <button
                                      key={subItem.label}
                                      type="button"
                                      onClick={async () => {
                                        await openTool(subItem.toolId);
                                        const next = await updateState((current) => ({
                                          ...current,
                                          menuBarActiveMenu: null,
                                          menuBarActiveSubmenu: null
                                        }));
                                        setState(next);
                                      }}
                                      className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors"
                                    >
                                      {subItem.label}
                                    </button>
                                  );
                                }
                                if ('scraperId' in subItem) {
                                  return (
                                    <button
                                      key={subItem.label}
                                      type="button"
                                      onClick={async () => {
                                        await openScraperRunner(subItem.scraperId);
                                        const next = await updateState((current) => ({
                                          ...current,
                                          menuBarActiveMenu: null,
                                          menuBarActiveSubmenu: null
                                        }));
                                        setState(next);
                                      }}
                                      className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors"
                                    >
                                      {subItem.label}
                                    </button>
                                  );
                                }
                                if ('action' in subItem) {
                                  return (
                                    <button
                                      key={subItem.label}
                                      type="button"
                                      onClick={() => handleScraperAction(subItem.action)}
                                      className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors"
                                    >
                                      {subItem.label}
                                    </button>
                                  );
                                }
                                return null;
                              })}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : null}
    <div
      className="xcalibr-app-container pointer-events-auto font-sans text-slate-200 z-[70]"
      style={{
        fontFamily: "'Inter', ui-sans-serif, system-ui, -apple-system",
        top: `${panelTop}px`
      }}
    >
      <button
        type="button"
        onPointerDown={handleTabPointerDown}
        style={{ touchAction: 'none', transform: `translateY(${tabTranslateY}px)` }}
        className={`z-[80] bg-slate-800 text-white flex items-center justify-center rounded-l-lg shadow-lg hover:bg-slate-700 transition-colors border-l border-t border-b border-slate-600 cursor-pointer ${
          isAnchoredEffective ? 'w-7 h-8' : 'w-8 h-12'
        }`}
      >
        <FontAwesomeIcon
          icon={state.isOpen ? faChevronRight : faChevronLeft}
          className={iconSizeClass}
        />
      </button>

      <div
        className={`bg-slate-900 h-full shadow-2xl transition-all duration-300 ease-in-out border-l border-slate-700 flex flex-col overflow-hidden rounded-l-md ${
          state.isOpen ? 'opacity-100' : 'opacity-0'
        }`}
        style={{
          width: panelWidth,
          borderTopLeftRadius: isAnchoredEffective ? 0 : undefined,
          borderBottomLeftRadius: isAnchoredEffective ? 0 : undefined
        }}
      >
        <div
          className={`border-b border-slate-800 flex justify-between items-center bg-slate-900 sticky top-0 z-10 ${
            isAnchoredEffective ? 'px-2' : 'p-3'
          }`}
          style={isAnchoredEffective ? { height: menuBarHeight } : undefined}
        >
          <div className="flex items-center gap-2 overflow-hidden">
            <div className="w-6 h-6 rounded bg-blue-600 flex items-center justify-center shrink-0">
              <FontAwesomeIcon
                icon={faBolt}
                className={`${iconSizeClass} text-white`}
              />
            </div>
            <span
              className={`font-bold text-slate-200 text-[11px] whitespace-nowrap transition-opacity duration-200 ${
                state.isOpen ? 'opacity-100 delay-150' : 'opacity-0'
              }`}
            >
              {isAnchoredEffective ? 'Quick Bar' : 'XCalibr - Quickbar'}
            </span>
          </div>
          <button
            type="button"
            onClick={toggleWide}
            className="text-slate-400 hover:text-white transition-colors shrink-0"
            title={state.isWide ? 'Compress Width' : 'Expand Width'}
          >
            <FontAwesomeIcon
              icon={state.isWide ? faCompress : faExpand}
              className={iconSizeClass}
            />
          </button>
        </div>

        <div className="p-2 border-b border-slate-800">
          <label className="flex items-center gap-2 text-[11px] text-slate-400 mb-2">
            <input
              type="checkbox"
              checked={state.showMenuBar}
              onChange={(event) => updateMenuBar(event.target.checked)}
              className="h-3 w-3 rounded border border-slate-700 bg-slate-800 text-blue-500 focus:ring-0 focus:outline-none"
            />
            <span>Show Menu Bar</span>
          </label>
          <div className="text-[11px] text-slate-500 px-1 py-1.5">
            Hit cmd+shift+p to search.
          </div>
        </div>

        <div className="flex-1 overflow-y-auto no-scrollbar p-1 space-y-1">
          {quickBarTools.length === 0 ? (
            <div className="px-3 py-4 text-[11px] text-slate-500">
              No favorites yet. Open a tool and press + to pin it here.
            </div>
          ) : (
            quickBarTools.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => openTool(item.id)}
                className="w-full flex items-center gap-3 p-2 rounded hover:bg-slate-800 transition-all text-left group"
              >
                <div
                  className={`w-6 h-6 rounded bg-slate-800 border border-slate-700 text-slate-400 transition-colors shrink-0 ${item.hover}`}
                >
                  <div className="w-full h-full flex items-center justify-center">
                    <FontAwesomeIcon icon={item.icon} className={iconSizeClass} />
                  </div>
                </div>
                <div className="flex-1 overflow-hidden">
                  <div className="text-slate-300 text-xs font-medium whitespace-nowrap">
                    {item.title}
                  </div>
                  <div className="text-slate-500 text-[10px] whitespace-nowrap">
                    {item.subtitle}
                  </div>
                </div>
                {state.isWide ? (
                  <span
                    className={`text-[7px] uppercase tracking-[0.2em] px-2 py-1 rounded-full border ${categoryBadge(item.category)}`}
                  >
                    {item.category}
                  </span>
                ) : null}
              </button>
            ))
          )}
        </div>

        <div className="p-2 border-t border-slate-800 bg-slate-900 mt-auto">
          <button
            type="button"
            className="w-full py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-400 transition-colors flex justify-center items-center gap-2"
          >
            <FontAwesomeIcon icon={faGear} className={iconSizeClass} />
            <span>Settings</span>
          </button>
        </div>
      </div>
    </div>
    <div className="fixed bottom-3 right-3 flex gap-2 z-[80]">
      {Object.entries(state.toolWindows)
        .filter(([, toolState]) => toolState.isOpen && toolState.isMinimized)
        .map(([toolId]) => {
          const entry = getToolEntry(toolId);
          if (!entry) return null;
          return (
            <button
              key={toolId}
              type="button"
              onClick={() => restoreTool(toolId)}
              className="px-3 py-2 rounded bg-slate-900 border border-slate-700 text-xs text-slate-200 shadow-lg hover:bg-slate-800 transition-colors"
            >
              {entry.title}
            </button>
          );
        })}
    </div>
    {Object.entries(state.toolWindows)
      .filter(([, toolState]) => toolState.isOpen && !toolState.isMinimized)
      .map(([toolId, toolState]) => {
        const entry = getToolEntry(toolId);
        if (!entry) return null;
        const isPinned = state.quickBarToolIds.includes(toolId);
        return (
          <div
            key={toolId}
            className="fixed z-[80] bg-slate-900 border border-slate-700 rounded-lg shadow-2xl w-72"
            style={{ left: toolState.x, top: toolState.y }}
          >
            <div
              className="flex items-center justify-between px-3 py-2 border-b border-slate-800 bg-slate-900 cursor-move"
              style={{ touchAction: 'none' }}
              onPointerDown={(event) => {
                if (
                  event.target instanceof HTMLElement &&
                  event.target.closest('button')
                ) {
                  return;
                }
                event.preventDefault();
                const windowEl = event.currentTarget.parentElement as HTMLElement | null;
                if (!windowEl) return;
                const rect = windowEl.getBoundingClientRect();
                event.currentTarget.setPointerCapture(event.pointerId);
                toolDragRef.current = {
                  toolId,
                  offsetX: event.clientX - rect.left,
                  offsetY: event.clientY - rect.top,
                  startX: toolState.x,
                  startY: toolState.y,
                  moved: false,
                  windowEl
                };
                const handleMove = (moveEvent: PointerEvent) => {
                  if (!toolDragRef.current?.windowEl) return;
                  toolDragRef.current.moved = true;
                  const nextX = moveEvent.clientX - toolDragRef.current.offsetX;
                  const nextY = moveEvent.clientY - toolDragRef.current.offsetY;
                  toolDragRef.current.windowEl.style.left = `${nextX}px`;
                  toolDragRef.current.windowEl.style.top = `${nextY}px`;
                  toolDragRef.current.startX = nextX;
                  toolDragRef.current.startY = nextY;
                };
                const handleUp = async () => {
                  window.removeEventListener('pointermove', handleMove);
                  window.removeEventListener('pointerup', handleUp);
                  if (toolDragRef.current?.moved) {
                    await updateToolPosition(
                      toolId,
                      toolDragRef.current.startX,
                      toolDragRef.current.startY
                    );
                  }
                  toolDragRef.current = null;
                };
                window.addEventListener('pointermove', handleMove);
                window.addEventListener('pointerup', handleUp, { once: true });
              }}
            >
              <span className="text-xs font-semibold text-slate-200">
                {entry.title}
              </span>
              <div className="flex items-center gap-3 text-slate-400">
                <button
                  type="button"
                  className="hover:text-slate-200 transition-colors text-xs"
                  onClick={() => minimizeTool(toolId)}
                >
                  _
                </button>
                <button
                  type="button"
                  className="hover:text-slate-200 transition-colors text-xs"
                  onClick={() => toggleQuickBarTool(toolId)}
                  title={isPinned ? 'Remove from Quick Bar' : 'Add to Quick Bar'}
                >
                  {isPinned ? '-' : '+'}
                </button>
                <button
                  type="button"
                  className="hover:text-slate-200 transition-colors text-xs"
                  onClick={() => closeTool(toolId)}
                >
                  ×
                </button>
              </div>
            </div>
            <div className="p-3 text-slate-200 text-sm">
              {entry.render(state.toolData[toolId], (next) =>
                updateToolData(toolId, next)
              )}
            </div>
          </div>
        );
      })}
    </>
  );
};

const mount = () => {
  if (document.getElementById(ROOT_ID)) return;

  const host = document.createElement('div');
  host.id = ROOT_ID;
  Object.assign(host.style, {
    position: 'fixed',
    top: '0',
    right: '0',
    zIndex: '2147483647',
    pointerEvents: 'none'
  });

  const shadow = host.attachShadow({ mode: 'open' });
  const styleTag = document.createElement('style');
  styleTag.textContent = tailwindStyles;
  shadow.appendChild(styleTag);

  const appRoot = document.createElement('div');
  appRoot.style.pointerEvents = 'auto';
  shadow.appendChild(appRoot);

  (document.body ?? document.documentElement).appendChild(host);

  const root = ReactDOM.createRoot(appRoot);
  root.render(<App />);
};

export default defineContentScript({
  matches: ['<all_urls>'],
  main() {
    mount();
  }
});
