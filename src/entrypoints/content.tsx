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
  faFont,
  faGear,
  faGlobe,
  faLink,
  faNetworkWired,
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
import { diffJson, resolveJsonPath, validateJsonSchema } from '../shared/json-tools';
import {
  buildSqlQuery,
  formatSql,
  fromDynamo,
  jsonArrayToCsv,
  lintFirebaseRules,
  normalizeBsonValue,
  suggestIndex,
  toDynamo
} from '../shared/data-tools';
import { moveItem } from '../shared/array-tools';
import { getAutoScrollDelta } from '../shared/drag-tools';
import {
  auditAccessibility,
  contrastRatio,
  decodeJwt,
  optimizeSvg,
  parseCookieString,
  runRegexTest,
  safeParseJson
} from '../shared/web-tools';

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
      { label: 'Live Link Preview', toolId: 'liveLinkPreview' },
      { label: 'Debugger', toolId: 'debuggerTool' },
      'Performance Timeline',
      { label: 'Storage Explorer', toolId: 'storageExplorer' },
      { label: 'Console Snippet Runner', toolId: 'snippetRunner' },
      { label: 'Lighthouse Snapshot', toolId: 'lighthouseSnapshot' },
      {
        label: 'Front End',
        items: [
          { label: 'Color Picker', toolId: 'colorPicker' },
          { label: 'CSS Grid Generator', toolId: 'cssGridGenerator' },
          { label: 'Flexbox Inspector', toolId: 'flexboxInspector' },
          { label: 'Font Identifier', toolId: 'fontIdentifier' },
          { label: 'Contrast Checker', toolId: 'contrastChecker' },
          { label: 'Responsive Preview', toolId: 'responsivePreview' },
          { label: 'Animation Preview', toolId: 'animationPreview' },
          { label: 'SVG Optimizer', toolId: 'svgOptimizer' },
          { label: 'Accessibility Audit', toolId: 'accessibilityAudit' }
        ]
      },
      {
        label: 'Back End',
        items: [
          { label: 'JWT Debugger', toolId: 'jwtDebugger' },
          { label: 'Regex Tester', toolId: 'regexTester' },
          { label: 'API Response Viewer', toolId: 'apiResponseViewer' },
          { label: 'GraphQL Explorer', toolId: 'graphqlExplorer' },
          { label: 'REST Client', toolId: 'restClient' },
          { label: 'OAuth Token Inspector', toolId: 'oauthTokenInspector' },
          { label: 'Webhook Tester', toolId: 'webhookTester' },
          { label: 'Cookie Manager', toolId: 'cookieManager' }
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
          { label: 'JSON Prettifier', toolId: 'jsonPrettifier' },
          { label: 'JSON Schema Validator', toolId: 'jsonSchemaValidator' },
          { label: 'JSON Path Tester', toolId: 'jsonPathTester' },
          { label: 'JSON Diff', toolId: 'jsonDiff' }
        ]
      },
      {
        label: 'SQL',
        items: [
          { label: 'SQL Formatter', toolId: 'sqlFormatter' },
          { label: 'SQL Query Builder', toolId: 'sqlQueryBuilder' },
          'Explain Plan Viewer',
          { label: 'SQL to CSV', toolId: 'sqlToCsv' },
          { label: 'Index Advisor', toolId: 'indexAdvisor' }
        ]
      },
      {
        label: 'NoSQL',
        items: [
          { label: 'BSON Viewer', toolId: 'bsonViewer' },
          { label: 'Mongo Query Builder', toolId: 'mongoQueryBuilder' },
          { label: 'DynamoDB JSON Converter', toolId: 'dynamoDbConverter' },
          { label: 'Firebase Rules Linter', toolId: 'firebaseRulesLinter' },
          { label: 'CouchDB Doc Explorer', toolId: 'couchDbDocExplorer' }
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

type LiveLinkPreviewData = {
  isActive?: boolean;
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

type JsonPrettifierData = {
  input?: string;
  output?: string;
  error?: string;
};

type JsonSchemaValidatorData = {
  schema?: string;
  input?: string;
  issues?: string[];
  error?: string;
};

type JsonPathTesterData = {
  input?: string;
  path?: string;
  output?: string;
  error?: string;
};

type JsonDiffData = {
  left?: string;
  right?: string;
  diff?: string[];
  error?: string;
};

type SqlFormatterData = {
  input?: string;
  output?: string;
};

type SqlQueryBuilderData = {
  table?: string;
  columns?: string;
  where?: string;
  orderBy?: string;
  limit?: string;
  output?: string;
};

type SqlToCsvData = {
  input?: string;
  output?: string;
  error?: string;
};

type IndexAdvisorData = {
  table?: string;
  columns?: string;
  unique?: boolean;
  output?: string;
};

type BsonViewerData = {
  input?: string;
  output?: string;
  error?: string;
};

type MongoQueryBuilderData = {
  collection?: string;
  filter?: string;
  projection?: string;
  sort?: string;
  limit?: string;
  output?: string;
  error?: string;
};

type DynamoDbConverterData = {
  input?: string;
  output?: string;
  mode?: 'toDynamo' | 'fromDynamo';
  error?: string;
};

type FirebaseRulesLinterData = {
  input?: string;
  warnings?: string[];
  error?: string;
};

type CouchDbDocExplorerData = {
  url?: string;
  output?: string;
  error?: string;
};

type DebuggerData = {
  entries?: { message: string; source: string; time: number }[];
};

type StorageExplorerData = {
  local?: { key: string; value: string }[];
  session?: { key: string; value: string }[];
};

type SnippetRunnerData = {
  input?: string;
  output?: string;
  error?: string;
};

type LighthouseSnapshotData = {
  metrics?: { label: string; value: string }[];
};

type CssGridGeneratorData = {
  columns?: string;
  rows?: string;
  gap?: string;
  output?: string;
};

type FlexboxInspectorData = {
  selector?: string;
  output?: string[];
};

type FontIdentifierData = {
  selector?: string;
  output?: string[];
};

type ContrastCheckerData = {
  foreground?: string;
  background?: string;
  ratio?: string;
  status?: string;
};

type ResponsivePreviewData = {
  width?: string;
  height?: string;
  status?: string;
};

type AnimationPreviewData = {
  css?: string;
};

type SvgOptimizerData = {
  input?: string;
  output?: string;
};

type AccessibilityAuditData = {
  issues?: string[];
};

type JwtDebuggerData = {
  token?: string;
  header?: string;
  payload?: string;
  error?: string;
};

type RegexTesterData = {
  pattern?: string;
  flags?: string;
  text?: string;
  matches?: string[];
  error?: string;
};

type ApiResponseViewerData = {
  url?: string;
  response?: string;
  status?: string;
  error?: string;
};

type GraphqlExplorerData = {
  url?: string;
  query?: string;
  variables?: string;
  response?: string;
  error?: string;
};

type RestClientData = {
  url?: string;
  method?: string;
  headers?: string;
  body?: string;
  response?: string;
  error?: string;
};

type OAuthTokenInspectorData = {
  token?: string;
  output?: string;
  error?: string;
};

type WebhookTesterData = {
  url?: string;
  body?: string;
  response?: string;
  error?: string;
};

type CookieManagerData = {
  name?: string;
  value?: string;
  cookies?: { name: string; value: string }[];
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

const JsonPrettifierTool = ({
  data,
  onChange
}: {
  data: JsonPrettifierData | undefined;
  onChange: (next: JsonPrettifierData) => void;
}) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handlePrettify = () => {
    try {
      const parsed = JSON.parse(input);
      const prettified = JSON.stringify(parsed, null, 2);
      onChange({ input, output: prettified, error: '' });
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
      <div className="text-xs text-slate-200">JSON Prettifier</div>
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
          onClick={handlePrettify}
          disabled={!input.trim()}
          className="flex-1 rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          Prettify
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
        placeholder="Prettified output..."
      />
    </div>
  );
};

const JsonSchemaValidatorTool = ({
  data,
  onChange
}: {
  data: JsonSchemaValidatorData | undefined;
  onChange: (next: JsonSchemaValidatorData) => void;
}) => {
  const schema = data?.schema ?? '';
  const input = data?.input ?? '';
  const issues = data?.issues ?? [];
  const error = data?.error ?? '';

  const handleValidate = () => {
    try {
      const parsedSchema = JSON.parse(schema);
      const parsedInput = JSON.parse(input);
      const result = validateJsonSchema(parsedSchema, parsedInput);
      onChange({
        schema,
        input,
        issues: result.map((issue) => `${issue.path}: ${issue.message}`),
        error: ''
      });
    } catch (err) {
      onChange({
        schema,
        input,
        issues: [],
        error: err instanceof Error ? err.message : 'Invalid JSON'
      });
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">JSON Schema Validator</div>
      <textarea
        value={schema}
        onChange={(event) =>
          onChange({ schema: event.target.value, input, issues, error })
        }
        rows={5}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Paste JSON schema..."
      />
      <textarea
        value={input}
        onChange={(event) =>
          onChange({ schema, input: event.target.value, issues, error })
        }
        rows={5}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Paste JSON data..."
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <button
        type="button"
        onClick={handleValidate}
        disabled={!schema.trim() || !input.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Validate
      </button>
      <div className="rounded border border-slate-800 bg-slate-900/60 p-3 text-[11px] text-slate-300 max-h-32 overflow-y-auto no-scrollbar">
        {issues.length === 0 ? 'No validation issues found.' : issues.join('\n')}
      </div>
    </div>
  );
};

const JsonPathTesterTool = ({
  data,
  onChange
}: {
  data: JsonPathTesterData | undefined;
  onChange: (next: JsonPathTesterData) => void;
}) => {
  const input = data?.input ?? '';
  const path = data?.path ?? '$';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handleRun = () => {
    try {
      const parsed = JSON.parse(input);
      const result = resolveJsonPath(parsed, path);
      onChange({
        input,
        path,
        output: JSON.stringify(result, null, 2),
        error: ''
      });
    } catch (err) {
      onChange({
        input,
        path,
        output: '',
        error: err instanceof Error ? err.message : 'Invalid JSON'
      });
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">JSON Path Tester</div>
      <input
        type="text"
        value={path}
        onChange={(event) => onChange({ input, path: event.target.value, output, error })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="$.items[0].name"
      />
      <textarea
        value={input}
        onChange={(event) =>
          onChange({ input: event.target.value, path, output, error })
        }
        rows={6}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Paste JSON data..."
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <button
        type="button"
        onClick={handleRun}
        disabled={!input.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Run Path
      </button>
      <textarea
        value={output}
        readOnly
        rows={4}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Result..."
      />
    </div>
  );
};

const JsonDiffTool = ({
  data,
  onChange
}: {
  data: JsonDiffData | undefined;
  onChange: (next: JsonDiffData) => void;
}) => {
  const left = data?.left ?? '';
  const right = data?.right ?? '';
  const diff = data?.diff ?? [];
  const error = data?.error ?? '';

  const handleDiff = () => {
    try {
      const leftParsed = JSON.parse(left);
      const rightParsed = JSON.parse(right);
      const result = diffJson(leftParsed, rightParsed);
      onChange({ left, right, diff: result, error: '' });
    } catch (err) {
      onChange({
        left,
        right,
        diff: [],
        error: err instanceof Error ? err.message : 'Invalid JSON'
      });
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">JSON Diff</div>
      <textarea
        value={left}
        onChange={(event) => onChange({ left: event.target.value, right, diff, error })}
        rows={4}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Left JSON..."
      />
      <textarea
        value={right}
        onChange={(event) => onChange({ left, right: event.target.value, diff, error })}
        rows={4}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Right JSON..."
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <button
        type="button"
        onClick={handleDiff}
        disabled={!left.trim() || !right.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Compare
      </button>
      <div className="rounded border border-slate-800 bg-slate-900/60 p-3 text-[11px] text-slate-300 max-h-32 overflow-y-auto no-scrollbar">
        {diff.length === 0 ? 'No differences found.' : diff.join('\n')}
      </div>
    </div>
  );
};

const SqlFormatterTool = ({
  data,
  onChange
}: {
  data: SqlFormatterData | undefined;
  onChange: (next: SqlFormatterData) => void;
}) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';

  const handleFormat = () => {
    onChange({ input, output: formatSql(input) });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">SQL Formatter</div>
      <textarea
        value={input}
        onChange={(event) => onChange({ input: event.target.value, output })}
        rows={6}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Paste SQL here..."
      />
      <button
        type="button"
        onClick={handleFormat}
        disabled={!input.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Format SQL
      </button>
      <textarea
        value={output}
        readOnly
        rows={6}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Formatted output..."
      />
    </div>
  );
};

const SqlQueryBuilderTool = ({
  data,
  onChange
}: {
  data: SqlQueryBuilderData | undefined;
  onChange: (next: SqlQueryBuilderData) => void;
}) => {
  const table = data?.table ?? '';
  const columns = data?.columns ?? '';
  const where = data?.where ?? '';
  const orderBy = data?.orderBy ?? '';
  const limit = data?.limit ?? '';
  const output = data?.output ?? '';

  const handleBuild = () => {
    const query = buildSqlQuery({
      table,
      columns: columns
        .split(',')
        .map((entry) => entry.trim())
        .filter(Boolean),
      where,
      orderBy,
      limit
    });
    onChange({ table, columns, where, orderBy, limit, output: query });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">SQL Query Builder</div>
      <input
        type="text"
        value={table}
        onChange={(event) =>
          onChange({ table: event.target.value, columns, where, orderBy, limit, output })
        }
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Table name"
      />
      <input
        type="text"
        value={columns}
        onChange={(event) =>
          onChange({ table, columns: event.target.value, where, orderBy, limit, output })
        }
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Columns (comma separated)"
      />
      <input
        type="text"
        value={where}
        onChange={(event) =>
          onChange({ table, columns, where: event.target.value, orderBy, limit, output })
        }
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="WHERE clause"
      />
      <input
        type="text"
        value={orderBy}
        onChange={(event) =>
          onChange({ table, columns, where, orderBy: event.target.value, limit, output })
        }
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="ORDER BY clause"
      />
      <input
        type="text"
        value={limit}
        onChange={(event) =>
          onChange({ table, columns, where, orderBy, limit: event.target.value, output })
        }
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="LIMIT"
      />
      <button
        type="button"
        onClick={handleBuild}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Build Query
      </button>
      <textarea
        value={output}
        readOnly
        rows={4}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="SQL output..."
      />
    </div>
  );
};

const SqlToCsvTool = ({
  data,
  onChange
}: {
  data: SqlToCsvData | undefined;
  onChange: (next: SqlToCsvData) => void;
}) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handleConvert = () => {
    try {
      const parsed = JSON.parse(input);
      const csv = jsonArrayToCsv(parsed);
      if (!csv) {
        onChange({ input, output: '', error: 'Input must be a JSON array.' });
        return;
      }
      onChange({ input, output: csv, error: '' });
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
      <div className="text-xs text-slate-200">SQL to CSV</div>
      <textarea
        value={input}
        onChange={(event) => onChange({ input: event.target.value, output, error })}
        rows={6}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Paste JSON array from SQL result..."
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <div className="flex gap-2">
        <button
          type="button"
          onClick={handleConvert}
          disabled={!input.trim()}
          className="flex-1 rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          Convert
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
        rows={4}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="CSV output..."
      />
    </div>
  );
};

const IndexAdvisorTool = ({
  data,
  onChange
}: {
  data: IndexAdvisorData | undefined;
  onChange: (next: IndexAdvisorData) => void;
}) => {
  const table = data?.table ?? '';
  const columns = data?.columns ?? '';
  const unique = data?.unique ?? false;
  const output = data?.output ?? '';

  const handleSuggest = () => {
    const result = suggestIndex(
      table,
      columns
        .split(',')
        .map((entry) => entry.trim())
        .filter(Boolean),
      unique
    );
    onChange({ table, columns, unique, output: result });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Index Advisor</div>
      <input
        type="text"
        value={table}
        onChange={(event) =>
          onChange({ table: event.target.value, columns, unique, output })
        }
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Table name"
      />
      <input
        type="text"
        value={columns}
        onChange={(event) =>
          onChange({ table, columns: event.target.value, unique, output })
        }
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Columns (comma separated)"
      />
      <label className="flex items-center gap-2 text-[11px] text-slate-400">
        <input
          type="checkbox"
          checked={unique}
          onChange={(event) =>
            onChange({ table, columns, unique: event.target.checked, output })
          }
          className="h-3 w-3 rounded border border-slate-700 bg-slate-800 text-blue-500 focus:ring-0 focus:outline-none"
        />
        Unique index
      </label>
      <button
        type="button"
        onClick={handleSuggest}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Suggest Index
      </button>
      <textarea
        value={output}
        readOnly
        rows={3}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Suggested index..."
      />
    </div>
  );
};

const BsonViewerTool = ({
  data,
  onChange
}: {
  data: BsonViewerData | undefined;
  onChange: (next: BsonViewerData) => void;
}) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handleParse = () => {
    try {
      const parsed = JSON.parse(input);
      const normalized = normalizeBsonValue(parsed);
      onChange({
        input,
        output: JSON.stringify(normalized, null, 2),
        error: ''
      });
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
      <div className="text-xs text-slate-200">BSON Viewer</div>
      <textarea
        value={input}
        onChange={(event) => onChange({ input: event.target.value, output, error })}
        rows={6}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Paste BSON (extended JSON)..."
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <button
        type="button"
        onClick={handleParse}
        disabled={!input.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Normalize
      </button>
      <textarea
        value={output}
        readOnly
        rows={5}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Normalized output..."
      />
    </div>
  );
};

const MongoQueryBuilderTool = ({
  data,
  onChange
}: {
  data: MongoQueryBuilderData | undefined;
  onChange: (next: MongoQueryBuilderData) => void;
}) => {
  const collection = data?.collection ?? '';
  const filter = data?.filter ?? '{}';
  const projection = data?.projection ?? '{}';
  const sort = data?.sort ?? '{}';
  const limit = data?.limit ?? '';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handleBuild = () => {
    try {
      JSON.parse(filter);
      JSON.parse(projection);
      JSON.parse(sort);
      const limitValue = limit.trim() ? `.limit(${limit.trim()})` : '';
      const query = `db.${collection || 'collection'}.find(${filter}, ${projection}).sort(${sort})${limitValue}`;
      onChange({ collection, filter, projection, sort, limit, output: query, error: '' });
    } catch (err) {
      onChange({
        collection,
        filter,
        projection,
        sort,
        limit,
        output: '',
        error: err instanceof Error ? err.message : 'Invalid JSON'
      });
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Mongo Query Builder</div>
      <input
        type="text"
        value={collection}
        onChange={(event) =>
          onChange({ collection: event.target.value, filter, projection, sort, limit, output, error })
        }
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Collection name"
      />
      <textarea
        value={filter}
        onChange={(event) =>
          onChange({ collection, filter: event.target.value, projection, sort, limit, output, error })
        }
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder='Filter (e.g. {"status":"active"})'
      />
      <textarea
        value={projection}
        onChange={(event) =>
          onChange({ collection, filter, projection: event.target.value, sort, limit, output, error })
        }
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder='Projection (e.g. {"name":1})'
      />
      <textarea
        value={sort}
        onChange={(event) =>
          onChange({ collection, filter, projection, sort: event.target.value, limit, output, error })
        }
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder='Sort (e.g. {"createdAt":-1})'
      />
      <input
        type="text"
        value={limit}
        onChange={(event) =>
          onChange({ collection, filter, projection, sort, limit: event.target.value, output, error })
        }
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Limit"
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <button
        type="button"
        onClick={handleBuild}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Build Query
      </button>
      <textarea
        value={output}
        readOnly
        rows={3}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Mongo query output..."
      />
    </div>
  );
};

const DynamoDbConverterTool = ({
  data,
  onChange
}: {
  data: DynamoDbConverterData | undefined;
  onChange: (next: DynamoDbConverterData) => void;
}) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const mode = data?.mode ?? 'toDynamo';
  const error = data?.error ?? '';

  const handleConvert = () => {
    try {
      const parsed = JSON.parse(input);
      const result = mode === 'toDynamo' ? toDynamo(parsed) : fromDynamo(parsed);
      onChange({ input, output: JSON.stringify(result, null, 2), mode, error: '' });
    } catch (err) {
      onChange({
        input,
        output: '',
        mode,
        error: err instanceof Error ? err.message : 'Invalid JSON'
      });
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">DynamoDB JSON Converter</div>
      <div className="flex gap-2">
        {(['toDynamo', 'fromDynamo'] as const).map((option) => (
          <button
            key={option}
            type="button"
            onClick={() => onChange({ input, output, mode: option, error })}
            className={`flex-1 rounded px-2 py-1 text-[11px] border transition-colors ${
              mode === option
                ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
            }`}
          >
            {option === 'toDynamo' ? 'To Dynamo' : 'From Dynamo'}
          </button>
        ))}
      </div>
      <textarea
        value={input}
        onChange={(event) => onChange({ input: event.target.value, output, mode, error })}
        rows={5}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Paste JSON..."
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <button
        type="button"
        onClick={handleConvert}
        disabled={!input.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Convert
      </button>
      <textarea
        value={output}
        readOnly
        rows={5}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Converted output..."
      />
    </div>
  );
};

const FirebaseRulesLinterTool = ({
  data,
  onChange
}: {
  data: FirebaseRulesLinterData | undefined;
  onChange: (next: FirebaseRulesLinterData) => void;
}) => {
  const input = data?.input ?? '';
  const warnings = data?.warnings ?? [];
  const error = data?.error ?? '';

  const handleLint = () => {
    try {
      const parsed = JSON.parse(input);
      const result = lintFirebaseRules(parsed);
      onChange({ input, warnings: result, error: '' });
    } catch (err) {
      onChange({
        input,
        warnings: [],
        error: err instanceof Error ? err.message : 'Invalid JSON'
      });
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Firebase Rules Linter</div>
      <textarea
        value={input}
        onChange={(event) => onChange({ input: event.target.value, warnings, error })}
        rows={6}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Paste rules JSON..."
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <button
        type="button"
        onClick={handleLint}
        disabled={!input.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Lint Rules
      </button>
      <div className="rounded border border-slate-800 bg-slate-900/60 p-3 text-[11px] text-slate-300 max-h-32 overflow-y-auto no-scrollbar">
        {warnings.length === 0 ? 'No warnings.' : warnings.join('\n')}
      </div>
    </div>
  );
};

const CouchDbDocExplorerTool = ({
  data,
  onChange
}: {
  data: CouchDbDocExplorerData | undefined;
  onChange: (next: CouchDbDocExplorerData) => void;
}) => {
  const url = data?.url ?? '';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handleFetch = async () => {
    const result = await chrome.runtime.sendMessage({
      type: 'xcalibr-couchdb-fetch',
      payload: { url }
    });
    onChange({
      url,
      output: result?.output ?? '',
      error: result?.error ?? ''
    });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">CouchDB Doc Explorer</div>
      <input
        type="text"
        value={url}
        onChange={(event) => onChange({ url: event.target.value, output, error })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="https://db.example.com/mydb/docid"
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <button
        type="button"
        onClick={handleFetch}
        disabled={!url.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Fetch Doc
      </button>
      <textarea
        value={output}
        readOnly
        rows={6}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Document output..."
      />
    </div>
  );
};

const DebuggerTool = ({
  data,
  onClear
}: {
  data: DebuggerData | undefined;
  onClear: () => void;
}) => {
  const entries = data?.entries ?? [];
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">Debugger</div>
        <button
          type="button"
          onClick={onClear}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Clear
        </button>
      </div>
      {entries.length === 0 ? (
        <div className="text-[11px] text-slate-500">No errors captured.</div>
      ) : (
        <div className="max-h-40 overflow-y-auto no-scrollbar space-y-2 text-[11px] text-slate-300">
          {entries.map((entry, index) => (
            <div key={`${entry.time}-${index}`} className="rounded border border-slate-800 bg-slate-900/60 px-2 py-1">
              <div className="text-[10px] text-slate-500">
                {new Date(entry.time).toLocaleTimeString()} • {entry.source}
              </div>
              <div className="break-words">{entry.message}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const StorageExplorerTool = ({
  data,
  onRefresh
}: {
  data: StorageExplorerData | undefined;
  onRefresh: () => void;
}) => {
  const local = data?.local ?? [];
  const session = data?.session ?? [];
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">Storage Explorer</div>
        <button
          type="button"
          onClick={onRefresh}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Refresh
        </button>
      </div>
      <div className="text-[11px] text-slate-500">Local Storage</div>
      <div className="max-h-24 overflow-y-auto no-scrollbar space-y-1 text-[11px] text-slate-300">
        {local.length === 0 ? 'No entries.' : null}
        {local.map((entry) => (
          <div key={`local-${entry.key}`} className="break-words">
            {entry.key}: {entry.value}
          </div>
        ))}
      </div>
      <div className="text-[11px] text-slate-500">Session Storage</div>
      <div className="max-h-24 overflow-y-auto no-scrollbar space-y-1 text-[11px] text-slate-300">
        {session.length === 0 ? 'No entries.' : null}
        {session.map((entry) => (
          <div key={`session-${entry.key}`} className="break-words">
            {entry.key}: {entry.value}
          </div>
        ))}
      </div>
    </div>
  );
};

const SnippetRunnerTool = ({
  data,
  onChange
}: {
  data: SnippetRunnerData | undefined;
  onChange: (next: SnippetRunnerData) => void;
}) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handleRun = () => {
    try {
      // eslint-disable-next-line no-new-func
      const result = new Function(input)();
      onChange({ input, output: String(result ?? ''), error: '' });
    } catch (err) {
      onChange({
        input,
        output: '',
        error: err instanceof Error ? err.message : 'Execution failed'
      });
    }
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Console Snippet Runner</div>
      <textarea
        value={input}
        onChange={(event) => onChange({ input: event.target.value, output, error })}
        rows={5}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="JavaScript snippet..."
      />
      {error ? (
        <div className="text-[11px] text-rose-300">{error}</div>
      ) : null}
      <button
        type="button"
        onClick={handleRun}
        disabled={!input.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Run Snippet
      </button>
      <textarea
        value={output}
        readOnly
        rows={3}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Output..."
      />
    </div>
  );
};

const LighthouseSnapshotTool = ({
  data,
  onCapture
}: {
  data: LighthouseSnapshotData | undefined;
  onCapture: () => void;
}) => {
  const metrics = data?.metrics ?? [];
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">Lighthouse Snapshot</div>
        <button
          type="button"
          onClick={onCapture}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Capture
        </button>
      </div>
      <div className="space-y-1 text-[11px] text-slate-300">
        {metrics.length === 0 ? (
          <div className="text-slate-500">No snapshot yet.</div>
        ) : (
          metrics.map((metric) => (
            <div key={metric.label} className="flex items-center justify-between">
              <span className="text-slate-400">{metric.label}</span>
              <span>{metric.value}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

const CssGridGeneratorTool = ({
  data,
  onChange
}: {
  data: CssGridGeneratorData | undefined;
  onChange: (next: CssGridGeneratorData) => void;
}) => {
  const columns = data?.columns ?? 'repeat(3, 1fr)';
  const rows = data?.rows ?? 'auto';
  const gap = data?.gap ?? '16px';
  const output = data?.output ?? '';

  const handleGenerate = () => {
    const css = `display: grid;\n grid-template-columns: ${columns};\n grid-template-rows: ${rows};\n gap: ${gap};`;
    onChange({ columns, rows, gap, output: css });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">CSS Grid Generator</div>
      <input
        type="text"
        value={columns}
        onChange={(event) => onChange({ columns: event.target.value, rows, gap, output })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Columns (e.g. repeat(3, 1fr))"
      />
      <input
        type="text"
        value={rows}
        onChange={(event) => onChange({ columns, rows: event.target.value, gap, output })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Rows (e.g. auto)"
      />
      <input
        type="text"
        value={gap}
        onChange={(event) => onChange({ columns, rows, gap: event.target.value, output })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="Gap (e.g. 16px)"
      />
      <button
        type="button"
        onClick={handleGenerate}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Generate CSS
      </button>
      <textarea
        value={output}
        readOnly
        rows={4}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="CSS output..."
      />
    </div>
  );
};

const FlexboxInspectorTool = ({
  data,
  onChange
}: {
  data: FlexboxInspectorData | undefined;
  onChange: (next: FlexboxInspectorData) => void;
}) => {
  const selector = data?.selector ?? '';
  const output = data?.output ?? [];

  const handleInspect = () => {
    const element = document.querySelector(selector);
    if (!element) {
      onChange({ selector, output: ['Element not found.'] });
      return;
    }
    const style = window.getComputedStyle(element);
    onChange({
      selector,
      output: [
        `display: ${style.display}`,
        `flex-direction: ${style.flexDirection}`,
        `justify-content: ${style.justifyContent}`,
        `align-items: ${style.alignItems}`,
        `gap: ${style.gap}`
      ]
    });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Flexbox Inspector</div>
      <input
        type="text"
        value={selector}
        onChange={(event) => onChange({ selector: event.target.value, output })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="CSS selector (e.g. .container)"
      />
      <button
        type="button"
        onClick={handleInspect}
        disabled={!selector.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Inspect
      </button>
      <div className="rounded border border-slate-800 bg-slate-900/60 p-3 text-[11px] text-slate-300">
        {output.length === 0 ? 'No data yet.' : output.join('\n')}
      </div>
    </div>
  );
};

const FontIdentifierTool = ({
  data,
  onChange
}: {
  data: FontIdentifierData | undefined;
  onChange: (next: FontIdentifierData) => void;
}) => {
  const selector = data?.selector ?? '';
  const output = data?.output ?? [];

  const handleInspect = () => {
    const element = document.querySelector(selector);
    if (!element) {
      onChange({ selector, output: ['Element not found.'] });
      return;
    }
    const style = window.getComputedStyle(element);
    onChange({
      selector,
      output: [
        `font-family: ${style.fontFamily}`,
        `font-size: ${style.fontSize}`,
        `font-weight: ${style.fontWeight}`,
        `line-height: ${style.lineHeight}`
      ]
    });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Font Identifier</div>
      <input
        type="text"
        value={selector}
        onChange={(event) => onChange({ selector: event.target.value, output })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="CSS selector (e.g. h1)"
      />
      <button
        type="button"
        onClick={handleInspect}
        disabled={!selector.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Inspect
      </button>
      <div className="rounded border border-slate-800 bg-slate-900/60 p-3 text-[11px] text-slate-300">
        {output.length === 0 ? 'No data yet.' : output.join('\n')}
      </div>
    </div>
  );
};

const ContrastCheckerTool = ({
  data,
  onChange
}: {
  data: ContrastCheckerData | undefined;
  onChange: (next: ContrastCheckerData) => void;
}) => {
  const foreground = data?.foreground ?? '#0f172a';
  const background = data?.background ?? '#ffffff';
  const ratio = data?.ratio ?? '';
  const status = data?.status ?? '';

  const handleCheck = () => {
    const result = contrastRatio(foreground, background);
    if (!result) {
      onChange({ foreground, background, ratio: '', status: 'Invalid colors.' });
      return;
    }
    const rounded = result.toFixed(2);
    const passAA = result >= 4.5;
    const passAAA = result >= 7;
    onChange({
      foreground,
      background,
      ratio: rounded,
      status: passAAA ? 'AAA Pass' : passAA ? 'AA Pass' : 'Fail'
    });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Contrast Checker</div>
      <div className="flex gap-2">
        <input
          type="color"
          value={foreground}
          onChange={(event) =>
            onChange({ foreground: event.target.value, background, ratio, status })
          }
          className="h-10 w-10 rounded border border-slate-700 bg-slate-800"
        />
        <input
          type="color"
          value={background}
          onChange={(event) =>
            onChange({ foreground, background: event.target.value, ratio, status })
          }
          className="h-10 w-10 rounded border border-slate-700 bg-slate-800"
        />
        <div className="flex-1 text-[11px] text-slate-500 flex items-center">
          Ratio: {ratio || '—'} ({status || '—'})
        </div>
      </div>
      <button
        type="button"
        onClick={handleCheck}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Check Contrast
      </button>
    </div>
  );
};

const ResponsivePreviewTool = ({
  data,
  onChange
}: {
  data: ResponsivePreviewData | undefined;
  onChange: (next: ResponsivePreviewData) => void;
}) => {
  const width = data?.width ?? '375';
  const height = data?.height ?? '812';
  const status = data?.status ?? '';

  const handleOpen = () => {
    const w = Number(width);
    const h = Number(height);
    if (!Number.isFinite(w) || !Number.isFinite(h)) {
      onChange({ width, height, status: 'Invalid size.' });
      return;
    }
    window.open(window.location.href, '_blank', `width=${w},height=${h}`);
    onChange({ width, height, status: 'Opened preview window.' });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Responsive Preview</div>
      <div className="flex gap-2">
        <input
          type="text"
          value={width}
          onChange={(event) => onChange({ width: event.target.value, height, status })}
          className="w-1/2 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
          placeholder="Width"
        />
        <input
          type="text"
          value={height}
          onChange={(event) => onChange({ width, height: event.target.value, status })}
          className="w-1/2 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
          placeholder="Height"
        />
      </div>
      <button
        type="button"
        onClick={handleOpen}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Open Preview Window
      </button>
      {status ? <div className="text-[11px] text-slate-500">{status}</div> : null}
    </div>
  );
};

const AnimationPreviewTool = ({
  data,
  onChange
}: {
  data: AnimationPreviewData | undefined;
  onChange: (next: AnimationPreviewData) => void;
}) => {
  const css = data?.css ?? 'animation: pulse 1.2s ease-in-out infinite;';
  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Animation Preview</div>
      <textarea
        value={css}
        onChange={(event) => onChange({ css: event.target.value })}
        rows={4}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="CSS animation..."
      />
      <div className="rounded border border-slate-800 bg-slate-900/60 p-4">
        <div className="xcalibr-animation-preview h-12 w-12 rounded bg-blue-500/70" />
        <style>{`
          @keyframes pulse { 0% { transform: scale(1); } 50% { transform: scale(1.15); } 100% { transform: scale(1); } }
          .xcalibr-animation-preview { ${css} }
        `}</style>
      </div>
    </div>
  );
};

const SvgOptimizerTool = ({
  data,
  onChange
}: {
  data: SvgOptimizerData | undefined;
  onChange: (next: SvgOptimizerData) => void;
}) => {
  const input = data?.input ?? '';
  const output = data?.output ?? '';
  const handleOptimize = () => onChange({ input, output: optimizeSvg(input) });
  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">SVG Optimizer</div>
      <textarea
        value={input}
        onChange={(event) => onChange({ input: event.target.value, output })}
        rows={5}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="<svg>...</svg>"
      />
      <button
        type="button"
        onClick={handleOptimize}
        disabled={!input.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Optimize SVG
      </button>
      <textarea
        value={output}
        readOnly
        rows={5}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Optimized output..."
      />
    </div>
  );
};

const AccessibilityAuditTool = ({
  data,
  onRun
}: {
  data: AccessibilityAuditData | undefined;
  onRun: () => void;
}) => {
  const issues = data?.issues ?? [];
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">Accessibility Audit</div>
        <button
          type="button"
          onClick={onRun}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Run Audit
        </button>
      </div>
      <div className="rounded border border-slate-800 bg-slate-900/60 p-3 text-[11px] text-slate-300 max-h-32 overflow-y-auto no-scrollbar">
        {issues.length === 0 ? 'No audit results yet.' : issues.join('\n')}
      </div>
    </div>
  );
};

const JwtDebuggerTool = ({
  data,
  onChange
}: {
  data: JwtDebuggerData | undefined;
  onChange: (next: JwtDebuggerData) => void;
}) => {
  const token = data?.token ?? '';
  const header = data?.header ?? '';
  const payload = data?.payload ?? '';
  const error = data?.error ?? '';

  const handleDecode = () => {
    const result = decodeJwt(token);
    if (result.error) {
      onChange({ token, header: '', payload: '', error: result.error });
      return;
    }
    onChange({
      token,
      header: JSON.stringify(result.header, null, 2),
      payload: JSON.stringify(result.payload, null, 2),
      error: ''
    });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">JWT Debugger</div>
      <textarea
        value={token}
        onChange={(event) => onChange({ token: event.target.value, header, payload, error })}
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors font-mono"
        placeholder="Paste JWT..."
      />
      {error ? <div className="text-[11px] text-rose-300">{error}</div> : null}
      <button
        type="button"
        onClick={handleDecode}
        disabled={!token.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Decode Token
      </button>
      <textarea
        value={header}
        readOnly
        rows={3}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Header..."
      />
      <textarea
        value={payload}
        readOnly
        rows={4}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Payload..."
      />
    </div>
  );
};

const RegexTesterTool = ({
  data,
  onChange
}: {
  data: RegexTesterData | undefined;
  onChange: (next: RegexTesterData) => void;
}) => {
  const pattern = data?.pattern ?? '';
  const flags = data?.flags ?? 'g';
  const text = data?.text ?? '';
  const matches = data?.matches ?? [];
  const error = data?.error ?? '';

  const handleTest = () => {
    const result = runRegexTest(pattern, flags, text);
    onChange({ pattern, flags, text, matches: result.matches, error: result.error ?? '' });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Regex Tester</div>
      <input
        type="text"
        value={pattern}
        onChange={(event) => onChange({ pattern: event.target.value, flags, text, matches, error })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder="Regex pattern"
      />
      <input
        type="text"
        value={flags}
        onChange={(event) => onChange({ pattern, flags: event.target.value, text, matches, error })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder="Flags (e.g. gi)"
      />
      <textarea
        value={text}
        onChange={(event) => onChange({ pattern, flags, text: event.target.value, matches, error })}
        rows={4}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder="Test string..."
      />
      {error ? <div className="text-[11px] text-rose-300">{error}</div> : null}
      <button
        type="button"
        onClick={handleTest}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors"
      >
        Run Test
      </button>
      <div className="rounded border border-slate-800 bg-slate-900/60 p-3 text-[11px] text-slate-300 max-h-24 overflow-y-auto no-scrollbar">
        {matches.length === 0 ? 'No matches.' : matches.join('\n')}
      </div>
    </div>
  );
};

const ApiResponseViewerTool = ({
  data,
  onChange
}: {
  data: ApiResponseViewerData | undefined;
  onChange: (next: ApiResponseViewerData) => void;
}) => {
  const url = data?.url ?? '';
  const response = data?.response ?? '';
  const status = data?.status ?? '';
  const error = data?.error ?? '';

  const handleFetch = async () => {
    const result = await chrome.runtime.sendMessage({
      type: 'xcalibr-http-request',
      payload: { url, method: 'GET', headers: {} }
    });
    if (result?.error) {
      onChange({ url, response: '', status: '', error: result.error });
      return;
    }
    onChange({
      url,
      response: result.body ?? '',
      status: `${result.status} ${result.statusText ?? ''}`.trim(),
      error: ''
    });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">API Response Viewer</div>
      <input
        type="text"
        value={url}
        onChange={(event) => onChange({ url: event.target.value, response, status, error })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="https://api.example.com"
      />
      {error ? <div className="text-[11px] text-rose-300">{error}</div> : null}
      <button
        type="button"
        onClick={handleFetch}
        disabled={!url.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Fetch Response
      </button>
      {status ? <div className="text-[11px] text-slate-500">Status: {status}</div> : null}
      <textarea
        value={response}
        readOnly
        rows={5}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Response body..."
      />
    </div>
  );
};

const GraphqlExplorerTool = ({
  data,
  onChange
}: {
  data: GraphqlExplorerData | undefined;
  onChange: (next: GraphqlExplorerData) => void;
}) => {
  const url = data?.url ?? '';
  const query = data?.query ?? '';
  const variables = data?.variables ?? '';
  const response = data?.response ?? '';
  const error = data?.error ?? '';

  const handleRun = async () => {
    const vars = variables.trim() ? safeParseJson(variables) : { value: {}, error: null };
    if (vars.error) {
      onChange({ url, query, variables, response: '', error: vars.error });
      return;
    }
    const result = await chrome.runtime.sendMessage({
      type: 'xcalibr-http-request',
      payload: {
        url,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query, variables: vars.value })
      }
    });
    if (result?.error) {
      onChange({ url, query, variables, response: '', error: result.error });
      return;
    }
    onChange({
      url,
      query,
      variables,
      response: result.body ?? '',
      error: ''
    });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">GraphQL Explorer</div>
      <input
        type="text"
        value={url}
        onChange={(event) => onChange({ url: event.target.value, query, variables, response, error })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="https://api.example.com/graphql"
      />
      <textarea
        value={query}
        onChange={(event) => onChange({ url, query: event.target.value, variables, response, error })}
        rows={4}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder="GraphQL query..."
      />
      <textarea
        value={variables}
        onChange={(event) => onChange({ url, query, variables: event.target.value, response, error })}
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder="Variables JSON..."
      />
      {error ? <div className="text-[11px] text-rose-300">{error}</div> : null}
      <button
        type="button"
        onClick={handleRun}
        disabled={!url.trim() || !query.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Run Query
      </button>
      <textarea
        value={response}
        readOnly
        rows={4}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Response..."
      />
    </div>
  );
};

const RestClientTool = ({
  data,
  onChange
}: {
  data: RestClientData | undefined;
  onChange: (next: RestClientData) => void;
}) => {
  const url = data?.url ?? '';
  const method = data?.method ?? 'GET';
  const headers = data?.headers ?? '';
  const body = data?.body ?? '';
  const response = data?.response ?? '';
  const error = data?.error ?? '';

  const handleSend = async () => {
    const headerEntries = parseHeadersInput(headers).reduce<Record<string, string>>((acc, entry) => {
      acc[entry.name] = entry.value;
      return acc;
    }, {});
    const result = await chrome.runtime.sendMessage({
      type: 'xcalibr-http-request',
      payload: { url, method, headers: headerEntries, body }
    });
    if (result?.error) {
      onChange({ url, method, headers, body, response: '', error: result.error });
      return;
    }
    onChange({
      url,
      method,
      headers,
      body,
      response: result.body ?? '',
      error: ''
    });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">REST Client</div>
      <input
        type="text"
        value={url}
        onChange={(event) => onChange({ url: event.target.value, method, headers, body, response, error })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="https://api.example.com"
      />
      <div className="flex gap-2">
        {['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((option) => (
          <button
            key={option}
            type="button"
            onClick={() => onChange({ url, method: option, headers, body, response, error })}
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
        onChange={(event) => onChange({ url, method, headers: event.target.value, body, response, error })}
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder="Header: value"
      />
      <textarea
        value={body}
        onChange={(event) => onChange({ url, method, headers, body: event.target.value, response, error })}
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder="Request body"
      />
      {error ? <div className="text-[11px] text-rose-300">{error}</div> : null}
      <button
        type="button"
        onClick={handleSend}
        disabled={!url.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Send Request
      </button>
      <textarea
        value={response}
        readOnly
        rows={4}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Response..."
      />
    </div>
  );
};

const OAuthTokenInspectorTool = ({
  data,
  onChange
}: {
  data: OAuthTokenInspectorData | undefined;
  onChange: (next: OAuthTokenInspectorData) => void;
}) => {
  const token = data?.token ?? '';
  const output = data?.output ?? '';
  const error = data?.error ?? '';

  const handleInspect = () => {
    const result = decodeJwt(token);
    if (result.error) {
      onChange({ token, output: '', error: result.error });
      return;
    }
    const payload = result.payload ?? {};
    onChange({ token, output: JSON.stringify(payload, null, 2), error: '' });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">OAuth Token Inspector</div>
      <textarea
        value={token}
        onChange={(event) => onChange({ token: event.target.value, output, error })}
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder="Paste access token..."
      />
      {error ? <div className="text-[11px] text-rose-300">{error}</div> : null}
      <button
        type="button"
        onClick={handleInspect}
        disabled={!token.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Inspect Token
      </button>
      <textarea
        value={output}
        readOnly
        rows={4}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Token payload..."
      />
    </div>
  );
};

const WebhookTesterTool = ({
  data,
  onChange
}: {
  data: WebhookTesterData | undefined;
  onChange: (next: WebhookTesterData) => void;
}) => {
  const url = data?.url ?? '';
  const body = data?.body ?? '';
  const response = data?.response ?? '';
  const error = data?.error ?? '';

  const handleSend = async () => {
    const result = await chrome.runtime.sendMessage({
      type: 'xcalibr-http-request',
      payload: {
        url,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body
      }
    });
    if (result?.error) {
      onChange({ url, body, response: '', error: result.error });
      return;
    }
    onChange({ url, body, response: result.body ?? '', error: '' });
  };

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Webhook Tester</div>
      <input
        type="text"
        value={url}
        onChange={(event) => onChange({ url: event.target.value, body, response, error })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        placeholder="https://webhook.site/..."
      />
      <textarea
        value={body}
        onChange={(event) => onChange({ url, body: event.target.value, response, error })}
        rows={3}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
        placeholder='{"event":"ping"}'
      />
      {error ? <div className="text-[11px] text-rose-300">{error}</div> : null}
      <button
        type="button"
        onClick={handleSend}
        disabled={!url.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Send Webhook
      </button>
      <textarea
        value={response}
        readOnly
        rows={4}
        className="w-full rounded bg-slate-900 text-slate-300 text-xs px-2 py-2 border border-slate-800 focus:outline-none font-mono"
        placeholder="Response..."
      />
    </div>
  );
};

const CookieManagerTool = ({
  data,
  onChange,
  onRefresh
}: {
  data: CookieManagerData | undefined;
  onChange: (next: CookieManagerData) => void;
  onRefresh: () => void;
}) => {
  const name = data?.name ?? '';
  const value = data?.value ?? '';
  const cookies = data?.cookies ?? [];

  const handleSet = () => {
    if (!name.trim()) return;
    document.cookie = `${name}=${value}; path=/`;
    onRefresh();
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-xs text-slate-200">Cookie Manager</div>
        <button
          type="button"
          onClick={onRefresh}
          className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
        >
          Refresh
        </button>
      </div>
      <div className="flex gap-2">
        <input
          type="text"
          value={name}
          onChange={(event) => onChange({ name: event.target.value, value, cookies })}
          className="w-1/2 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
          placeholder="Cookie name"
        />
        <input
          type="text"
          value={value}
          onChange={(event) => onChange({ name, value: event.target.value, cookies })}
          className="w-1/2 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
          placeholder="Value"
        />
      </div>
      <button
        type="button"
        onClick={handleSet}
        disabled={!name.trim()}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        Set Cookie
      </button>
      <div className="max-h-32 overflow-y-auto no-scrollbar text-[11px] text-slate-300 space-y-1">
        {cookies.length === 0 ? 'No cookies.' : null}
        {cookies.map((cookie) => (
          <div key={cookie.name} className="break-words">
            {cookie.name}: {cookie.value}
          </div>
        ))}
      </div>
    </div>
  );
};

const LiveLinkPreviewTool = ({
  data,
  onChange
}: {
  data: LiveLinkPreviewData | undefined;
  onChange: (next: LiveLinkPreviewData) => void;
}) => {
  const isActive = data?.isActive ?? false;
  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Live Link Preview</div>
      <div className="text-[11px] text-slate-500">
        Hover over links to preview destinations. Only active when toggled on.
      </div>
      <button
        type="button"
        onClick={() => onChange({ isActive: !isActive })}
        className={`w-full rounded px-2 py-1.5 text-xs border transition-colors ${
          isActive
            ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-200'
            : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
        }`}
      >
        {isActive ? 'Active' : 'Inactive'}
      </button>
    </div>
  );
};

const PREVIEW_SCALE = 0.5;
const PREVIEW_WIDTH = 960;
const PREVIEW_HEIGHT = 540;
const PREVIEW_MARGIN = 12;

const createPreviewHost = () => {
  const host = document.createElement('div');
  host.style.position = 'fixed';
  host.style.zIndex = '2147483646';
  host.style.pointerEvents = 'none';
  const shadow = host.attachShadow({ mode: 'open' });
  const style = document.createElement('style');
  style.textContent = `
    .preview-card {
      position: fixed;
      border-radius: 14px;
      border: 1px solid rgba(15, 23, 42, 0.8);
      background: rgba(15, 23, 42, 0.92);
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.45);
      padding: 8px;
      width: ${PREVIEW_WIDTH * PREVIEW_SCALE}px;
      height: ${PREVIEW_HEIGHT * PREVIEW_SCALE}px;
      overflow: hidden;
      pointer-events: none;
    }
    .preview-frame {
      width: ${PREVIEW_WIDTH}px;
      height: ${PREVIEW_HEIGHT}px;
      border: none;
      transform: scale(${PREVIEW_SCALE});
      transform-origin: top left;
      background: #0f172a;
    }
    .preview-title {
      font-size: 10px;
      color: #94a3b8;
      margin-bottom: 6px;
      text-overflow: ellipsis;
      white-space: nowrap;
      overflow: hidden;
      max-width: 100%;
    }
  `;
  shadow.appendChild(style);
  const wrapper = document.createElement('div');
  wrapper.className = 'preview-card';
  const title = document.createElement('div');
  title.className = 'preview-title';
  wrapper.appendChild(title);
  const frame = document.createElement('iframe');
  frame.className = 'preview-frame';
  frame.setAttribute('sandbox', 'allow-same-origin allow-scripts allow-forms');
  frame.setAttribute('loading', 'lazy');
  wrapper.appendChild(frame);
  shadow.appendChild(wrapper);
  document.body.appendChild(host);
  return { host, wrapper, frame, title };
};

const isValidPreviewUrl = (href: string) => {
  try {
    const url = new URL(href);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
};

const buildToolRegistry = (handlers: {
  refreshStorageExplorer: () => void;
  refreshCookies: () => void;
}): ToolRegistryEntry[] => [
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
    id: 'liveLinkPreview',
    title: 'Live Link Preview',
    subtitle: 'Hover link previews',
    category: 'Web Dev',
    icon: faLink,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <LiveLinkPreviewTool
        data={data as LiveLinkPreviewData | undefined}
        onChange={(next) => onChange(next)}
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
    id: 'jsonPrettifier',
    title: 'JSON Prettifier',
    subtitle: 'Format JSON',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <JsonPrettifierTool
        data={data as JsonPrettifierData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'jsonSchemaValidator',
    title: 'JSON Schema Validator',
    subtitle: 'Validate JSON',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <JsonSchemaValidatorTool
        data={data as JsonSchemaValidatorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'jsonPathTester',
    title: 'JSON Path Tester',
    subtitle: 'Query JSON',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <JsonPathTesterTool
        data={data as JsonPathTesterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'jsonDiff',
    title: 'JSON Diff',
    subtitle: 'Compare JSON',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <JsonDiffTool
        data={data as JsonDiffData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'sqlFormatter',
    title: 'SQL Formatter',
    subtitle: 'Format SQL',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <SqlFormatterTool
        data={data as SqlFormatterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'sqlQueryBuilder',
    title: 'SQL Query Builder',
    subtitle: 'Build SELECT',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <SqlQueryBuilderTool
        data={data as SqlQueryBuilderData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'sqlToCsv',
    title: 'SQL to CSV',
    subtitle: 'Export results',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <SqlToCsvTool
        data={data as SqlToCsvData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'indexAdvisor',
    title: 'Index Advisor',
    subtitle: 'Suggest indexes',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <IndexAdvisorTool
        data={data as IndexAdvisorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'bsonViewer',
    title: 'BSON Viewer',
    subtitle: 'Normalize BSON',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <BsonViewerTool
        data={data as BsonViewerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'mongoQueryBuilder',
    title: 'Mongo Query Builder',
    subtitle: 'Build Mongo find',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <MongoQueryBuilderTool
        data={data as MongoQueryBuilderData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'dynamoDbConverter',
    title: 'DynamoDB Converter',
    subtitle: 'Map JSON types',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <DynamoDbConverterTool
        data={data as DynamoDbConverterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'firebaseRulesLinter',
    title: 'Firebase Rules Linter',
    subtitle: 'Check rules',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <FirebaseRulesLinterTool
        data={data as FirebaseRulesLinterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'couchDbDocExplorer',
    title: 'CouchDB Doc Explorer',
    subtitle: 'Fetch docs',
    category: 'Database',
    icon: faCode,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <CouchDbDocExplorerTool
        data={data as CouchDbDocExplorerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'debuggerTool',
    title: 'Debugger',
    subtitle: 'Capture errors',
    category: 'Web Dev',
    icon: faBug,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <DebuggerTool
        data={data as DebuggerData | undefined}
        onClear={() => onChange({ entries: [] })}
      />
    )
  },
  {
    id: 'storageExplorer',
    title: 'Storage Explorer',
    subtitle: 'View storage',
    category: 'Web Dev',
    icon: faGear,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data) => (
      <StorageExplorerTool
        data={data as StorageExplorerData | undefined}
        onRefresh={handlers.refreshStorageExplorer}
      />
    )
  },
  {
    id: 'snippetRunner',
    title: 'Console Snippet Runner',
    subtitle: 'Run snippets',
    category: 'Web Dev',
    icon: faCode,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <SnippetRunnerTool
        data={data as SnippetRunnerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'lighthouseSnapshot',
    title: 'Lighthouse Snapshot',
    subtitle: 'Perf metrics',
    category: 'Web Dev',
    icon: faBolt,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <LighthouseSnapshotTool
        data={data as LighthouseSnapshotData | undefined}
        onCapture={() => {
          const timing = performance.timing;
          const paint = performance.getEntriesByType('paint');
          const metrics = [
            { label: 'TTFB', value: `${timing.responseStart - timing.requestStart} ms` },
            { label: 'DOMContentLoaded', value: `${timing.domContentLoadedEventEnd - timing.navigationStart} ms` },
            { label: 'Load', value: `${timing.loadEventEnd - timing.navigationStart} ms` }
          ];
          const firstPaint = paint.find((entry) => entry.name === 'first-contentful-paint');
          if (firstPaint) {
            metrics.push({ label: 'FCP', value: `${Math.round(firstPaint.startTime)} ms` });
          }
          onChange({ metrics });
        }}
      />
    )
  },
  {
    id: 'cssGridGenerator',
    title: 'CSS Grid Generator',
    subtitle: 'Grid CSS',
    category: 'Front End',
    icon: faTable,
    hover: 'group-hover:border-blue-500 group-hover:text-blue-400',
    render: (data, onChange) => (
      <CssGridGeneratorTool
        data={data as CssGridGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'flexboxInspector',
    title: 'Flexbox Inspector',
    subtitle: 'Inspect flex',
    category: 'Front End',
    icon: faSliders,
    hover: 'group-hover:border-blue-500 group-hover:text-blue-400',
    render: (data, onChange) => (
      <FlexboxInspectorTool
        data={data as FlexboxInspectorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'fontIdentifier',
    title: 'Font Identifier',
    subtitle: 'Font details',
    category: 'Front End',
    icon: faFont,
    hover: 'group-hover:border-blue-500 group-hover:text-blue-400',
    render: (data, onChange) => (
      <FontIdentifierTool
        data={data as FontIdentifierData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'contrastChecker',
    title: 'Contrast Checker',
    subtitle: 'WCAG ratio',
    category: 'Front End',
    icon: faEyeDropper,
    hover: 'group-hover:border-blue-500 group-hover:text-blue-400',
    render: (data, onChange) => (
      <ContrastCheckerTool
        data={data as ContrastCheckerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'responsivePreview',
    title: 'Responsive Preview',
    subtitle: 'Viewport size',
    category: 'Front End',
    icon: faExpand,
    hover: 'group-hover:border-blue-500 group-hover:text-blue-400',
    render: (data, onChange) => (
      <ResponsivePreviewTool
        data={data as ResponsivePreviewData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'animationPreview',
    title: 'Animation Preview',
    subtitle: 'Preview motion',
    category: 'Front End',
    icon: faWaveSquare,
    hover: 'group-hover:border-blue-500 group-hover:text-blue-400',
    render: (data, onChange) => (
      <AnimationPreviewTool
        data={data as AnimationPreviewData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'svgOptimizer',
    title: 'SVG Optimizer',
    subtitle: 'Minify SVG',
    category: 'Front End',
    icon: faFileCode,
    hover: 'group-hover:border-blue-500 group-hover:text-blue-400',
    render: (data, onChange) => (
      <SvgOptimizerTool
        data={data as SvgOptimizerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'accessibilityAudit',
    title: 'Accessibility Audit',
    subtitle: 'Basic checks',
    category: 'Front End',
    icon: faShieldHalved,
    hover: 'group-hover:border-blue-500 group-hover:text-blue-400',
    render: (data, onChange) => (
      <AccessibilityAuditTool
        data={data as AccessibilityAuditData | undefined}
        onRun={() => onChange({ issues: auditAccessibility(document) })}
      />
    )
  },
  {
    id: 'jwtDebugger',
    title: 'JWT Debugger',
    subtitle: 'Decode JWT',
    category: 'Back End',
    icon: faCode,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <JwtDebuggerTool
        data={data as JwtDebuggerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'regexTester',
    title: 'Regex Tester',
    subtitle: 'Test patterns',
    category: 'Back End',
    icon: faWaveSquare,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <RegexTesterTool
        data={data as RegexTesterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'apiResponseViewer',
    title: 'API Response Viewer',
    subtitle: 'Inspect API',
    category: 'Back End',
    icon: faGlobe,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <ApiResponseViewerTool
        data={data as ApiResponseViewerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'graphqlExplorer',
    title: 'GraphQL Explorer',
    subtitle: 'Run queries',
    category: 'Back End',
    icon: faCode,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <GraphqlExplorerTool
        data={data as GraphqlExplorerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'restClient',
    title: 'REST Client',
    subtitle: 'Send requests',
    category: 'Back End',
    icon: faNetworkWired,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <RestClientTool
        data={data as RestClientData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'oauthTokenInspector',
    title: 'OAuth Token Inspector',
    subtitle: 'Inspect token',
    category: 'Back End',
    icon: faFingerprint,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <OAuthTokenInspectorTool
        data={data as OAuthTokenInspectorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'webhookTester',
    title: 'Webhook Tester',
    subtitle: 'Ping webhook',
    category: 'Back End',
    icon: faWaveSquare,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <WebhookTesterTool
        data={data as WebhookTesterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'cookieManager',
    title: 'Cookie Manager',
    subtitle: 'Edit cookies',
    category: 'Back End',
    icon: faGear,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <CookieManagerTool
        data={data as CookieManagerData | undefined}
        onChange={onChange}
        onRefresh={handlers.refreshCookies}
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
  const [quickBarSearch, setQuickBarSearch] = useState('');
  const [quickBarPage, setQuickBarPage] = useState(1);
  const [quickBarDragId, setQuickBarDragId] = useState<string | null>(null);
  const [quickBarDragOverIndex, setQuickBarDragOverIndex] = useState<number | null>(
    null
  );
  const [quickBarDragOverPage, setQuickBarDragOverPage] = useState<number | null>(
    null
  );
  const menuBarRef = useRef<HTMLDivElement | null>(null);
  const spotlightInputRef = useRef<HTMLInputElement | null>(null);
  const requestLogSeenRef = useRef<Set<string>>(new Set());
  const debuggerSeenRef = useRef<number>(0);
  const quickBarDragIdRef = useRef<string | null>(null);
  const quickBarPageHoverRef = useRef<number | null>(null);
  const quickBarListRef = useRef<HTMLDivElement | null>(null);
  const quickBarPageRef = useRef(quickBarPage);
  const quickBarDragOverIndexRef = useRef<number | null>(quickBarDragOverIndex);
  const quickBarDragOverPageRef = useRef<number | null>(quickBarDragOverPage);
  const pagedQuickBarToolsRef = useRef(0);
  const linkPreviewHostRef = useRef<{
    host: HTMLDivElement;
    wrapper: HTMLDivElement;
    frame: HTMLIFrameElement;
    title: HTMLDivElement;
  } | null>(null);
  const linkPreviewAnchorRef = useRef<HTMLAnchorElement | null>(null);
  const linkPreviewTimeoutRef = useRef<number | null>(null);
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
    const isOpen = state.toolWindows.debuggerTool?.isOpen;
    if (!isOpen) return;

    const addEntry = (message: string, source: string) => {
      updateState((current) => {
        const existing =
          (current.toolData.debuggerTool as DebuggerData | undefined)?.entries ?? [];
        const next = [
          { message, source, time: Date.now() },
          ...existing
        ].slice(0, 100);
        return {
          ...current,
          toolData: {
            ...current.toolData,
            debuggerTool: { entries: next }
          }
        };
      }).then(setState);
    };

    const handleError = (event: ErrorEvent) => {
      addEntry(event.message, 'error');
    };
    const handleRejection = (event: PromiseRejectionEvent) => {
      addEntry(
        event.reason instanceof Error ? event.reason.message : String(event.reason),
        'unhandledrejection'
      );
    };

    window.addEventListener('error', handleError);
    window.addEventListener('unhandledrejection', handleRejection);
    return () => {
      window.removeEventListener('error', handleError);
      window.removeEventListener('unhandledrejection', handleRejection);
    };
  }, [state.toolWindows.debuggerTool?.isOpen]);

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
      case 'Back End':
        return 'bg-amber-500/10 text-amber-300 border-amber-500/30';
      case 'CyberSec':
        return 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30';
      default:
        return 'bg-slate-500/10 text-slate-300 border-slate-500/30';
    }
  };

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

  const updateQuickBarOrder = async (fromIndex: number, toIndex: number) => {
    const next = await updateState((current) => ({
      ...current,
      quickBarToolIds: moveItem(current.quickBarToolIds, fromIndex, toIndex)
    }));
    setState(next);
  };

  const setQuickBarDragOver = (page: number, index: number) => {
    setQuickBarDragOverPage(page);
    setQuickBarDragOverIndex(index);
    quickBarDragOverPageRef.current = page;
    quickBarDragOverIndexRef.current = index;
  };

  const clearQuickBarDragState = () => {
    setQuickBarDragId(null);
    quickBarDragIdRef.current = null;
    setQuickBarDragOverIndex(null);
    setQuickBarDragOverPage(null);
    if (quickBarPageHoverRef.current) {
      window.clearTimeout(quickBarPageHoverRef.current);
      quickBarPageHoverRef.current = null;
    }
  };

  const refreshStorageExplorer = async () => {
    const local = Object.keys(localStorage).map((key) => ({
      key,
      value: localStorage.getItem(key) ?? ''
    }));
    const session = Object.keys(sessionStorage).map((key) => ({
      key,
      value: sessionStorage.getItem(key) ?? ''
    }));
    const next = await updateState((current) => ({
      ...current,
      toolData: {
        ...current.toolData,
        storageExplorer: { local, session }
      }
    }));
    setState(next);
  };

  const refreshCookies = async () => {
    const cookies = parseCookieString(document.cookie);
    const next = await updateState((current) => ({
      ...current,
      toolData: {
        ...current.toolData,
        cookieManager: { ...((current.toolData.cookieManager as CookieManagerData) ?? {}), cookies }
      }
    }));
    setState(next);
  };

  const toolRegistry = useMemo(
    () =>
      buildToolRegistry({
        refreshStorageExplorer,
        refreshCookies
      }),
    [refreshStorageExplorer, refreshCookies]
  );

  const getToolEntry = (toolId: string) =>
    toolRegistry.find((tool) => tool.id === toolId) ?? null;

  const quickBarTools = useMemo(
    () =>
      state.quickBarToolIds
        .map((toolId) => getToolEntry(toolId))
        .filter((entry): entry is ToolRegistryEntry => Boolean(entry)),
    [state.quickBarToolIds, toolRegistry]
  );

  const quickBarPageSize = 6;
  const filteredQuickBarTools = useMemo(() => {
    const query = quickBarSearch.trim().toLowerCase();
    if (!query) return quickBarTools;
    return quickBarTools.filter((tool) => {
      const title = tool.title.toLowerCase();
      const subtitle = tool.subtitle.toLowerCase();
      return title.includes(query) || subtitle.includes(query);
    });
  }, [quickBarSearch, quickBarTools]);
  const quickBarTotalPages = Math.max(
    1,
    Math.ceil(filteredQuickBarTools.length / quickBarPageSize)
  );
  const quickBarDragEnabled = quickBarSearch.trim().length === 0;
  const pagedQuickBarTools = useMemo(() => {
    const start = (quickBarPage - 1) * quickBarPageSize;
    return filteredQuickBarTools.slice(start, start + quickBarPageSize);
  }, [filteredQuickBarTools, quickBarPage]);
  useEffect(() => {
    quickBarPageRef.current = quickBarPage;
  }, [quickBarPage]);
  useEffect(() => {
    quickBarDragOverIndexRef.current = quickBarDragOverIndex;
  }, [quickBarDragOverIndex]);
  useEffect(() => {
    quickBarDragOverPageRef.current = quickBarDragOverPage;
  }, [quickBarDragOverPage]);
  useEffect(() => {
    pagedQuickBarToolsRef.current = pagedQuickBarTools.length;
  }, [pagedQuickBarTools.length]);

  useEffect(() => {
    setQuickBarPage(1);
  }, [quickBarSearch, state.quickBarToolIds.length]);

  useEffect(() => {
    if (quickBarPage > quickBarTotalPages) {
      setQuickBarPage(quickBarTotalPages);
    }
  }, [quickBarPage, quickBarTotalPages]);

  const handleQuickBarPageHover = (page: number) => {
    if (!quickBarDragIdRef.current && !quickBarDragId) return;
    if (quickBarPageHoverRef.current) {
      window.clearTimeout(quickBarPageHoverRef.current);
    }
    quickBarPageHoverRef.current = window.setTimeout(() => {
      setQuickBarPage(page);
      setQuickBarDragOverPage(page);
      quickBarDragOverPageRef.current = page;
    }, 500);
  };

  const clearQuickBarPageHover = () => {
    if (quickBarPageHoverRef.current) {
      window.clearTimeout(quickBarPageHoverRef.current);
      quickBarPageHoverRef.current = null;
    }
  };

  const searchableTools = useMemo(
    () =>
      toolRegistry.map((tool) => ({
        id: tool.id,
        label: tool.title,
        subtitle: tool.subtitle
      })),
    [toolRegistry]
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

  useEffect(() => {
    const isActive = Boolean(
      (state.toolData.liveLinkPreview as LiveLinkPreviewData | undefined)?.isActive
    );
    if (!isActive) {
      if (linkPreviewTimeoutRef.current) {
        window.clearTimeout(linkPreviewTimeoutRef.current);
        linkPreviewTimeoutRef.current = null;
      }
      if (linkPreviewHostRef.current) {
        linkPreviewHostRef.current.host.remove();
        linkPreviewHostRef.current = null;
      }
      linkPreviewAnchorRef.current = null;
      return;
    }

    const hidePreview = () => {
      if (linkPreviewTimeoutRef.current) {
        window.clearTimeout(linkPreviewTimeoutRef.current);
        linkPreviewTimeoutRef.current = null;
      }
      if (linkPreviewHostRef.current) {
        linkPreviewHostRef.current.host.remove();
        linkPreviewHostRef.current = null;
      }
      linkPreviewAnchorRef.current = null;
    };

    const showPreview = (anchor: HTMLAnchorElement) => {
      const href = anchor.getAttribute('href') ?? '';
      if (!href || !isValidPreviewUrl(anchor.href)) return;
      if (!linkPreviewHostRef.current) {
        linkPreviewHostRef.current = createPreviewHost();
      }
      const { wrapper, frame, title } = linkPreviewHostRef.current;
      frame.src = anchor.href;
      title.textContent = anchor.href;
      const rect = anchor.getBoundingClientRect();
      const width = PREVIEW_WIDTH * PREVIEW_SCALE;
      const height = PREVIEW_HEIGHT * PREVIEW_SCALE;
      const fitsBelow = rect.bottom + height + PREVIEW_MARGIN < window.innerHeight;
      const top = fitsBelow
        ? rect.bottom + PREVIEW_MARGIN
        : Math.max(PREVIEW_MARGIN, rect.top - height - PREVIEW_MARGIN);
      const left = Math.min(
        Math.max(PREVIEW_MARGIN, rect.left),
        window.innerWidth - width - PREVIEW_MARGIN
      );
      wrapper.style.top = `${top}px`;
      wrapper.style.left = `${left}px`;
    };

    const handleMouseOver = (event: MouseEvent) => {
      const target = event.target as HTMLElement | null;
      if (!target) return;
      const host = document.getElementById(ROOT_ID);
      if (host && host.contains(target)) return;
      const anchor = target.closest('a') as HTMLAnchorElement | null;
      if (!anchor || !anchor.href) return;
      if (linkPreviewAnchorRef.current === anchor) return;
      linkPreviewAnchorRef.current = anchor;
      if (linkPreviewTimeoutRef.current) {
        window.clearTimeout(linkPreviewTimeoutRef.current);
      }
      linkPreviewTimeoutRef.current = window.setTimeout(() => {
        showPreview(anchor);
      }, 500);
    };

    const handleMouseOut = (event: MouseEvent) => {
      const target = event.target as HTMLElement | null;
      if (!target) return;
      const anchor = target.closest('a') as HTMLAnchorElement | null;
      if (!anchor || anchor !== linkPreviewAnchorRef.current) return;
      hidePreview();
    };

    document.addEventListener('mouseover', handleMouseOver);
    document.addEventListener('mouseout', handleMouseOut);
    return () => {
      document.removeEventListener('mouseover', handleMouseOver);
      document.removeEventListener('mouseout', handleMouseOut);
      hidePreview();
    };
  }, [state.toolData.liveLinkPreview]);

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
  const quickBarPageStart = (quickBarPage - 1) * quickBarPageSize;

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

        <div className="px-2 pb-1 pt-2">
          <div className="relative">
            <FontAwesomeIcon
              icon={faSearch}
              className={`absolute left-2 top-1/2 -translate-y-1/2 text-slate-500 ${iconSizeClass}`}
            />
            <input
              type="text"
              value={quickBarSearch}
              onChange={(event) => setQuickBarSearch(event.target.value)}
              className="w-full rounded bg-slate-800 text-slate-300 text-xs pl-7 pr-2 py-1.5 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors placeholder-slate-500"
              placeholder="Search favorites..."
            />
          </div>
          <div className="flex items-center justify-between text-[10px] text-slate-500 mt-2 px-1">
            <span>
              {filteredQuickBarTools.length === 0
                ? '0 results'
                : `${filteredQuickBarTools.length} results`}
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setQuickBarPage((prev) => Math.max(1, prev - 1))}
                disabled={quickBarPage === 1}
                className="rounded px-2 py-1 border border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500 transition-colors disabled:opacity-50"
              >
                Prev
              </button>
              <div className="flex items-center gap-1">
                {Array.from({ length: quickBarTotalPages }, (_, index) => {
                  const page = index + 1;
                  const isActive = page === quickBarPage;
                  return (
                    <button
                      key={page}
                      type="button"
                      data-quickbar-page-target={page}
                      onClick={() => setQuickBarPage(page)}
                      onPointerEnter={() => handleQuickBarPageHover(page)}
                      onPointerOver={() => handleQuickBarPageHover(page)}
                      onPointerLeave={clearQuickBarPageHover}
                      onPointerOut={clearQuickBarPageHover}
                      className={`h-6 w-6 rounded border text-[10px] transition-colors ${
                        isActive
                          ? 'border-blue-500/50 text-blue-200 bg-blue-500/10'
                          : 'border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500'
                      }`}
                    >
                      {page}
                    </button>
                  );
                })}
              </div>
              <span className="text-slate-500">
                {quickBarPage} / {quickBarTotalPages}
              </span>
              <button
                type="button"
                onClick={() =>
                  setQuickBarPage((prev) =>
                    Math.min(quickBarTotalPages, prev + 1)
                  )
                }
                disabled={quickBarPage === quickBarTotalPages}
                className="rounded px-2 py-1 border border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500 transition-colors disabled:opacity-50"
              >
                Next
              </button>
            </div>
          </div>
        </div>
        <div
          ref={quickBarListRef}
          className={`flex-1 overflow-y-auto no-scrollbar p-1 space-y-1 ${
            quickBarDragId ? 'select-none cursor-grabbing' : ''
          }`}
        >
          {quickBarTools.length === 0 ? (
            <div className="px-3 py-4 text-[11px] text-slate-500">
              No favorites yet. Open a tool and press + to pin it here.
            </div>
          ) : filteredQuickBarTools.length === 0 ? (
            <div className="px-3 py-4 text-[11px] text-slate-500">
              No matches found.
            </div>
          ) : (
            <>
              {pagedQuickBarTools.map((item, index) => {
                const isDragging = quickBarDragId === item.id;
                const showDropIndicator =
                  quickBarDragId &&
                  quickBarDragOverPage === quickBarPage &&
                  quickBarDragOverIndex === index;
                return (
                  <React.Fragment key={item.id}>
                    <button
                      type="button"
                      data-quickbar-id={item.id}
                      data-quickbar-index={index}
                      data-quickbar-page={quickBarPage}
                      onPointerDown={(event) => {
                        if (!quickBarDragEnabled) return;
                        event.preventDefault();
                        setQuickBarDragId(item.id);
                        quickBarDragIdRef.current = item.id;
                        setQuickBarDragOver(quickBarPage, index);
                        const handleMove = (moveEvent: PointerEvent) => {
                          const dragId =
                            quickBarDragIdRef.current ?? quickBarDragId;
                          if (!dragId || !quickBarDragEnabled) return;
                          const listEl = quickBarListRef.current;
                          let handled = false;
                          if (listEl) {
                            const rect = listEl.getBoundingClientRect();
                            const delta = getAutoScrollDelta({
                              clientY: moveEvent.clientY,
                              rectTop: rect.top,
                              rectBottom: rect.bottom,
                              threshold: 32,
                              speed: 8
                            });
                            if (delta !== 0) {
                              listEl.scrollTop += delta;
                            }
                          }
                          const path =
                            typeof moveEvent.composedPath === 'function'
                              ? moveEvent.composedPath()
                              : [];
                          const pathMatch = path.find(
                            (entry) =>
                              entry instanceof HTMLElement &&
                              entry.dataset?.quickbarIndex
                          ) as HTMLElement | undefined;
                          const targetMatch =
                            moveEvent.target instanceof HTMLElement
                              ? (moveEvent.target.closest(
                                  '[data-quickbar-index]'
                                ) as HTMLElement | null)
                              : null;
                          const pointMatch = document
                            .elementFromPoint(moveEvent.clientX, moveEvent.clientY)
                            ?.closest('[data-quickbar-index]') as HTMLElement | null;
                          const itemEl = pathMatch ?? targetMatch ?? pointMatch ?? undefined;
                          if (itemEl) {
                            const nextIndex = Number(itemEl.dataset.quickbarIndex);
                            const nextPage = Number(itemEl.dataset.quickbarPage);
                            if (!Number.isNaN(nextIndex) && !Number.isNaN(nextPage)) {
                              handled = true;
                              if (
                                quickBarDragOverPageRef.current !== nextPage ||
                                quickBarDragOverIndexRef.current !== nextIndex
                              ) {
                                setQuickBarDragOver(nextPage, nextIndex);
                              }
                            }
                          }
                          if (!handled && listEl) {
                            const items = listEl.querySelectorAll<HTMLElement>(
                              '[data-quickbar-index]'
                            );
                            const lastItem = items[items.length - 1];
                            if (lastItem) {
                              const lastRect = lastItem.getBoundingClientRect();
                              if (moveEvent.clientY > lastRect.bottom) {
                                const endIndex = pagedQuickBarToolsRef.current;
                                if (
                                  quickBarDragOverPageRef.current !==
                                    quickBarPageRef.current ||
                                  quickBarDragOverIndexRef.current !== endIndex
                                ) {
                                  setQuickBarDragOver(
                                    quickBarPageRef.current,
                                    endIndex
                                  );
                                }
                              }
                            }
                          }
                        };
                        const handleUp = async (upEvent: PointerEvent) => {
                          window.removeEventListener('pointermove', handleMove);
                          window.removeEventListener('pointerup', handleUp);
                          const dragId =
                            quickBarDragIdRef.current ?? quickBarDragId;
                          if (!dragId) {
                            clearQuickBarDragState();
                            return;
                          }
                          const fromIndex = state.quickBarToolIds.indexOf(dragId);
                          const resolveTarget = () => {
                            const targetEl =
                              upEvent.target instanceof HTMLElement
                                ? (upEvent.target.closest(
                                    '[data-quickbar-index]'
                                  ) as HTMLElement | null)
                                : null;
                            const pointEl = document
                              .elementFromPoint(upEvent.clientX, upEvent.clientY)
                              ?.closest('[data-quickbar-index]') as HTMLElement | null;
                            const element = targetEl ?? pointEl;
                            if (!element) return null;
                            const nextIndex = Number(element.dataset.quickbarIndex);
                            const nextPage = Number(element.dataset.quickbarPage);
                            if (Number.isNaN(nextIndex) || Number.isNaN(nextPage)) {
                              return null;
                            }
                            return { nextIndex, nextPage };
                          };
                          const resolved = resolveTarget();
                          const targetPage =
                            resolved?.nextPage ??
                            quickBarDragOverPageRef.current ??
                            quickBarPageRef.current;
                          const targetIndex =
                            resolved?.nextIndex ??
                            quickBarDragOverIndexRef.current ??
                            0;
                          const toIndex =
                            (targetPage - 1) * quickBarPageSize + targetIndex;
                          if (fromIndex >= 0 && toIndex >= 0) {
                            await updateQuickBarOrder(fromIndex, toIndex);
                          }
                          clearQuickBarDragState();
                        };
                        window.addEventListener('pointermove', handleMove);
                        window.addEventListener('pointerup', handleUp, { once: true });
                      }}
                      onClick={() => {
                        if (quickBarDragIdRef.current || quickBarDragId) return;
                        openTool(item.id);
                      }}
                      className={`relative w-full flex items-center gap-3 p-2 rounded hover:bg-slate-800 transition-all text-left group ${
                        isDragging
                          ? 'opacity-40 pointer-events-none'
                          : 'transition-transform duration-150 ease-out will-change-transform'
                      }`}
                    >
                      <span
                        aria-hidden="true"
                        className={`pointer-events-none absolute inset-0 rounded border border-blue-500/40 bg-blue-500/5 transition-opacity duration-150 ${
                          showDropIndicator ? 'opacity-100' : 'opacity-0'
                        }`}
                      />
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
                  </React.Fragment>
                );
              })}
              {quickBarDragId &&
              quickBarDragOverPage === quickBarPage &&
              quickBarDragOverIndex === pagedQuickBarTools.length ? (
                <div className="h-12 rounded border border-dashed border-blue-500/40 bg-blue-500/5" />
              ) : null}
            </>
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
