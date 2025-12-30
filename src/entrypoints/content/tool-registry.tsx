import type { ReactNode } from 'react';
import {
  faBolt,
  faBug,
  faCode,
  faCompress,
  faExpand,
  faEyeDropper,
  faFileCode,
  faFingerprint,
  faFlask,
  faFont,
  faGear,
  faGlobe,
  faLink,
  faNetworkWired,
  faRobot,
  faShieldHalved,
  faSitemap,
  faSliders,
  faTable,
  faWaveSquare
} from '@fortawesome/free-solid-svg-icons';
import {
  AccessibilityAuditTool,
  AnimationPreviewTool,
  ApiResponseViewerTool,
  AssetMapperTool,
  BsonViewerTool,
  CodeInjectorTool,
  ColorPickerTool,
  ContrastCheckerTool,
  CookieManagerTool,
  CorsCheckTool,
  CouchDbDocExplorerTool,
  CssGridGeneratorTool,
  DebuggerTool,
  DomSnapshotTool,
  DynamoDbConverterTool,
  FirebaseRulesLinterTool,
  FlexboxInspectorTool,
  FontIdentifierTool,
  FormFuzzerTool,
  GraphqlExplorerTool,
  HeaderInspectorTool,
  IndexAdvisorTool,
  JsonDiffTool,
  JsonMinifierTool,
  JsonPathTesterTool,
  JsonPrettifierTool,
  JsonSchemaValidatorTool,
  JwtDebuggerTool,
  LighthouseSnapshotTool,
  LinkExtractorTool,
  LiveLinkPreviewTool,
  MongoQueryBuilderTool,
  OAuthTokenInspectorTool,
  ParamAnalyzerTool,
  PayloadReplayTool,
  RegexTesterTool,
  RequestLogTool,
  ResponsivePreviewTool,
  RestClientTool,
  RobotsViewerTool,
  SnippetRunnerTool,
  SqlFormatterTool,
  SqlQueryBuilderTool,
  SqlToCsvTool,
  StorageExplorerTool,
  SvgOptimizerTool,
  TechFingerprintTool,
  UrlCodecTool,
  WebhookTesterTool
} from './Tools';
import type {
  AccessibilityAuditData,
  AnimationPreviewData,
  ApiResponseViewerData,
  AssetMapperData,
  BsonViewerData,
  CodeInjectorData,
  ContrastCheckerData,
  CookieManagerData,
  CorsCheckData,
  CouchDbDocExplorerData,
  CssGridGeneratorData,
  DebuggerData,
  DomSnapshotData,
  DynamoDbConverterData,
  FirebaseRulesLinterData,
  FlexboxInspectorData,
  FontIdentifierData,
  FormFuzzerData,
  GraphqlExplorerData,
  HeaderInspectorData,
  IndexAdvisorData,
  JsonDiffData,
  JsonMinifierData,
  JsonPathTesterData,
  JsonPrettifierData,
  JsonSchemaValidatorData,
  JwtDebuggerData,
  LighthouseSnapshotData,
  LinkExtractorData,
  LiveLinkPreviewData,
  MongoQueryBuilderData,
  OAuthTokenInspectorData,
  ParamAnalyzerData,
  PayloadReplayData,
  RegexTesterData,
  RequestLogData,
  ResponsivePreviewData,
  RestClientData,
  RobotsViewerData,
  SnippetRunnerData,
  SqlFormatterData,
  SqlQueryBuilderData,
  SqlToCsvData,
  StorageExplorerData,
  SvgOptimizerData,
  TechFingerprintData,
  UrlCodecData,
  WebhookTesterData
} from './Tools/tool-types';
import {
  applyPayloadToForm,
  auditAccessibility,
  defaultPayloads,
  detectTechnologies,
  extractLinksFromDocument,
  getFormsSnapshot,
  mapAssetsFromDocument,
  parseQueryParams,
  sanitizeHtmlSnapshot
} from './Tools/helpers';

export const TOOL_DEFAULT_POSITION = { x: 80, y: 140 };

export type ToolRegistryEntry = {
  id: string;
  title: string;
  subtitle: string;
  category: string;
  icon: typeof faBolt;
  hover: string;
  render: (
    data: unknown,
    onChange: (next: unknown) => void
  ) => ReactNode;
};

export const buildToolRegistry = (handlers: {
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
      <CodeInjectorTool.Component
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
      <LiveLinkPreviewTool.Component
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
      <HeaderInspectorTool.Component
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
      <TechFingerprintTool.Component
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
      <RobotsViewerTool.Component
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
      <FormFuzzerTool.Component
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
      <UrlCodecTool.Component data={data as UrlCodecData | undefined} onChange={onChange} />
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
      <ParamAnalyzerTool.Component
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
      <LinkExtractorTool.Component
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
      <DomSnapshotTool.Component
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
      <AssetMapperTool.Component
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
      <RequestLogTool.Component
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
      <PayloadReplayTool.Component
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
      <CorsCheckTool.Component
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
      <JsonMinifierTool.Component
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
      <JsonPrettifierTool.Component
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
      <JsonSchemaValidatorTool.Component
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
      <JsonPathTesterTool.Component
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
      <JsonDiffTool.Component
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
      <SqlFormatterTool.Component
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
      <SqlQueryBuilderTool.Component
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
      <SqlToCsvTool.Component
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
      <IndexAdvisorTool.Component
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
      <BsonViewerTool.Component
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
      <MongoQueryBuilderTool.Component
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
      <DynamoDbConverterTool.Component
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
      <FirebaseRulesLinterTool.Component
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
      <CouchDbDocExplorerTool.Component
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
      <DebuggerTool.Component
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
      <StorageExplorerTool.Component
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
      <SnippetRunnerTool.Component
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
      <LighthouseSnapshotTool.Component
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
      <CssGridGeneratorTool.Component
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
      <FlexboxInspectorTool.Component
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
      <FontIdentifierTool.Component
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
      <ContrastCheckerTool.Component
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
      <ResponsivePreviewTool.Component
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
      <AnimationPreviewTool.Component
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
      <SvgOptimizerTool.Component
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
      <AccessibilityAuditTool.Component
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
      <JwtDebuggerTool.Component
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
      <RegexTesterTool.Component
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
      <ApiResponseViewerTool.Component
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
      <GraphqlExplorerTool.Component
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
      <RestClientTool.Component
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
      <OAuthTokenInspectorTool.Component
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
      <WebhookTesterTool.Component
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
      <CookieManagerTool.Component
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
      <ColorPickerTool.Component
        data={data as { color?: string } | undefined}
        onChange={(next) => onChange(next)}
      />
    )
  }
];
