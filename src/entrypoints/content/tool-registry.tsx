import React, { type ReactNode } from 'react';
import {
  faBolt,
  faBug,
  faCode,
  faCompress,
  faDiagramProject,
  faEnvelope,
  faExpand,
  faEyeDropper,
  faFileCode,
  faFingerprint,
  faFlask,
  faFont,
  faGear,
  faGlobe,
  faLink,
  faLock,
  faMagnifyingGlass,
  faNetworkWired,
  faSquare,
  faCircle,
  faRobot,
  faSearch,
  faServer,
  faShieldHalved,
  faSitemap,
  faSliders,
  faTable,
  faUser,
  faWaveSquare,
  faImage,
  faClockRotateLeft,
  faStar,
  faArrowsRotate,
  faFileLines,
  faKeyboard,
  faRuler,
  faCompress,
  faPalette,
  faPuzzlePiece,
  faKey,
  faLanguage,
  faFileExcel,
  faTextHeight,
  faCalculator,
  faListOl,
  faShuffle,
  faCodeCompare,
  faFileAlt,
  faFileExport,
  faMask,
  faMemory,
  faIcons,
  faHighlighter,
  faShieldAlt,
  faClock,
  faGlobeAmericas,
  faExchangeAlt,
  faRulerCombined,
  faFingerprint as faUuid,
  faDatabase,
  faCodeBranch,
  faFileAlt,
  faBalanceScale,
  faCompress,
  faPalette,
  faFileCode,
  faCode as faTypescript,
  faCubes,
  faTable,
  faTerminal,
  faQrcode,
  faBarcode,
  faStopwatch,
  faClock as faPomodoro,
  faStickyNote,
  faListCheck,
  faCalculator as faMathCalc,
  faEye,
  faTableCells,
  faSquare as faClickjack,
  faHashtag,
  faFolder
} from '@fortawesome/free-solid-svg-icons';
import {
  AccessibilityAuditTool,
  AnimationPreviewTool,
  ApiResponseViewerTool,
  Base64AdvancedTool,
  AssetMapperTool,
  BsonViewerTool,
  CodeInjectorTool,
  ColorPickerTool,
  ContrastCheckerTool,
  CookieManagerTool,
  CorsCheckTool,
  CouchDbDocExplorerTool,
  CspBuilderTool,
  CssGridGeneratorTool,
  DebuggerTool,
  DnsRecordViewerTool,
  DomSnapshotTool,
  DynamoDbConverterTool,
  EmailBreachCheckerTool,
  ExifMetadataViewerTool,
  parseExif,
  FirebaseRulesLinterTool,
  FlexboxInspectorTool,
  FontIdentifierTool,
  FormFuzzerTool,
  GoogleDorkGeneratorTool,
  GraphqlExplorerTool,
  HashesGeneratorTool,
  HeaderInspectorTool,
  HmacGeneratorTool,
  HtmlEntityEncoderTool,
  PasswordStrengthTool,
  PasswordGeneratorTool,
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
  ReverseIpLookupTool,
  RobotsViewerTool,
  SqlFormatterTool,
  SqlQueryBuilderTool,
  SqlToCsvTool,
  SriGeneratorTool,
  SslCertDecoderTool,
  StorageExplorerTool,
  SubdomainFinderTool,
  SvgOptimizerTool,
  TechFingerprintTool,
  UrlCodecTool,
  UsernameSearchTool,
  WaybackMachineViewerTool,
  WebhookTesterTool,
  WhoisLookupTool,
  XssPayloadTool,
  SqliPayloadTool,
  UserAgentTool,
  JwtCrackerTool,
  PemDerConverterTool,
  WebSocketTesterTool,
  MetadataScrubberTool,
  CidrCalculatorTool,
  SubnetCheatSheetTool,
  MacVendorLookupTool,
  PortReferenceTool,
  HttpStatusReferenceTool,
  CronGeneratorTool,
  ChmodCalculatorTool,
  DockerfileLinterTool,
  YamlValidatorTool,
  NginxConfigGeneratorTool,
  HtaccessGeneratorTool,
  MetaTagGeneratorTool,
  OpenGraphPreviewerTool,
  BoxShadowGeneratorTool,
  BorderRadiusGeneratorTool,
  FaviconGeneratorTool,
  CssGradientGeneratorTool,
  CssFilterGeneratorTool,
  CssTransformGeneratorTool,
  HtmlTableGeneratorTool,
  MarkdownToHtmlTool,
  HtmlToMarkdownTool,
  LoremIpsumGeneratorTool,
  PlaceholderImageTool,
  Base64ImageConverterTool,
  KeycodeInfoTool,
  ClampCalculatorTool,
  ImageCompressorTool,
  ColorPaletteExtractorTool,
  ManifestValidatorTool,
  PermissionsReferenceTool,
  I18nHelperTool,
  CsvToJsonTool,
  CaseConverterTool,
  TextStatisticsTool,
  LineSorterTool,
  ListRandomizerTool,
  TextDiffTool,
  XmlToJsonTool,
  YamlToJsonTool,
  JsonToYamlTool,
  StringObfuscatorTool,
  TextToBinaryTool,
  HexViewerTool,
  UnicodeExplorerTool,
  RegexHighlighterTool,
  EscapingTool,
  UnixTimestampTool,
  TimezoneConverterTool,
  UnitConverterTool,
  AspectRatioCalculatorTool,
  UuidGeneratorTool,
  ObjectIdGeneratorTool,
  GitCommandBuilderTool,
  GitIgnoreGeneratorTool,
  LicenseGeneratorTool,
  JsMinifierTool,
  CssMinifierTool,
  PythonToJsonTool,
  TypescriptInterfaceGenTool,
  GoStructGeneratorTool,
  SqlSchemaGeneratorTool,
  CurlToFetchTool,
  QrCodeGeneratorTool,
  BarcodeGeneratorTool,
  StopwatchTimerTool,
  PomodoroTimerTool,
  ScratchpadTool,
  TodoListTool,
  MathEvaluatorTool,
  ColorBlindnessSimulatorTool,
  VisualGridBuilderTool,
  ClickjackingTesterTool,
  IdorIteratorTool,
  DirectoryBusterTool
} from './Tools';
import type {
  AccessibilityAuditData,
  AnimationPreviewData,
  ApiResponseViewerData,
  Base64AdvancedData,
  AssetMapperData,
  BsonViewerData,
  CodeInjectorData,
  ContrastCheckerData,
  CookieManagerData,
  CorsCheckData,
  CouchDbDocExplorerData,
  CspBuilderData,
  CssGridGeneratorData,
  DebuggerData,
  DnsRecordViewerData,
  DomSnapshotData,
  DynamoDbConverterData,
  EmailBreachCheckerData,
  ExifMetadataViewerData,
  FirebaseRulesLinterData,
  FlexboxInspectorData,
  FontIdentifierData,
  FormFuzzerData,
  GoogleDorkGeneratorData,
  GraphqlExplorerData,
  HashesGeneratorData,
  HeaderInspectorData,
  HmacGeneratorData,
  HtmlEntityEncoderData,
  PasswordStrengthData,
  PasswordGeneratorData,
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
  ReverseIpLookupData,
  RobotsViewerData,
  SqlFormatterData,
  SqlQueryBuilderData,
  SqlToCsvData,
  SriGeneratorData,
  SslCertDecoderData,
  StorageExplorerData,
  SubdomainFinderData,
  SvgOptimizerData,
  TechFingerprintData,
  UrlCodecData,
  UsernameSearchData,
  WaybackMachineViewerData,
  WebhookTesterData,
  WhoisLookupData,
  XssPayloadData,
  SqliPayloadData,
  UserAgentData,
  JwtCrackerData,
  PemDerConverterData,
  WebSocketTesterData,
  MetadataScrubberData,
  CidrCalculatorData,
  SubnetCheatSheetData,
  MacVendorLookupData,
  PortReferenceData,
  HttpStatusReferenceData,
  CronGeneratorData,
  ChmodCalculatorData,
  DockerfileLinterData,
  YamlValidatorData,
  NginxConfigGeneratorData,
  HtaccessGeneratorData,
  MetaTagGeneratorData,
  OpenGraphPreviewerData,
  BoxShadowGeneratorData,
  BorderRadiusGeneratorData,
  FaviconGeneratorData,
  CssGradientGeneratorData,
  CssFilterGeneratorData,
  CssTransformGeneratorData,
  HtmlTableGeneratorData,
  MarkdownToHtmlData,
  HtmlToMarkdownData,
  LoremIpsumGeneratorData,
  PlaceholderImageData,
  Base64ImageConverterData,
  KeycodeInfoData,
  ClampCalculatorData,
  ImageCompressorData,
  ColorPaletteExtractorData,
  ManifestValidatorData,
  PermissionsReferenceData,
  I18nHelperData,
  CsvToJsonData,
  CaseConverterData,
  TextStatisticsData,
  LineSorterData,
  ListRandomizerData,
  TextDiffData,
  XmlToJsonData,
  YamlToJsonData,
  JsonToYamlData,
  StringObfuscatorData,
  TextToBinaryData,
  HexViewerData,
  UnicodeExplorerData,
  RegexHighlighterData,
  EscapingToolData,
  UnixTimestampData,
  TimezoneConverterData,
  UnitConverterData,
  AspectRatioCalculatorData,
  UuidGeneratorData,
  ObjectIdGeneratorData,
  GitCommandBuilderData,
  GitIgnoreGeneratorData,
  LicenseGeneratorData,
  JsMinifierData,
  CssMinifierData,
  PythonToJsonData,
  TypescriptInterfaceGenData,
  GoStructGeneratorData,
  SqlSchemaGeneratorData,
  CurlToFetchData,
  QrCodeGeneratorData,
  BarcodeGeneratorData,
  StopwatchTimerData,
  PomodoroTimerData,
  ScratchpadData,
  TodoListData,
  MathEvaluatorData,
  ColorBlindnessSimulatorData,
  VisualGridBuilderData,
  ClickjackingTesterData,
  IdorIteratorData,
  DirectoryBusterData
} from './Tools/tool-types';
import {
  applyPayloadToForm,
  auditAccessibility,
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
  width?: number;
  height?: number;
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
    title: 'CSS Injector',
    subtitle: 'Inject custom CSS',
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
    width: 576,
    height: 450,
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
    width: 450,
    height: 400,
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
    width: 600,
    height: 608,
    render: (data, onChange) => (
      <FormFuzzerTool.Component
        data={data as FormFuzzerData | undefined}
        onChange={(next) => onChange(next)}
        onRefresh={async () => {
          onChange({
            ...(data as FormFuzzerData | undefined),
            forms: getFormsSnapshot(),
            selectedFormIndex: 0
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
    width: 700,
    height: 400,
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
    width: 550,
    height: 450,
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
    width: 480,
    height: 550,
    render: (data, onChange) => (
      <RequestLogTool.Component
        data={data as RequestLogData | undefined}
        onChange={(next) => onChange(next)}
        onClear={async () => onChange({ entries: [], filterCategory: 'all', page: 0 })}
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
          onChange({ ...(data as object ?? {}), ...result });
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
    id: 'base64Advanced',
    title: 'Base64 Advanced',
    subtitle: 'Multi-mode encoder',
    category: 'CyberSec',
    icon: faCode,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <Base64AdvancedTool.Component
        data={data as Base64AdvancedData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'htmlEntityEncoder',
    title: 'HTML Entity Encoder',
    subtitle: 'Encode/decode entities',
    category: 'CyberSec',
    icon: faCode,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <HtmlEntityEncoderTool.Component
        data={data as HtmlEntityEncoderData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'hashesGenerator',
    title: 'Hashes Generator',
    subtitle: 'SHA-1/256/384/512',
    category: 'CyberSec',
    icon: faFingerprint,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <HashesGeneratorTool.Component
        data={data as HashesGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'hmacGenerator',
    title: 'HMAC Generator',
    subtitle: 'Keyed-hash MAC',
    category: 'CyberSec',
    icon: faLock,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <HmacGeneratorTool.Component
        data={data as HmacGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'passwordStrength',
    title: 'Password Strength',
    subtitle: 'Analyze passwords',
    category: 'CyberSec',
    icon: faLock,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <PasswordStrengthTool.Component
        data={data as PasswordStrengthData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'passwordGenerator',
    title: 'Password Generator',
    subtitle: 'Secure random passwords',
    category: 'CyberSec',
    icon: faLock,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <PasswordGeneratorTool.Component
        data={data as PasswordGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'cspBuilder',
    title: 'CSP Builder',
    subtitle: 'Build & analyze CSP',
    category: 'CyberSec',
    icon: faShieldHalved,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    width: 420,
    height: 550,
    render: (data, onChange) => (
      <CspBuilderTool.Component
        data={data as CspBuilderData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'sriGenerator',
    title: 'SRI Generator',
    subtitle: 'Subresource integrity',
    category: 'CyberSec',
    icon: faLock,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <SriGeneratorTool.Component
        data={data as SriGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'xssPayload',
    title: 'XSS Payload',
    subtitle: 'Security testing payloads',
    category: 'CyberSec',
    icon: faFlask,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    height: 500,
    render: (data, onChange) => (
      <XssPayloadTool.Component
        data={data as XssPayloadData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'sqliPayload',
    title: 'SQLi Payload',
    subtitle: 'SQL injection testing',
    category: 'CyberSec',
    icon: faFlask,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    height: 450,
    render: (data, onChange) => (
      <SqliPayloadTool.Component
        data={data as SqliPayloadData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'userAgent',
    title: 'User-Agent Generator',
    subtitle: 'Browser user-agents',
    category: 'CyberSec',
    icon: faGlobe,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    render: (data, onChange) => (
      <UserAgentTool.Component
        data={data as UserAgentData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'jwtCracker',
    title: 'JWT Cracker',
    subtitle: 'Crack HMAC secrets',
    category: 'CyberSec',
    icon: faLock,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    width: 400,
    height: 550,
    render: (data, onChange) => (
      <JwtCrackerTool.Component
        data={data as JwtCrackerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'pemDerConverter',
    title: 'PEM/DER Converter',
    subtitle: 'Convert cert formats',
    category: 'CyberSec',
    icon: faLock,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    width: 400,
    render: (data, onChange) => (
      <PemDerConverterTool.Component
        data={data as PemDerConverterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'websocketTester',
    title: 'WebSocket Tester',
    subtitle: 'Test WS connections',
    category: 'CyberSec',
    icon: faNetworkWired,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    width: 420,
    height: 500,
    render: (data, onChange) => (
      <WebSocketTesterTool.Component
        data={data as WebSocketTesterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'metadataScrubber',
    title: 'Metadata Scrubber',
    subtitle: 'Strip image metadata',
    category: 'CyberSec',
    icon: faImage,
    hover: 'group-hover:border-emerald-500 group-hover:text-emerald-400',
    width: 380,
    render: (data, onChange) => (
      <MetadataScrubberTool.Component
        data={data as MetadataScrubberData | undefined}
        onChange={onChange}
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
    width: 450,
    height: 400,
    render: (data) => (
      <StorageExplorerTool.Component
        data={data as StorageExplorerData | undefined}
        onRefresh={handlers.refreshStorageExplorer}
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
        onInject={async (css) => {
          await chrome.runtime.sendMessage({
            type: 'xcalibr-inject-code',
            payload: { scope: 'current', code: css }
          });
        }}
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
    width: 420,
    height: 450,
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
  },
  {
    id: 'whoisLookup',
    title: 'Whois Lookup',
    subtitle: 'Domain RDAP data',
    category: 'OSINT',
    icon: faMagnifyingGlass,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 400,
    render: (data, onChange) => (
      <WhoisLookupTool.Component
        data={data as WhoisLookupData | undefined}
        onChange={onChange}
        onLookup={async (domain) => {
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-whois-lookup',
            payload: { domain }
          });
          onChange({ ...(data as WhoisLookupData), domain, ...result, loading: false });
        }}
      />
    )
  },
  {
    id: 'dnsRecordViewer',
    title: 'DNS Record Viewer',
    subtitle: 'A, MX, NS, TXT records',
    category: 'OSINT',
    icon: faServer,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 420,
    render: (data, onChange) => (
      <DnsRecordViewerTool.Component
        data={data as DnsRecordViewerData | undefined}
        onChange={onChange}
        onLookup={async (domain) => {
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-dns-lookup',
            payload: { domain }
          });
          onChange({ ...(data as DnsRecordViewerData), domain, ...result, loading: false });
        }}
      />
    )
  },
  {
    id: 'reverseIpLookup',
    title: 'Reverse IP Lookup',
    subtitle: 'Domains on IP',
    category: 'OSINT',
    icon: faNetworkWired,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 400,
    render: (data, onChange) => (
      <ReverseIpLookupTool.Component
        data={data as ReverseIpLookupData | undefined}
        onChange={onChange}
        onLookup={async (ip) => {
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-reverse-ip-lookup',
            payload: { ip }
          });
          onChange({ ...(data as ReverseIpLookupData), ip, ...result, loading: false });
        }}
      />
    )
  },
  {
    id: 'usernameSearch',
    title: 'Username Search',
    subtitle: 'Find username',
    category: 'OSINT',
    icon: faUser,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 420,
    height: 450,
    render: (data, onChange) => (
      <UsernameSearchTool.Component
        data={data as UsernameSearchData | undefined}
        onChange={onChange}
        onSearch={async (username) => {
          onChange({ ...(data as UsernameSearchData), username, loading: true, error: undefined });
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-username-search',
            payload: { username }
          });
          onChange({ ...(data as UsernameSearchData), username, ...result, loading: false });
        }}
      />
    )
  },
  {
    id: 'exifMetadataViewer',
    title: 'EXIF Metadata Viewer',
    subtitle: 'Image metadata',
    category: 'OSINT',
    icon: faImage,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 380,
    height: 450,
    render: (data, onChange) => (
      <ExifMetadataViewerTool.Component
        data={data as ExifMetadataViewerData | undefined}
        onChange={onChange}
        onLoadFile={async (file) => {
          onChange({ loading: true, error: undefined, metadata: undefined });
          try {
            const buffer = await file.arrayBuffer();
            const metadata = parseExif(buffer);
            if (metadata) {
              onChange({ fileName: file.name, metadata, loading: false });
            } else {
              onChange({ fileName: file.name, error: 'No EXIF metadata found in image', loading: false });
            }
          } catch (err) {
            onChange({
              fileName: file.name,
              error: err instanceof Error ? err.message : 'Failed to read image',
              loading: false
            });
          }
        }}
      />
    )
  },
  {
    id: 'emailBreachChecker',
    title: 'Email Breach Checker',
    subtitle: 'Check pwned status',
    category: 'OSINT',
    icon: faEnvelope,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 400,
    height: 450,
    render: (data, onChange) => (
      <EmailBreachCheckerTool.Component
        data={data as EmailBreachCheckerData | undefined}
        onChange={onChange}
        onCheck={async (email) => {
          onChange({ ...(data as EmailBreachCheckerData), email, loading: true, error: undefined });
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-email-breach-check',
            payload: { email }
          });
          if (result.error) {
            onChange({
              ...(data as EmailBreachCheckerData),
              email,
              loading: false,
              error: result.error,
              checkedAt: Date.now()
            });
          } else {
            onChange({
              ...(data as EmailBreachCheckerData),
              email,
              breaches: result.breaches,
              loading: false,
              error: undefined,
              checkedAt: Date.now()
            });
          }
        }}
      />
    )
  },
  {
    id: 'sslCertDecoder',
    title: 'SSL Certificate Decoder',
    subtitle: 'View cert details',
    category: 'OSINT',
    icon: faLock,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 400,
    height: 500,
    render: (data, onChange) => (
      <SslCertDecoderTool.Component
        data={data as SslCertDecoderData | undefined}
        onChange={onChange}
        onDecode={async (domain) => {
          onChange({ ...(data as SslCertDecoderData), domain, loading: true, error: undefined });
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-ssl-cert-decode',
            payload: { domain }
          });
          if (result.error) {
            onChange({
              ...(data as SslCertDecoderData),
              domain,
              loading: false,
              error: result.error,
              fetchedAt: Date.now()
            });
          } else {
            onChange({
              ...(data as SslCertDecoderData),
              domain,
              certificate: result.certificate,
              loading: false,
              error: undefined,
              fetchedAt: Date.now()
            });
          }
        }}
      />
    )
  },
  {
    id: 'googleDorkGenerator',
    title: 'Google Dork Generator',
    subtitle: 'Advanced search queries',
    category: 'OSINT',
    icon: faSearch,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 400,
    height: 500,
    render: (data, onChange) => (
      <GoogleDorkGeneratorTool.Component
        data={data as GoogleDorkGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'subdomainFinder',
    title: 'Subdomain Finder',
    subtitle: 'Find subdomains',
    category: 'OSINT',
    icon: faDiagramProject,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 400,
    height: 450,
    render: (data, onChange) => (
      <SubdomainFinderTool.Component
        data={data as SubdomainFinderData | undefined}
        onChange={onChange}
        onFind={async (domain) => {
          onChange({ ...(data as SubdomainFinderData), domain, loading: true, error: undefined });
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-subdomain-find',
            payload: { domain }
          });
          if (result.error) {
            onChange({
              ...(data as SubdomainFinderData),
              domain,
              loading: false,
              error: result.error,
              searchedAt: Date.now()
            });
          } else {
            onChange({
              ...(data as SubdomainFinderData),
              domain,
              subdomains: result.subdomains,
              loading: false,
              error: undefined,
              searchedAt: Date.now()
            });
          }
        }}
      />
    )
  },
  {
    id: 'waybackMachineViewer',
    title: 'Wayback Machine Viewer',
    subtitle: 'View archived pages',
    category: 'OSINT',
    icon: faClockRotateLeft,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    width: 600,
    height: 500,
    render: (data, onChange) => (
      <WaybackMachineViewerTool
        data={(data as WaybackMachineViewerData) || {}}
        onChange={onChange}
        onSearch={async (url) => {
          onChange({ ...(data as WaybackMachineViewerData), url, loading: true, error: undefined });
          const result = await chrome.runtime.sendMessage({
            type: 'xcalibr-wayback-search',
            payload: { url }
          });
          if (result.error) {
            onChange({
              ...(data as WaybackMachineViewerData),
              url,
              loading: false,
              error: result.error,
              searchedAt: Date.now()
            });
          } else {
            onChange({
              ...(data as WaybackMachineViewerData),
              url,
              snapshots: result.snapshots,
              loading: false,
              error: undefined,
              searchedAt: Date.now()
            });
          }
        }}
      />
    )
  },
  {
    id: 'cidrCalculator',
    title: 'CIDR Calculator',
    subtitle: 'Network calculations',
    category: 'Network',
    icon: faNetworkWired,
    hover: 'group-hover:border-teal-500 group-hover:text-teal-400',
    render: (data, onChange) => (
      <CidrCalculatorTool.Component
        data={data as CidrCalculatorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'subnetCheatSheet',
    title: 'Subnet Cheat Sheet',
    subtitle: 'Subnet mask reference',
    category: 'Network',
    icon: faTable,
    hover: 'group-hover:border-teal-500 group-hover:text-teal-400',
    width: 450,
    render: (data, onChange) => (
      <SubnetCheatSheetTool.Component
        data={data as SubnetCheatSheetData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'macVendorLookup',
    title: 'MAC Vendor Lookup',
    subtitle: 'OUI database',
    category: 'Network',
    icon: faFingerprint,
    hover: 'group-hover:border-teal-500 group-hover:text-teal-400',
    render: (data, onChange) => (
      <MacVendorLookupTool.Component
        data={data as MacVendorLookupData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'portReference',
    title: 'Port Reference',
    subtitle: 'TCP/UDP ports',
    category: 'Network',
    icon: faServer,
    hover: 'group-hover:border-teal-500 group-hover:text-teal-400',
    height: 500,
    render: (data, onChange) => (
      <PortReferenceTool.Component
        data={data as PortReferenceData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'httpStatusReference',
    title: 'HTTP Status Reference',
    subtitle: 'Status codes',
    category: 'Network',
    icon: faGlobe,
    hover: 'group-hover:border-teal-500 group-hover:text-teal-400',
    height: 500,
    render: (data, onChange) => (
      <HttpStatusReferenceTool.Component
        data={data as HttpStatusReferenceData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'cronGenerator',
    title: 'Cron Generator',
    subtitle: 'Build cron expressions',
    category: 'DevOps',
    icon: faGear,
    hover: 'group-hover:border-yellow-500 group-hover:text-yellow-400',
    render: (data, onChange) => (
      <CronGeneratorTool.Component
        data={data as CronGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'chmodCalculator',
    title: 'Chmod Calculator',
    subtitle: 'File permissions',
    category: 'DevOps',
    icon: faLock,
    hover: 'group-hover:border-yellow-500 group-hover:text-yellow-400',
    render: (data, onChange) => (
      <ChmodCalculatorTool.Component
        data={data as ChmodCalculatorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'dockerfileLinter',
    title: 'Dockerfile Linter',
    subtitle: 'Check best practices',
    category: 'DevOps',
    icon: faFileCode,
    hover: 'group-hover:border-yellow-500 group-hover:text-yellow-400',
    height: 450,
    render: (data, onChange) => (
      <DockerfileLinterTool.Component
        data={data as DockerfileLinterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'yamlValidator',
    title: 'YAML Validator',
    subtitle: 'Validate syntax',
    category: 'DevOps',
    icon: faCode,
    hover: 'group-hover:border-yellow-500 group-hover:text-yellow-400',
    height: 450,
    render: (data, onChange) => (
      <YamlValidatorTool.Component
        data={data as YamlValidatorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'nginxConfigGenerator',
    title: 'Nginx Config Generator',
    subtitle: 'Server blocks',
    category: 'DevOps',
    icon: faServer,
    hover: 'group-hover:border-yellow-500 group-hover:text-yellow-400',
    height: 500,
    render: (data, onChange) => (
      <NginxConfigGeneratorTool.Component
        data={data as NginxConfigGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'htaccessGenerator',
    title: 'Htaccess Generator',
    subtitle: 'Apache rules',
    category: 'DevOps',
    icon: faFileCode,
    hover: 'group-hover:border-yellow-500 group-hover:text-yellow-400',
    height: 450,
    render: (data, onChange) => (
      <HtaccessGeneratorTool.Component
        data={data as HtaccessGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'metaTagGenerator',
    title: 'Meta Tag Generator',
    subtitle: 'SEO meta tags',
    category: 'Web Dev',
    icon: faCode,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <MetaTagGeneratorTool.Component
        data={data as MetaTagGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'openGraphPreviewer',
    title: 'Open Graph Preview',
    subtitle: 'Social media preview',
    category: 'Web Dev',
    icon: faGlobe,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <OpenGraphPreviewerTool.Component
        data={data as OpenGraphPreviewerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'boxShadowGenerator',
    title: 'Box Shadow Generator',
    subtitle: 'CSS box-shadow',
    category: 'Web Dev',
    icon: faSquare,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <BoxShadowGeneratorTool.Component
        data={data as BoxShadowGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'borderRadiusGenerator',
    title: 'Border Radius Generator',
    subtitle: 'CSS border-radius',
    category: 'Web Dev',
    icon: faCircle,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <BorderRadiusGeneratorTool.Component
        data={data as BorderRadiusGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'faviconGenerator',
    title: 'Favicon Generator',
    subtitle: 'Create favicons',
    category: 'Web Dev',
    icon: faStar,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <FaviconGeneratorTool.Component
        data={data as FaviconGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'cssGradientGenerator',
    title: 'CSS Gradient Generator',
    subtitle: 'Create gradients',
    category: 'Web Dev',
    icon: faEyeDropper,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <CssGradientGeneratorTool.Component
        data={data as CssGradientGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'cssFilterGenerator',
    title: 'CSS Filter Generator',
    subtitle: 'Image filters',
    category: 'Web Dev',
    icon: faSliders,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <CssFilterGeneratorTool.Component
        data={data as CssFilterGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'cssTransformGenerator',
    title: 'CSS Transform Generator',
    subtitle: 'Transform elements',
    category: 'Web Dev',
    icon: faArrowsRotate,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <CssTransformGeneratorTool.Component
        data={data as CssTransformGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'htmlTableGenerator',
    title: 'HTML Table Generator',
    subtitle: 'Generate tables',
    category: 'Web Dev',
    icon: faTable,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    width: 450,
    render: (data, onChange) => (
      <HtmlTableGeneratorTool.Component
        data={data as HtmlTableGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'markdownToHtml',
    title: 'Markdown to HTML',
    subtitle: 'Convert markdown',
    category: 'Web Dev',
    icon: faCode,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    width: 400,
    render: (data, onChange) => (
      <MarkdownToHtmlTool.Component
        data={data as MarkdownToHtmlData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'htmlToMarkdown',
    title: 'HTML to Markdown',
    subtitle: 'Convert HTML',
    category: 'Web Dev',
    icon: faCode,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    width: 400,
    render: (data, onChange) => (
      <HtmlToMarkdownTool.Component
        data={data as HtmlToMarkdownData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'loremIpsumGenerator',
    title: 'Lorem Ipsum Generator',
    subtitle: 'Placeholder text',
    category: 'Web Dev',
    icon: faFileLines,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <LoremIpsumGeneratorTool.Component
        data={data as LoremIpsumGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'placeholderImage',
    title: 'Placeholder Image',
    subtitle: 'Generate placeholder',
    category: 'Web Dev',
    icon: faImage,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <PlaceholderImageTool.Component
        data={data as PlaceholderImageData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'base64ImageConverter',
    title: 'Base64 Image Converter',
    subtitle: 'Image/Base64 convert',
    category: 'Web Dev',
    icon: faImage,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <Base64ImageConverterTool.Component
        data={data as Base64ImageConverterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'keycodeInfo',
    title: 'Keycode Info',
    subtitle: 'Key event details',
    category: 'Web Dev',
    icon: faKeyboard,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <KeycodeInfoTool.Component
        data={data as KeycodeInfoData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'clampCalculator',
    title: 'Clamp Calculator',
    subtitle: 'Fluid typography',
    category: 'Web Dev',
    icon: faRuler,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <ClampCalculatorTool.Component
        data={data as ClampCalculatorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'imageCompressor',
    title: 'Image Compressor',
    subtitle: 'Compress images',
    category: 'Web Dev',
    icon: faCompress,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <ImageCompressorTool.Component
        data={data as ImageCompressorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'colorPaletteExtractor',
    title: 'Color Palette Extractor',
    subtitle: 'Extract colors',
    category: 'Web Dev',
    icon: faPalette,
    hover: 'group-hover:border-pink-500 group-hover:text-pink-400',
    render: (data, onChange) => (
      <ColorPaletteExtractorTool.Component
        data={data as ColorPaletteExtractorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'manifestValidator',
    title: 'Manifest V3 Validator',
    subtitle: 'Validate manifest',
    category: 'Extension Dev',
    icon: faPuzzlePiece,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    width: 400,
    render: (data, onChange) => (
      <ManifestValidatorTool.Component
        data={data as ManifestValidatorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'permissionsReference',
    title: 'Permissions Reference',
    subtitle: 'Chrome permissions',
    category: 'Extension Dev',
    icon: faKey,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <PermissionsReferenceTool.Component
        data={data as PermissionsReferenceData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'i18nHelper',
    title: 'i18n Message Helper',
    subtitle: 'Localization helper',
    category: 'Extension Dev',
    icon: faLanguage,
    hover: 'group-hover:border-purple-500 group-hover:text-purple-400',
    render: (data, onChange) => (
      <I18nHelperTool.Component
        data={data as I18nHelperData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'csvToJson',
    title: 'CSV to JSON',
    subtitle: 'Convert CSV data',
    category: 'Data & Text',
    icon: faFileExcel,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <CsvToJsonTool.Component
        data={data as CsvToJsonData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'caseConverter',
    title: 'Case Converter',
    subtitle: 'Convert text case',
    category: 'Data & Text',
    icon: faTextHeight,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <CaseConverterTool.Component
        data={data as CaseConverterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'textStatistics',
    title: 'Text Statistics',
    subtitle: 'Count words/chars',
    category: 'Data & Text',
    icon: faCalculator,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <TextStatisticsTool.Component
        data={data as TextStatisticsData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'lineSorter',
    title: 'Line Sorter',
    subtitle: 'Sort/dedupe lines',
    category: 'Data & Text',
    icon: faListOl,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <LineSorterTool.Component
        data={data as LineSorterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'listRandomizer',
    title: 'List Randomizer',
    subtitle: 'Shuffle/pick random',
    category: 'Data & Text',
    icon: faShuffle,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <ListRandomizerTool.Component
        data={data as ListRandomizerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'textDiff',
    title: 'Text Diff',
    subtitle: 'Compare texts',
    category: 'Data & Text',
    icon: faCodeCompare,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <TextDiffTool.Component
        data={data as TextDiffData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'xmlToJson',
    title: 'XML to JSON',
    subtitle: 'Convert XML data',
    category: 'Data & Text',
    icon: faFileCode,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <XmlToJsonTool.Component
        data={data as XmlToJsonData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'yamlToJson',
    title: 'YAML to JSON',
    subtitle: 'Convert YAML data',
    category: 'Data & Text',
    icon: faFileAlt,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <YamlToJsonTool.Component
        data={data as YamlToJsonData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'jsonToYaml',
    title: 'JSON to YAML',
    subtitle: 'Convert JSON data',
    category: 'Data & Text',
    icon: faFileExport,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <JsonToYamlTool.Component
        data={data as JsonToYamlData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'stringObfuscator',
    title: 'String Obfuscator',
    subtitle: 'Obfuscate strings',
    category: 'Data & Text',
    icon: faMask,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <StringObfuscatorTool.Component
        data={data as StringObfuscatorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'textToBinary',
    title: 'Text to Binary',
    subtitle: 'Convert text/binary',
    category: 'Data & Text',
    icon: faCode,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <TextToBinaryTool.Component
        data={data as TextToBinaryData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'hexViewer',
    title: 'Hex Viewer',
    subtitle: 'View hex dump',
    category: 'Data & Text',
    icon: faMemory,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <HexViewerTool.Component
        data={data as HexViewerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'unicodeExplorer',
    title: 'Unicode Explorer',
    subtitle: 'Browse characters',
    category: 'Data & Text',
    icon: faIcons,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <UnicodeExplorerTool.Component
        data={data as UnicodeExplorerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'regexHighlighter',
    title: 'Regex Highlighter',
    subtitle: 'Test & highlight matches',
    category: 'Data & Text',
    icon: faHighlighter,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <RegexHighlighterTool.Component
        data={data as RegexHighlighterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'escapingTool',
    title: 'Escaping Tool',
    subtitle: 'Escape strings',
    category: 'Data & Text',
    icon: faShieldAlt,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <EscapingTool.Component
        data={data as EscapingToolData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'unixTimestamp',
    title: 'Unix Timestamp',
    subtitle: 'Convert timestamps',
    category: 'Data & Text',
    icon: faClock,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <UnixTimestampTool.Component
        data={data as UnixTimestampData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'timezoneConverter',
    title: 'Timezone Converter',
    subtitle: 'Convert timezones',
    category: 'Data & Text',
    icon: faGlobeAmericas,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <TimezoneConverterTool.Component
        data={data as TimezoneConverterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'unitConverter',
    title: 'Unit Converter',
    subtitle: 'Convert dev units',
    category: 'Data & Text',
    icon: faExchangeAlt,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <UnitConverterTool.Component
        data={data as UnitConverterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'aspectRatioCalculator',
    title: 'Aspect Ratio Calculator',
    subtitle: 'Calculate ratios',
    category: 'Data & Text',
    icon: faRulerCombined,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <AspectRatioCalculatorTool.Component
        data={data as AspectRatioCalculatorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'uuidGenerator',
    title: 'UUID Generator',
    subtitle: 'Generate UUIDs',
    category: 'Data & Text',
    icon: faUuid,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <UuidGeneratorTool.Component
        data={data as UuidGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'objectIdGenerator',
    title: 'ObjectId Generator',
    subtitle: 'MongoDB ObjectIds',
    category: 'Data & Text',
    icon: faDatabase,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <ObjectIdGeneratorTool.Component
        data={data as ObjectIdGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'gitCommandBuilder',
    title: 'Git Command Builder',
    subtitle: 'Build git commands',
    category: 'Data & Text',
    icon: faCodeBranch,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <GitCommandBuilderTool.Component
        data={data as GitCommandBuilderData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'gitignoreGenerator',
    title: 'GitIgnore Generator',
    subtitle: 'Generate .gitignore',
    category: 'Data & Text',
    icon: faFileAlt,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <GitIgnoreGeneratorTool.Component
        data={data as GitIgnoreGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'licenseGenerator',
    title: 'License Generator',
    subtitle: 'Generate licenses',
    category: 'Data & Text',
    icon: faBalanceScale,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <LicenseGeneratorTool.Component
        data={data as LicenseGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'jsMinifier',
    title: 'JS Minifier',
    subtitle: 'Minify JavaScript',
    category: 'Data & Text',
    icon: faCompress,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <JsMinifierTool.Component
        data={data as JsMinifierData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'cssMinifier',
    title: 'CSS Minifier',
    subtitle: 'Minify CSS',
    category: 'Data & Text',
    icon: faPalette,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <CssMinifierTool.Component
        data={data as CssMinifierData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'pythonToJson',
    title: 'Python to JSON',
    subtitle: 'Convert Python dict',
    category: 'Data & Text',
    icon: faFileCode,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <PythonToJsonTool.Component
        data={data as PythonToJsonData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'typescriptInterfaceGen',
    title: 'TypeScript Interface',
    subtitle: 'Generate TS interfaces',
    category: 'Data & Text',
    icon: faTypescript,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <TypescriptInterfaceGenTool.Component
        data={data as TypescriptInterfaceGenData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'goStructGenerator',
    title: 'Go Struct Generator',
    subtitle: 'Generate Go structs',
    category: 'Data & Text',
    icon: faCubes,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <GoStructGeneratorTool.Component
        data={data as GoStructGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'sqlSchemaGenerator',
    title: 'SQL Schema Generator',
    subtitle: 'Generate SQL CREATE',
    category: 'Data & Text',
    icon: faTable,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <SqlSchemaGeneratorTool.Component
        data={data as SqlSchemaGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'curlToFetch',
    title: 'cURL to Fetch',
    subtitle: 'Convert cURL to JS',
    category: 'Data & Text',
    icon: faTerminal,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <CurlToFetchTool.Component
        data={data as CurlToFetchData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'qrCodeGenerator',
    title: 'QR Code Generator',
    subtitle: 'Generate QR codes',
    category: 'Data & Text',
    icon: faQrcode,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <QrCodeGeneratorTool.Component
        data={data as QrCodeGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'barcodeGenerator',
    title: 'Barcode Generator',
    subtitle: 'Generate barcodes',
    category: 'Data & Text',
    icon: faBarcode,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <BarcodeGeneratorTool.Component
        data={data as BarcodeGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'stopwatchTimer',
    title: 'Stopwatch / Timer',
    subtitle: 'Time tracking',
    category: 'Data & Text',
    icon: faStopwatch,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <StopwatchTimerTool.Component
        data={data as StopwatchTimerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'pomodoroTimer',
    title: 'Pomodoro Timer',
    subtitle: 'Focus timer',
    category: 'Data & Text',
    icon: faPomodoro,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <PomodoroTimerTool.Component
        data={data as PomodoroTimerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'scratchpad',
    title: 'Scratchpad',
    subtitle: 'Persistent notes',
    category: 'Data & Text',
    icon: faStickyNote,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <ScratchpadTool.Component
        data={data as ScratchpadData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'todoList',
    title: 'Todo List',
    subtitle: 'Task manager',
    category: 'Data & Text',
    icon: faListCheck,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <TodoListTool.Component
        data={data as TodoListData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'mathEvaluator',
    title: 'Math Evaluator',
    subtitle: 'Calculate expressions',
    category: 'Data & Text',
    icon: faMathCalc,
    hover: 'group-hover:border-orange-500 group-hover:text-orange-400',
    render: (data, onChange) => (
      <MathEvaluatorTool.Component
        data={data as MathEvaluatorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'colorBlindnessSimulator',
    title: 'Color Blindness Sim',
    subtitle: 'Simulate vision',
    category: 'Web Dev',
    icon: faEye,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <ColorBlindnessSimulatorTool.Component
        data={data as ColorBlindnessSimulatorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'visualGridBuilder',
    title: 'Visual Grid Builder',
    subtitle: 'Design CSS grids',
    category: 'Web Dev',
    icon: faTableCells,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <VisualGridBuilderTool.Component
        data={data as VisualGridBuilderData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'clickjackingTester',
    title: 'Clickjacking Tester',
    subtitle: 'Test X-Frame-Options',
    category: 'CyberSec',
    icon: faClickjack,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    render: (data, onChange) => (
      <ClickjackingTesterTool.Component
        data={data as ClickjackingTesterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'idorIterator',
    title: 'IDOR Iterator',
    subtitle: 'Test object references',
    category: 'CyberSec',
    icon: faHashtag,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    render: (data, onChange) => (
      <IdorIteratorTool.Component
        data={data as IdorIteratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'directoryBuster',
    title: 'Directory Buster',
    subtitle: 'Find hidden paths',
    category: 'CyberSec',
    icon: faFolder,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    render: (data, onChange) => (
      <DirectoryBusterTool.Component
        data={data as DirectoryBusterData | undefined}
        onChange={onChange}
      />
    )
  }
];
