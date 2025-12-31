import { vi } from 'vitest';
import { DEFAULT_STATE } from '../../shared/state';

export const STORAGE_KEY = 'xcalibr_state';

export const flushPromises = () => new Promise((resolve) => setTimeout(resolve, 0));

export const waitFor = async <T,>(
  getter: () => T | null | undefined,
  attempts = 25
): Promise<T | null> => {
  for (let i = 0; i < attempts; i += 1) {
    const value = getter();
    if (value) return value as T;
    await flushPromises();
  }
  return null;
};

export const resetChrome = () => {
  const reset = (globalThis as Record<string, unknown>).__resetChromeMocks as
    | (() => void)
    | undefined;
  if (reset) reset();
  const clearHandlers = (globalThis as Record<string, unknown>).__clearRuntimeHandlers as
    | (() => void)
    | undefined;
  if (clearHandlers) clearHandlers();
};

export const setRuntimeHandler = (type: string, handler: (payload?: unknown) => unknown) => {
  const setter = (globalThis as Record<string, unknown>).__setRuntimeHandler as
    | ((type: string, handler: (payload?: unknown) => unknown) => void)
    | undefined;
  setter?.(type, handler);
};

export const setState = async (partial: Record<string, unknown>) => {
  await chrome.storage.local.set({
    [STORAGE_KEY]: { ...DEFAULT_STATE, ...partial }
  });
};

export const getState = async () => {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  return stored[STORAGE_KEY] as typeof DEFAULT_STATE;
};

export const waitForState = async (
  predicate: (state: typeof DEFAULT_STATE) => boolean,
  attempts = 25
) => {
  for (let i = 0; i < attempts; i += 1) {
    const state = await getState();
    if (predicate(state)) return state;
    await flushPromises();
  }
  return null;
};

export const openToolState = (toolId: string) => ({
  toolWindows: {
    [toolId]: { isOpen: true, isMinimized: false, x: 80, y: 120 }
  }
});

export const TOOL_TITLES: Record<string, string> = {
  base64Advanced: 'Base64 Advanced',
  htmlEntityEncoder: 'HTML Entity Encoder',
  hashesGenerator: 'Hashes Generator',
  hmacGenerator: 'HMAC Generator',
  passwordStrength: 'Password Strength',
  pemDerConverter: 'PEM/DER Converter',
  passwordGenerator: 'Password Generator',
  cspBuilder: 'CSP Builder',
  sriGenerator: 'SRI Generator',
  xssPayload: 'XSS Payload',
  sqliPayload: 'SQLi Payload',
  userAgent: 'User-Agent Generator',
  codeInjector: 'CSS Injector',
  liveLinkPreview: 'Live Link Preview',
  headerInspector: 'Header Inspector',
  techFingerprint: 'Tech Fingerprint',
  robotsViewer: 'Robots.txt Viewer',
  formFuzzer: 'Form Fuzzer',
  urlCodec: 'URL Encoder/Decoder',
  paramAnalyzer: 'Param Analyzer',
  linkExtractor: 'Link Extractor',
  domSnapshot: 'DOM Snapshot',
  assetMapper: 'Asset Mapper',
  requestLog: 'Request Log',
  payloadReplay: 'Payload Replay',
  corsCheck: 'CORS Check',
  jsonMinifier: 'JSON Minifier',
  jsonPrettifier: 'JSON Prettifier',
  jsonSchemaValidator: 'JSON Schema Validator',
  jsonPathTester: 'JSON Path Tester',
  jsonDiff: 'JSON Diff',
  sqlFormatter: 'SQL Formatter',
  sqlQueryBuilder: 'SQL Query Builder',
  sqlToCsv: 'SQL to CSV',
  indexAdvisor: 'Index Advisor',
  bsonViewer: 'BSON Viewer',
  mongoQueryBuilder: 'Mongo Query Builder',
  dynamoDbConverter: 'DynamoDB JSON Converter',
  firebaseRulesLinter: 'Firebase Rules Linter',
  couchDbDocExplorer: 'CouchDB Doc Explorer',
  debuggerTool: 'Debugger',
  storageExplorer: 'Storage Explorer',
  lighthouseSnapshot: 'Lighthouse Snapshot',
  cssGridGenerator: 'CSS Grid Generator',
  flexboxInspector: 'Flexbox Inspector',
  fontIdentifier: 'Font Identifier',
  contrastChecker: 'Contrast Checker',
  responsivePreview: 'Responsive Preview',
  animationPreview: 'Animation Preview',
  svgOptimizer: 'SVG Optimizer',
  accessibilityAudit: 'Accessibility Audit',
  jwtCracker: 'JWT Cracker',
  jwtDebugger: 'JWT Debugger',
  regexTester: 'Regex Tester',
  apiResponseViewer: 'API Response Viewer',
  graphqlExplorer: 'GraphQL Explorer',
  restClient: 'REST Client',
  oauthTokenInspector: 'OAuth Token Inspector',
  webhookTester: 'Webhook Tester',
  websocketTester: 'WebSocket Tester',
  cookieManager: 'Cookie Manager',
  colorPicker: 'Color Picker',
  whoisLookup: 'Whois Lookup',
  dnsRecordViewer: 'DNS Record Viewer',
  reverseIpLookup: 'Reverse IP Lookup',
  usernameSearch: 'Username Search',
  exifMetadataViewer: 'EXIF Metadata Viewer',
  metadataScrubber: 'Metadata Scrubber',
  emailBreachChecker: 'Email Breach Checker',
  sslCertDecoder: 'SSL Certificate Decoder',
  googleDorkGenerator: 'Google Dork Generator',
  subdomainFinder: 'Subdomain Finder',
  waybackMachineViewer: 'Wayback Machine Viewer',
  cidrCalculator: 'CIDR Calculator',
  subnetCheatSheet: 'Subnet Cheat Sheet',
  macVendorLookup: 'MAC Vendor Lookup',
  portReference: 'Port Reference',
  httpStatusReference: 'HTTP Status Reference',
  cronGenerator: 'Cron Generator',
  chmodCalculator: 'Chmod Calculator',
  dockerfileLinter: 'Dockerfile Linter',
  yamlValidator: 'YAML Validator',
  nginxConfigGenerator: 'Nginx Config Generator',
  htaccessGenerator: 'Htaccess Generator',
  metaTagGenerator: 'Meta Tag Generator',
  openGraphPreviewer: 'Open Graph Preview',
  boxShadowGenerator: 'Box Shadow Generator',
  borderRadiusGenerator: 'Border Radius Generator',
  faviconGenerator: 'Favicon Generator',
  cssGradientGenerator: 'CSS Gradient Generator',
  cssFilterGenerator: 'CSS Filter Generator',
  cssTransformGenerator: 'CSS Transform Generator',
  htmlTableGenerator: 'HTML Table Generator',
  markdownToHtml: 'Markdown to HTML',
  htmlToMarkdown: 'HTML to Markdown',
  loremIpsumGenerator: 'Lorem Ipsum Generator',
  placeholderImage: 'Placeholder Image',
  base64ImageConverter: 'Base64 Image Converter',
  keycodeInfo: 'Keycode Info',
  clampCalculator: 'Clamp Calculator',
  imageCompressor: 'Image Compressor',
  colorPaletteExtractor: 'Color Palette Extractor',
  manifestValidator: 'Manifest V3 Validator',
  permissionsReference: 'Permissions Reference',
  i18nHelper: 'i18n Message Helper',
  csvToJson: 'CSV to JSON',
  caseConverter: 'Case Converter',
  textStatistics: 'Text Statistics',
  lineSorter: 'Line Sorter',
  listRandomizer: 'List Randomizer',
  textDiff: 'Text Diff',
  xmlToJson: 'XML to JSON',
  yamlToJson: 'YAML to JSON',
  jsonToYaml: 'JSON to YAML',
  stringObfuscator: 'String Obfuscator',
  textToBinary: 'Text to Binary',
  hexViewer: 'Hex Viewer',
  unicodeExplorer: 'Unicode Explorer',
  regexHighlighter: 'Regex Highlighter',
  escapingTool: 'Escaping Tool',
  unixTimestamp: 'Unix Timestamp',
  timezoneConverter: 'Timezone Converter',
  unitConverter: 'Unit Converter',
  aspectRatioCalculator: 'Aspect Ratio Calculator',
  uuidGenerator: 'UUID Generator',
  objectIdGenerator: 'ObjectId Generator',
  gitCommandBuilder: 'Git Command Builder',
  gitignoreGenerator: 'GitIgnore Generator',
  licenseGenerator: 'License Generator',
  jsMinifier: 'JS Minifier',
  cssMinifier: 'CSS Minifier',
  pythonToJson: 'Python to JSON',
  typescriptInterfaceGen: 'TypeScript Interface',
  goStructGenerator: 'Go Struct Generator',
  sqlSchemaGenerator: 'SQL Schema Generator',
  curlToFetch: 'cURL to Fetch',
  qrCodeGenerator: 'QR Code Generator',
  barcodeGenerator: 'Barcode Generator',
  stopwatchTimer: 'Stopwatch / Timer',
  pomodoroTimer: 'Pomodoro Timer',
  scratchpad: 'Scratchpad',
  todoList: 'Todo List',
  mathEvaluator: 'Math Evaluator',
  colorBlindnessSimulator: 'Color Blindness Sim',
  visualGridBuilder: 'Visual Grid Builder',
  clickjackingTester: 'Clickjacking Tester',
  idorIterator: 'IDOR Iterator',
  directoryBuster: 'Directory Buster',
  // === BATCH B: Red Team Tools #11-17 ===
  protoPollutionFuzzer: 'Proto-Pollution Fuzzer',
  openRedirectTester: 'Open Redirect Tester',
  apiEndpointScraper: 'API Endpoint Scraper',
  csrfPocGenerator: 'CSRF PoC Generator',
  wafDetector: 'WAF Detector',
  subdomainTakeoverChecker: 'Subdomain Takeover Checker',
  postMessageLogger: 'PostMessage Logger',
  // === BATCH C: Red Team Tools #18-23 ===
  sourceMapDetector: 'Source Map Detector',
  adminPanelFinder: 'Admin Panel Finder',
  httpMethodTester: 'HTTP Method Tester',
  defaultCredentialChecker: 'Default Credentials',
  graphqlIntrospectionTester: 'GraphQL Introspection',
  corsExploitGenerator: 'CORS Exploit Generator',
  // === BATCH A: Red Team Tools #4-10 ===
  commentSecretScraper: 'Comment & Secret Scraper',
  hiddenFieldRevealer: 'Hidden Field Revealer',
  s3BucketFinder: 'S3 Bucket Finder',
  gitExposureChecker: 'Git Exposure Checker',
  targetBlankAuditor: 'Target Blank Auditor',
  storageSecretHunter: 'Storage Secret Hunter',
  metafileScanner: 'Metafile Scanner'
};

export const mountContent = async () => {
  vi.resetModules();
  vi.doMock('wxt/sandbox', () => ({
    defineContentScript: (config: { main: (ctx: unknown) => void }) => config
  }));
  const module = await import('../content');
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (module.default.main as (ctx: unknown) => void)({});
  await flushPromises();
};

export const getShadowRoot = () => {
  const host = document.getElementById('xcalibr-root');
  return host?.shadowRoot ?? null;
};

export const mountWithTool = async (
  toolId: string,
  toolData: Record<string, unknown> = {}
) => {
  await setState({
    isOpen: true,
    isVisible: true,
    ...openToolState(toolId),
    toolData: { [toolId]: toolData }
  });
  await mountContent();
  const root = await waitFor(() => getShadowRoot());
  if (!root) return null;
  const title = TOOL_TITLES[toolId];
  if (title) {
    await waitFor(() => queryAllByText(root, title)[0]);
  }
  return root;
};

export const queryAllByText = (root: ShadowRoot, text: string) =>
  Array.from(root.querySelectorAll('*')).filter((node) =>
    node.textContent?.includes(text)
  );

export const findButtonByText = (root: ShadowRoot, text: string) => {
  return Array.from(root.querySelectorAll('button')).find(
    (button) => button.textContent?.trim() === text
  );
};

export const findQuickBarButtonById = (root: ShadowRoot, toolId: string) => {
  return root.querySelector(`button[data-quickbar-id="${toolId}"]`);
};

export const findPreviewFrame = () => {
  const hosts = Array.from(document.querySelectorAll('div'));
  for (const host of hosts) {
    const shadow = host.shadowRoot;
    const frame = shadow?.querySelector('iframe.preview-frame') as HTMLIFrameElement | null;
    if (frame) return frame;
  }
  return null;
};

export const typeInput = (input: HTMLInputElement | HTMLTextAreaElement, value: string) => {
  input.value = value;
  input.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
  input.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
};
