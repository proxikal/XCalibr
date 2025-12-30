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
  jwtDebugger: 'JWT Debugger',
  regexTester: 'Regex Tester',
  apiResponseViewer: 'API Response Viewer',
  graphqlExplorer: 'GraphQL Explorer',
  restClient: 'REST Client',
  oauthTokenInspector: 'OAuth Token Inspector',
  webhookTester: 'Webhook Tester',
  cookieManager: 'Cookie Manager',
  colorPicker: 'Color Picker'
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
