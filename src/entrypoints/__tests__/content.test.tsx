import { beforeEach, describe, it, vi } from 'vitest';
import { aiAssertEqual, aiAssertIncludes, aiAssertTruthy } from '../../test-utils/aiAssert';
import { DEFAULT_STATE } from '../../shared/state';

const STORAGE_KEY = 'xcalibr_state';

const flushPromises = () => new Promise((resolve) => setTimeout(resolve, 0));
const waitFor = async <T,>(
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

const resetChrome = () => {
  const reset = (globalThis as Record<string, unknown>).__resetChromeMocks as
    | (() => void)
    | undefined;
  if (reset) reset();
  const clearHandlers = (globalThis as Record<string, unknown>).__clearRuntimeHandlers as
    | (() => void)
    | undefined;
  if (clearHandlers) clearHandlers();
};

const setRuntimeHandler = (type: string, handler: (payload?: unknown) => unknown) => {
  const setter = (globalThis as Record<string, unknown>).__setRuntimeHandler as
    | ((type: string, handler: (payload?: unknown) => unknown) => void)
    | undefined;
  setter?.(type, handler);
};

const setState = async (partial: Record<string, unknown>) => {
  await chrome.storage.local.set({
    [STORAGE_KEY]: { ...DEFAULT_STATE, ...partial }
  });
};

const getState = async () => {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  return stored[STORAGE_KEY] as typeof DEFAULT_STATE;
};

const waitForState = async (
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

const openToolState = (toolId: string) => ({
  toolWindows: {
    [toolId]: { isOpen: true, isMinimized: false, x: 80, y: 120 }
  }
});

const TOOL_TITLES: Record<string, string> = {
  codeInjector: 'Code Injector',
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
  snippetRunner: 'Console Snippet Runner',
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

const mountWithTool = async (
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

const queryAllByText = (root: ShadowRoot, text: string) =>
  Array.from(root.querySelectorAll('*')).filter((node) =>
    node.textContent?.includes(text)
  );

const mountContent = async () => {
  vi.resetModules();
  vi.doMock('wxt/sandbox', () => ({
    defineContentScript: (config: { main: () => void }) => config
  }));
  const module = await import('../content');
  module.default.main();
  await flushPromises();
};

const getShadowRoot = () => {
  const host = document.getElementById('xcalibr-root');
  return host?.shadowRoot ?? null;
};

const findButtonByText = (root: ShadowRoot, text: string) => {
  return Array.from(root.querySelectorAll('button')).find(
    (button) => button.textContent?.trim() === text
  );
};

const findPreviewFrame = () => {
  const hosts = Array.from(document.querySelectorAll('div'));
  for (const host of hosts) {
    const shadow = host.shadowRoot;
    const frame = shadow?.querySelector('iframe.preview-frame') as HTMLIFrameElement | null;
    if (frame) return frame;
  }
  return null;
};

const typeInput = (input: HTMLInputElement | HTMLTextAreaElement, value: string) => {
  input.value = value;
  input.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
  input.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
};

describe('content entrypoint', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  it('mounts and paginates quick bar favorites with search', async () => {
    await setState({
      isOpen: true,
      isVisible: true,
      isWide: true,
      quickBarToolIds: [
        'colorPicker',
        'jsonMinifier',
        'jsonPrettifier',
        'jsonSchemaValidator',
        'jsonPathTester',
        'jsonDiff',
        'codeInjector'
      ]
    });
    await mountContent();
    const root = getShadowRoot();
    aiAssertTruthy({ name: 'QuickBarRoot', state: { hasRoot: Boolean(root) } }, root);
    if (!root) return;

    const nextButton = await waitFor(() => findButtonByText(root, 'Next'));
    aiAssertTruthy({ name: 'QuickBarNextButton' }, nextButton);
    if (!nextButton) return;

    const pageLabel = await waitFor(() =>
      Array.from(root.querySelectorAll('span')).find((node) =>
        node.textContent?.includes('/')
      )
    );
    const pageText = pageLabel?.textContent ?? '';
    aiAssertIncludes(
      { name: 'QuickBarPagination', state: { text: pageText } },
      pageText,
      '/'
    );
    const match = pageText.match(/(\d+)\s*\/\s*(\d+)/);
    const totalPages = match ? Number(match[2]) : 1;
    if (totalPages > 1) {
      nextButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const pageLabelAfter = await waitFor(() =>
        Array.from(root.querySelectorAll('span')).find((node) =>
          node.textContent?.includes('/')
        )
      );
      aiAssertIncludes(
        {
          name: 'QuickBarPaginationAfter',
          state: { text: pageLabelAfter?.textContent }
        },
        pageLabelAfter?.textContent ?? '',
        `2 / ${totalPages}`
      );
    } else {
      aiAssertTruthy(
        { name: 'QuickBarPaginationSingle', state: { text: pageText } },
        nextButton.disabled
      );
    }

    const searchInput = (await waitFor(() =>
      root.querySelector('input[placeholder="Search favorites..."]')
    )) as HTMLInputElement | null;
    aiAssertTruthy({ name: 'QuickBarSearchInput' }, searchInput);
    if (!searchInput) return;
    typeInput(searchInput, 'json');
    await flushPromises();
    const resultsLabel = await waitFor(() =>
      Array.from(root.querySelectorAll('span')).find((node) =>
        node.textContent?.includes('results')
      )
    );
    aiAssertIncludes(
      { name: 'QuickBarSearchResults', input: { query: 'json' } },
      resultsLabel?.textContent ?? '',
      'results'
    );
  });

  it('opens spotlight overlay via cmd+shift+p and filters tools', async () => {
    await setState({ isOpen: true, isVisible: true });
    await mountContent();
    const root = getShadowRoot();
    if (!root) return;

    window.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'p', metaKey: true, shiftKey: true })
    );
    await flushPromises();

    const spotlightInput = (await waitFor(() =>
      root.querySelector('input[placeholder="Search tools..."]')
    )) as HTMLInputElement | null;
    aiAssertTruthy({ name: 'SpotlightInput' }, spotlightInput);
    if (!spotlightInput) return;
    typeInput(spotlightInput, 'color');
    await flushPromises();

    const match = Array.from(root.querySelectorAll('button')).some((button) =>
      button.textContent?.includes('Color Picker')
    );
    aiAssertTruthy(
      { name: 'SpotlightMatch', input: { query: 'color' } },
      match
    );
  });

  it('adds and removes tools from quick bar via tool window toggle', async () => {
    await setState({
      isOpen: true,
      isVisible: true,
      toolWindows: {
        colorPicker: { isOpen: true, isMinimized: false, x: 80, y: 120 }
      }
    });
    await mountContent();
    const root = getShadowRoot();
    if (!root) return;

    const toggleButton = await waitFor(() => findButtonByText(root, '+'));
    aiAssertTruthy({ name: 'QuickBarToggleButton' }, toggleButton);
    toggleButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await getState();
    aiAssertTruthy(
      { name: 'QuickBarAdded', state: stored },
      stored.quickBarToolIds.includes('colorPicker')
    );

    const removeButton = findButtonByText(root, '-');
    removeButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const storedAfter = await getState();
    aiAssertTruthy(
      { name: 'QuickBarRemoved', state: storedAfter },
      !storedAfter.quickBarToolIds.includes('colorPicker')
    );
  });

  it('toggles Live Link Preview activation state', async () => {
    const root = await mountWithTool('liveLinkPreview', { isActive: false });
    if (!root) return;
    const button = await waitFor(() => findButtonByText(root, 'Inactive'));
    aiAssertTruthy({ name: 'LiveLinkPreviewToggleButton' }, button);
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { isActive?: boolean }>;
      return toolData.liveLinkPreview?.isActive === true;
    });
    const isActive = (stored?.toolData as Record<string, { isActive?: boolean }> | undefined)
      ?.liveLinkPreview?.isActive ?? false;
    aiAssertEqual({ name: 'LiveLinkPreviewToggleState' }, isActive, true);
  });

  it('shows link preview iframe on hover when active', async () => {
    document.body.innerHTML = '<a href="https://example.com">Example</a>';
    await mountWithTool('liveLinkPreview', { isActive: true });
    const anchor = document.querySelector('a') as HTMLAnchorElement | null;
    if (!anchor) return;
    anchor.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 600));
    const frame = findPreviewFrame();
    aiAssertTruthy({ name: 'LiveLinkPreviewFrame' }, frame);
    aiAssertIncludes(
      { name: 'LiveLinkPreviewFrameSrc' },
      frame?.getAttribute('src') ?? '',
      'https://example.com'
    );
  });

  it('does not show link preview when inactive', async () => {
    document.body.innerHTML = '<a href="https://example.com">Example</a>';
    await mountWithTool('liveLinkPreview', { isActive: false });
    const anchor = document.querySelector('a') as HTMLAnchorElement | null;
    if (!anchor) return;
    anchor.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 600));
    const frame = findPreviewFrame();
    aiAssertTruthy({ name: 'LiveLinkPreviewNoFrame' }, !frame);
  });

  it('reacts to persisted activation state changes', async () => {
    document.body.innerHTML = '<a href="https://example.com">Example</a>';
    await setState({ isOpen: true, isVisible: true });
    await mountContent();
    const nextState = await getState();
    await chrome.storage.local.set({
      [STORAGE_KEY]: {
        ...nextState,
        toolData: {
          ...nextState.toolData,
          liveLinkPreview: { isActive: true }
        }
      }
    });
    await flushPromises();
    const anchor = document.querySelector('a') as HTMLAnchorElement | null;
    if (!anchor) return;
    anchor.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 600));
    const frame = findPreviewFrame();
    aiAssertTruthy({ name: 'LiveLinkPreviewPersistFrame' }, frame);
  });

  it('opens scraper builder from menu and shows modal', async () => {
    await setState({ isVisible: true, showMenuBar: true });
    await mountContent();
    const root = getShadowRoot();
    if (!root) return;

    const scraperMenu = await waitFor(() => findButtonByText(root, 'Scraper'));
    aiAssertTruthy({ name: 'ScraperMenuButton' }, scraperMenu);
    scraperMenu?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();

    const makeScraper = await waitFor(() => findButtonByText(root, 'Make Scraper'));
    aiAssertTruthy({ name: 'MakeScraperButton' }, makeScraper);
    makeScraper?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();

    const modalTitle = await waitFor(() =>
      Array.from(root.querySelectorAll('div')).find((node) =>
        node.textContent?.includes('Build Scraper')
      )
    );
    aiAssertTruthy({ name: 'BuildScraperModal' }, modalTitle);
  });

  it('minifies JSON in the JSON Minifier tool', async () => {
    await setState({
      isOpen: true,
      isVisible: true,
      toolWindows: {
        jsonMinifier: { isOpen: true, isMinimized: false, x: 80, y: 120 }
      },
      toolData: {
        jsonMinifier: { input: '{"a": 1}', output: '', error: '' }
      }
    });
    await mountContent();
    const root = getShadowRoot();
    if (!root) return;

    const input = (await waitFor(() =>
      root.querySelector('textarea[placeholder="Paste JSON here..."]')
    )) as HTMLTextAreaElement | null;
    aiAssertTruthy({ name: 'JsonMinifierInput' }, input);
    if (!input) return;
    aiAssertEqual(
      { name: 'JsonMinifierInputValue' },
      input.value,
      '{"a": 1}'
    );

    const minifyButton = findButtonByText(root, 'Minify');
    minifyButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();

    const storedAfter = await getState();
    const toolDataAfter = storedAfter.toolData as Record<
      string,
      { output?: string }
    >;
    aiAssertEqual(
      { name: 'JsonMinifierOutput', input: { raw: '{\"a\": 1}' } },
      toolDataAfter.jsonMinifier?.output ?? '',
      '{"a":1}'
    );
  });

  it('runs Code Injector and sends payload via chrome runtime', async () => {
    let payload: unknown = null;
    setRuntimeHandler('xcalibr-inject-code', (next) => {
      payload = next;
      return { ok: true };
    });
    const root = await mountWithTool('codeInjector', {
      code: 'body { background: #000; }'
    });
    if (!root) return;
    const injectButton = await waitFor(() => findButtonByText(root, 'Inject Code'));
    aiAssertTruthy({ name: 'CodeInjectorInjectButton' }, injectButton);
    injectButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    await waitFor(() => payload as { code?: string });
    aiAssertTruthy(
      { name: 'CodeInjectorPayload', state: payload },
      Boolean(payload && (payload as { code?: string }).code)
    );
  });

  it('copies color in Color Picker', async () => {
    const root = await mountWithTool('colorPicker');
    if (!root) return;
    const copyButton = await waitFor(() => findButtonByText(root, 'Copy'));
    aiAssertTruthy({ name: 'ColorPickerCopyButton' }, copyButton);
    copyButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    aiAssertTruthy(
      { name: 'ColorPickerClipboard' },
      (navigator.clipboard.writeText as unknown as { mock: { calls: unknown[] } }).mock
        .calls.length > 0
    );
  });

  it('fetches headers in Header Inspector', async () => {
    setRuntimeHandler('xcalibr-fetch-headers', () => ({
      url: 'https://example.com',
      headers: [{ name: 'Content-Security-Policy', value: "default-src 'self'" }],
      updatedAt: Date.now()
    }));
    const root = await mountWithTool('headerInspector');
    if (!root) return;
    const refreshButton = await waitFor(() => findButtonByText(root, 'Refresh'));
    aiAssertTruthy({ name: 'HeaderInspectorRefresh' }, refreshButton);
    refreshButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { headers?: unknown[] }>;
      return Boolean(toolData.headerInspector?.headers?.length);
    });
    const toolData = stored?.toolData as Record<string, { headers?: unknown[] }>;
    aiAssertTruthy(
      { name: 'HeaderInspectorData', state: toolData.headerInspector },
      (toolData.headerInspector?.headers?.length ?? 0) > 0
    );
  });

  it('detects tech fingerprint signals', async () => {
    document.head.innerHTML = '<meta name=\"generator\" content=\"WordPress\" />';
    const root = await mountWithTool('techFingerprint');
    if (!root) return;
    const scanButton = await waitFor(() => findButtonByText(root, 'Scan'));
    aiAssertTruthy({ name: 'TechFingerprintScan' }, scanButton);
    scanButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<
        string,
        { findings?: { value: string }[] }
      >;
      return (toolData.techFingerprint?.findings?.length ?? 0) > 0;
    });
    const toolData = stored?.toolData as Record<
      string,
      { findings?: { value: string }[] }
    >;
    const findings = toolData?.techFingerprint?.findings ?? [];
    aiAssertTruthy(
      { name: 'TechFingerprintFindings', state: findings },
      findings.some((entry) => entry.value.includes('WordPress'))
    );
  });

  it('loads robots.txt content', async () => {
    setRuntimeHandler('xcalibr-fetch-robots', () => ({
      url: 'https://example.com/robots.txt',
      content: 'User-agent: *',
      updatedAt: Date.now()
    }));
    const root = await mountWithTool('robotsViewer');
    if (!root) return;
    const fetchButton = await waitFor(() => findButtonByText(root, 'Fetch'));
    aiAssertTruthy({ name: 'RobotsViewerFetch' }, fetchButton);
    fetchButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const textarea = (await waitFor(() =>
      root.querySelector('textarea[placeholder=\"robots.txt will appear here...\"]')
    )) as HTMLTextAreaElement | null;
    aiAssertIncludes(
      { name: 'RobotsViewerContent' },
      textarea?.value ?? '',
      'User-agent'
    );
  });

  it('applies payloads with Form Fuzzer', async () => {
    document.body.innerHTML = '<form><input name=\"email\" /></form>';
    const root = await mountWithTool('formFuzzer');
    if (!root) return;
    const refreshButton = await waitFor(() => findButtonByText(root, 'Refresh Forms'));
    aiAssertTruthy({ name: 'FormFuzzerRefresh' }, refreshButton);
    refreshButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const applyButton = await waitFor(() => findButtonByText(root, 'Apply Payload'));
    aiAssertTruthy({ name: 'FormFuzzerApply' }, applyButton);
    applyButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const input = (await waitFor(() =>
      document.querySelector('input[name=\"email\"]')
    )) as HTMLInputElement | null;
    aiAssertTruthy(
      { name: 'FormFuzzerApplied', state: { value: input?.value } },
      Boolean(input?.value)
    );
  });

  it('encodes input in URL Encoder/Decoder', async () => {
    const root = await mountWithTool('urlCodec', {
      input: 'hello world',
      output: '',
      mode: 'decode'
    });
    if (!root) return;
    const toggleButton = await waitFor(() => findButtonByText(root, 'Decode'));
    aiAssertTruthy({ name: 'UrlCodecToggleButton' }, toggleButton);
    toggleButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { output?: string }>;
      return (toolData.urlCodec?.output ?? '').includes('hello%20world');
    });
    const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
      ?.urlCodec?.output ?? '';
    aiAssertIncludes(
      { name: 'UrlCodecOutput', input: { text: 'hello world' } },
      output,
      'hello%20world'
    );
  });

  it('parses query params in Param Analyzer', async () => {
    const root = await mountWithTool('paramAnalyzer', {
      url: 'https://example.com/?a=1&b=2',
      params: [
        { key: 'a', value: '1' },
        { key: 'b', value: '2' }
      ]
    });
    if (!root) return;
    const keyInputs = await waitFor(() =>
      Array.from(root.querySelectorAll('input[placeholder=\"Key\"]'))
    );
    aiAssertTruthy(
      { name: 'ParamAnalyzerInputs', state: { count: keyInputs?.length } },
      (keyInputs?.length ?? 0) === 2
    );
  });

  it('extracts links with Link Extractor', async () => {
    document.body.innerHTML = `
      <a href=\"https://example.com/page\">Internal</a>
      <a href=\"https://external.com\">External</a>
    `;
    const root = await mountWithTool('linkExtractor');
    if (!root) return;
    const refreshButton = findButtonByText(root, 'Refresh');
    refreshButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const countLabel = queryAllByText(root, 'internal')[0];
    aiAssertTruthy(
      { name: 'LinkExtractorCounts', state: { text: countLabel?.textContent } },
      Boolean(countLabel?.textContent)
    );
  });

  it('captures sanitized DOM snapshot', async () => {
    document.body.innerHTML = '<div>Hello</div><script>evil()</script>';
    const root = await mountWithTool('domSnapshot');
    if (!root) return;
    const captureButton = findButtonByText(root, 'Capture');
    captureButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const output = root.querySelector(
      'textarea[placeholder=\"Snapshot will appear here...\"]'
    ) as HTMLTextAreaElement | null;
    aiAssertTruthy(
      { name: 'DomSnapshotSanitized' },
      output?.value?.includes('<script>') === false
    );
  });

  it('maps assets', async () => {
    document.body.innerHTML = `
      <img src=\"https://example.com/img.png\" />
      <script src=\"https://example.com/app.js\"></script>
      <link rel=\"stylesheet\" href=\"https://example.com/app.css\" />
    `;
    const root = await mountWithTool('assetMapper');
    if (!root) return;
    const refreshButton = findButtonByText(root, 'Refresh');
    refreshButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const counts = queryAllByText(root, 'images')[0];
    aiAssertTruthy(
      { name: 'AssetMapperCounts', state: { text: counts?.textContent } },
      Boolean(counts?.textContent)
    );
  });

  it('renders request log entries', async () => {
    const root = await mountWithTool('requestLog', {
      entries: [
        { name: 'https://example.com', initiatorType: 'fetch', duration: 1, transferSize: 0, startTime: 1 }
      ]
    });
    if (!root) return;
    const entry = await waitFor(() => queryAllByText(root, 'example.com')[0]);
    aiAssertTruthy({ name: 'RequestLogEntry' }, entry);
  });

  it('replays payloads with Payload Replay', async () => {
    setRuntimeHandler('xcalibr-payload-replay', () => ({
      responseStatus: 200,
      responseHeaders: [],
      responseBody: 'ok'
    }));
    const root = await mountWithTool('payloadReplay', {
      url: 'https://example.com/api',
      method: 'GET',
      headers: '',
      body: ''
    });
    if (!root) return;
    const sendButton = findButtonByText(root, 'Send Request');
    sendButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { responseBody?: string }>;
      return (toolData.payloadReplay?.responseBody ?? '').includes('ok');
    });
    const output = (stored?.toolData as Record<string, { responseBody?: string }> | undefined)
      ?.payloadReplay?.responseBody ?? '';
    aiAssertIncludes(
      { name: 'PayloadReplayOutput' },
      output,
      'ok'
    );
  });

  it('runs CORS check', async () => {
    setRuntimeHandler('xcalibr-cors-check', () => ({
      result: { status: 200, acao: '*', acc: null, methods: 'GET', headers: null }
    }));
    const root = await mountWithTool('corsCheck', {
      url: 'https://example.com'
    });
    if (!root) return;
    const runButton = findButtonByText(root, 'Run Check');
    runButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { result?: { status?: number } }>;
      return toolData.corsCheck?.result?.status === 200;
    });
    const status = (stored?.toolData as Record<string, { result?: { status?: number } }> | undefined)
      ?.corsCheck?.result?.status;
    aiAssertEqual({ name: 'CorsCheckStatus' }, status, 200);
  });

  it('validates JSON schema', async () => {
    const root = await mountWithTool('jsonSchemaValidator', {
      schema: '{"type":"object","required":["a"],"properties":{"a":{"type":"string"}}}',
      input: '{"a":1}',
      issues: [],
      error: ''
    });
    if (!root) return;
    const validateButton = await waitFor(() => findButtonByText(root, 'Validate'));
    validateButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { issues?: string[] }>;
      return (toolData.jsonSchemaValidator?.issues?.length ?? 0) > 0;
    });
    const issues = (stored?.toolData as Record<string, { issues?: string[] }> | undefined)
      ?.jsonSchemaValidator?.issues ?? [];
    aiAssertTruthy({ name: 'JsonSchemaIssues', state: issues }, issues.some((issue) => issue.includes('Expected')));
  });

  it('runs JSON path tester', async () => {
    const root = await mountWithTool('jsonPathTester', {
      path: '$.items[0].name',
      input: '{"items":[{"name":"ok"}]}',
      output: '',
      error: ''
    });
    if (!root) return;
    const runButton = findButtonByText(root, 'Run Path');
    runButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { output?: string }>;
      return (toolData.jsonPathTester?.output ?? '').includes('ok');
    });
    const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
      ?.jsonPathTester?.output ?? '';
    aiAssertIncludes({ name: 'JsonPathOutput' }, output, 'ok');
  });

  it('diffs JSON', async () => {
    const root = await mountWithTool('jsonDiff', {
      left: '{"a":1}',
      right: '{"a":2}',
      diff: [],
      error: ''
    });
    if (!root) return;
    const compareButton = await waitFor(() => findButtonByText(root, 'Compare'));
    compareButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { diff?: string[] }>;
      return (toolData.jsonDiff?.diff ?? []).some((entry) => entry.includes('$.a'));
    });
    const diff = (stored?.toolData as Record<string, { diff?: string[] }> | undefined)
      ?.jsonDiff?.diff ?? [];
    aiAssertTruthy({ name: 'JsonDiffOutput', state: diff }, diff.length > 0);
  });

  it('formats SQL', async () => {
    const root = await mountWithTool('sqlFormatter', {
      input: 'select * from users where id=1',
      output: ''
    });
    if (!root) return;
    const button = findButtonByText(root, 'Format SQL');
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { output?: string }>;
      return (toolData.sqlFormatter?.output ?? '').includes('SELECT');
    });
    const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
      ?.sqlFormatter?.output ?? '';
    aiAssertIncludes({ name: 'SqlFormatterOutput' }, output, 'SELECT');
  });

  it('builds SQL query', async () => {
    const root = await mountWithTool('sqlQueryBuilder');
    if (!root) return;
    const tableInput = root.querySelector('input[placeholder=\"Table name\"]') as HTMLInputElement | null;
    const columnsInput = root.querySelector('input[placeholder=\"Columns (comma separated)\"]') as HTMLInputElement | null;
    if (!tableInput || !columnsInput) return;
    typeInput(tableInput, 'users');
    typeInput(columnsInput, 'id,name');
    await waitForState((state) => {
      const toolData = state.toolData as Record<string, { table?: string; columns?: string }>;
      return toolData.sqlQueryBuilder?.table === 'users';
    });
    const buildButton = await waitFor(() => findButtonByText(root, 'Build Query'));
    buildButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const output = root.querySelector('textarea[placeholder=\"SQL output...\"]') as HTMLTextAreaElement | null;
    aiAssertIncludes({ name: 'SqlQueryBuilderOutput' }, output?.value ?? '', 'SELECT');
  });

  it('converts SQL result JSON to CSV', async () => {
    const root = await mountWithTool('sqlToCsv', {
      input: '[{\"a\":1}]',
      output: ''
    });
    if (!root) return;
    const convertButton = findButtonByText(root, 'Convert');
    convertButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { output?: string }>;
      return (toolData.sqlToCsv?.output ?? '').includes('a');
    });
    const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
      ?.sqlToCsv?.output ?? '';
    aiAssertIncludes({ name: 'SqlToCsvOutput' }, output, 'a');
  });

  it('suggests index statements', async () => {
    const root = await mountWithTool('indexAdvisor', {
      table: 'users',
      columns: 'email',
      unique: false,
      output: ''
    });
    if (!root) return;
    const button = await waitFor(() => findButtonByText(root, 'Suggest Index'));
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { output?: string }>;
      return (toolData.indexAdvisor?.output ?? '').includes('CREATE');
    });
    const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
      ?.indexAdvisor?.output ?? '';
    aiAssertIncludes({ name: 'IndexAdvisorOutput' }, output, 'CREATE');
  });

  it('normalizes BSON values', async () => {
    const root = await mountWithTool('bsonViewer', {
      input: '{\"count\":{\"$numberInt\":\"5\"}}',
      output: '',
      error: ''
    });
    if (!root) return;
    const button = findButtonByText(root, 'Normalize');
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { output?: string }>;
      return (toolData.bsonViewer?.output ?? '').includes('5');
    });
    const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
      ?.bsonViewer?.output ?? '';
    aiAssertIncludes({ name: 'BsonViewerOutput' }, output, '5');
  });

  it('builds Mongo queries', async () => {
    const root = await mountWithTool('mongoQueryBuilder', {
      collection: 'users',
      filter: '{}',
      projection: '{}',
      sort: '{}',
      limit: '',
      output: '',
      error: ''
    });
    if (!root) return;
    const buildButton = findButtonByText(root, 'Build Query');
    buildButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { output?: string }>;
      return (toolData.mongoQueryBuilder?.output ?? '').includes('db.users.find');
    });
    const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
      ?.mongoQueryBuilder?.output ?? '';
    aiAssertIncludes({ name: 'MongoQueryBuilderOutput' }, output, 'db.users.find');
  });

  it('converts DynamoDB JSON', async () => {
    const root = await mountWithTool('dynamoDbConverter', {
      input: '{\"a\":1}',
      output: '',
      mode: 'toDynamo',
      error: ''
    });
    if (!root) return;
    const button = findButtonByText(root, 'Convert');
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { output?: string }>;
      return (toolData.dynamoDbConverter?.output ?? '').includes('\"N\"');
    });
    const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
      ?.dynamoDbConverter?.output ?? '';
    aiAssertIncludes({ name: 'DynamoConverterOutput' }, output, '\"N\"');
  });

  it('lints Firebase rules', async () => {
    const root = await mountWithTool('firebaseRulesLinter', {
      input: '{\"rules\":{\".read\":true}}',
      warnings: [],
      error: ''
    });
    if (!root) return;
    const button = findButtonByText(root, 'Lint Rules');
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { warnings?: string[] }>;
      return (toolData.firebaseRulesLinter?.warnings ?? []).length > 0;
    });
    const warnings = (stored?.toolData as Record<string, { warnings?: string[] }> | undefined)
      ?.firebaseRulesLinter?.warnings ?? [];
    aiAssertTruthy({ name: 'FirebaseRulesWarning', state: warnings }, warnings.length > 0);
  });

  it('fetches CouchDB documents', async () => {
    setRuntimeHandler('xcalibr-couchdb-fetch', () => ({ output: '{\"ok\":true}', error: '' }));
    const root = await mountWithTool('couchDbDocExplorer', {
      url: 'https://db.example.com/mydb/docid',
      output: '',
      error: ''
    });
    if (!root) return;
    const button = findButtonByText(root, 'Fetch Doc');
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { output?: string }>;
      return (toolData.couchDbDocExplorer?.output ?? '').includes('ok');
    });
    const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
      ?.couchDbDocExplorer?.output ?? '';
    aiAssertIncludes({ name: 'CouchDbDocOutput' }, output, 'ok');
  });

  it('captures debugger errors', async () => {
    const root = await mountWithTool('debuggerTool');
    if (!root) return;
    window.dispatchEvent(new ErrorEvent('error', { message: 'Boom' }));
    await flushPromises();
    const entry = await waitFor(() => queryAllByText(root, 'Boom')[0]);
    aiAssertTruthy({ name: 'DebuggerEntry' }, entry);
  });

  it('refreshes storage explorer', async () => {
    localStorage.setItem('hello', 'world');
    sessionStorage.setItem('foo', 'bar');
    const root = await mountWithTool('storageExplorer');
    if (!root) return;
    const button = await waitFor(() => findButtonByText(root, 'Refresh'));
    aiAssertTruthy({ name: 'StorageExplorerRefresh' }, button);
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { local?: { key: string }[] }>;
      return (toolData.storageExplorer?.local ?? []).some((item) => item.key === 'hello');
    });
    const localEntries = (stored?.toolData as Record<string, { local?: { key: string }[] }> | undefined)
      ?.storageExplorer?.local ?? [];
    aiAssertTruthy(
      { name: 'StorageExplorerEntry', state: localEntries },
      localEntries.some((item) => item.key === 'hello')
    );
  });

  it('runs snippet runner', async () => {
    const root = await mountWithTool('snippetRunner', {
      input: 'return 2 + 2',
      output: '',
      error: ''
    });
    if (!root) return;
    const button = findButtonByText(root, 'Run Snippet');
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { output?: string }>;
      return (toolData.snippetRunner?.output ?? '').includes('4');
    });
    const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
      ?.snippetRunner?.output ?? '';
    aiAssertIncludes({ name: 'SnippetRunnerOutput' }, output, '4');
  });

  it('captures lighthouse snapshot metrics', async () => {
    const root = await mountWithTool('lighthouseSnapshot');
    if (!root) return;
    const button = await waitFor(() => findButtonByText(root, 'Capture'));
    aiAssertTruthy({ name: 'LighthouseCapture' }, button);
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const metric = await waitFor(() => queryAllByText(root, 'TTFB')[0]);
    aiAssertTruthy({ name: 'LighthouseMetric' }, metric);
  });

  it('generates CSS grid', async () => {
    const root = await mountWithTool('cssGridGenerator');
    if (!root) return;
    const button = await waitFor(() => findButtonByText(root, 'Generate CSS'));
    aiAssertTruthy({ name: 'CssGridGenerate' }, button);
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const output = (await waitFor(() =>
      root.querySelector('textarea[placeholder=\"CSS output...\"]')
    )) as HTMLTextAreaElement | null;
    aiAssertIncludes({ name: 'CssGridOutput' }, output?.value ?? '', 'grid-template-columns');
  });

  it('inspects flexbox styles', async () => {
    document.body.innerHTML = '<div class=\"flex-target\" style=\"display:flex; gap: 8px;\"></div>';
    const root = await mountWithTool('flexboxInspector', {
      selector: '.flex-target',
      output: []
    });
    if (!root) return;
    const button = findButtonByText(root, 'Inspect');
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { output?: string[] }>;
      return (toolData.flexboxInspector?.output ?? []).some((entry) =>
        entry.includes('display: flex')
      );
    });
    const output = (stored?.toolData as Record<string, { output?: string[] }> | undefined)
      ?.flexboxInspector?.output ?? [];
    aiAssertTruthy({ name: 'FlexboxInspectorOutput', state: output }, output.length > 0);
  });

  it('identifies fonts', async () => {
    document.body.innerHTML = '<div class=\"font-target\" style=\"font-family: Arial; font-size: 16px;\"></div>';
    const root = await mountWithTool('fontIdentifier', {
      selector: '.font-target',
      output: []
    });
    if (!root) return;
    const button = findButtonByText(root, 'Inspect');
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { output?: string[] }>;
      return (toolData.fontIdentifier?.output ?? []).some((entry) =>
        entry.includes('font-family')
      );
    });
    const output = (stored?.toolData as Record<string, { output?: string[] }> | undefined)
      ?.fontIdentifier?.output ?? [];
    aiAssertTruthy({ name: 'FontIdentifierOutput', state: output }, output.length > 0);
  });

  it('checks contrast ratio', async () => {
    const root = await mountWithTool('contrastChecker');
    if (!root) return;
    const button = findButtonByText(root, 'Check Contrast');
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const ratio = queryAllByText(root, 'Ratio:')[0];
    aiAssertTruthy({ name: 'ContrastRatio' }, ratio);
  });

  it('opens responsive preview window', async () => {
    const openSpy = vi.spyOn(window, 'open').mockReturnValue(null);
    const root = await mountWithTool('responsivePreview');
    if (!root) return;
    const button = await waitFor(() => findButtonByText(root, 'Open Preview Window'));
    aiAssertTruthy({ name: 'ResponsivePreviewButton' }, button);
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    aiAssertTruthy({ name: 'ResponsivePreviewOpen' }, openSpy.mock.calls.length > 0);
    openSpy.mockRestore();
  });

  it('updates animation preview styles', async () => {
    const root = await mountWithTool('animationPreview', {
      css: 'animation: pulse 2s linear infinite;'
    });
    if (!root) return;
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { css?: string }>;
      return (toolData.animationPreview?.css ?? '').includes('pulse 2s');
    });
    const styleTag = await waitFor(() =>
      Array.from(root.querySelectorAll('style')).find((node) =>
        node.textContent?.includes('pulse 2s')
      )
    );
    aiAssertTruthy(
      { name: 'AnimationPreviewStyle', state: stored?.toolData },
      styleTag
    );
  });

  it('optimizes SVG', async () => {
    const root = await mountWithTool('svgOptimizer');
    if (!root) return;
    const textarea = root.querySelector('textarea[placeholder=\"<svg>...</svg>\"]') as HTMLTextAreaElement | null;
    if (!textarea) return;
    typeInput(textarea, '<svg><!--comment--><path /></svg>');
    const button = findButtonByText(root, 'Optimize SVG');
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const output = root.querySelector('textarea[placeholder=\"Optimized output...\"]') as HTMLTextAreaElement | null;
    aiAssertTruthy({ name: 'SvgOptimizerOutput' }, output?.value?.includes('comment') === false);
  });

  it('runs accessibility audit', async () => {
    document.body.innerHTML = '<img src=\"/test.png\" />';
    const root = await mountWithTool('accessibilityAudit');
    if (!root) return;
    const button = await waitFor(() => findButtonByText(root, 'Run Audit'));
    aiAssertTruthy({ name: 'AccessibilityAuditButton' }, button);
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const issue = await waitFor(() =>
      queryAllByText(root, 'Image missing alt text')[0]
    );
    aiAssertTruthy({ name: 'AccessibilityAuditIssue' }, issue);
  });

  it('decodes JWT in debugger tools', async () => {
    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
      btoa(JSON.stringify({ sub: '123' })).replace(/=/g, '') +
      '.sig';
    const root = await mountWithTool('jwtDebugger', {
      token,
      output: '',
      error: ''
    });
    if (!root) return;
    const button = findButtonByText(root, 'Decode Token');
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { payload?: string }>;
      return (toolData.jwtDebugger?.payload ?? '').includes('sub');
    });
    const payload = (stored?.toolData as Record<string, { payload?: string }> | undefined)
      ?.jwtDebugger?.payload ?? '';
    aiAssertIncludes({ name: 'JwtDebuggerPayload' }, payload, 'sub');
  });

  it('tests regex patterns', async () => {
    const root = await mountWithTool('regexTester');
    if (!root) return;
    const patternInput = root.querySelector('input[placeholder=\"Regex pattern\"]') as HTMLInputElement | null;
    const textArea = root.querySelector('textarea[placeholder=\"Test string...\"]') as HTMLTextAreaElement | null;
    if (!patternInput || !textArea) return;
    typeInput(patternInput, 'a');
    typeInput(textArea, 'aba');
    const button = findButtonByText(root, 'Run Test');
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const match = queryAllByText(root, 'a')[0];
    aiAssertTruthy({ name: 'RegexTesterMatch' }, match);
  });

  it('fetches API response', async () => {
    setRuntimeHandler('xcalibr-http-request', () => ({
      status: 200,
      statusText: 'OK',
      headers: [],
      body: 'ok'
    }));
    const root = await mountWithTool('apiResponseViewer', {
      url: 'https://api.example.com',
      response: '',
      status: '',
      error: ''
    });
    if (!root) return;
    const button = findButtonByText(root, 'Fetch Response');
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { response?: string }>;
      return (toolData.apiResponseViewer?.response ?? '').includes('ok');
    });
    const output = (stored?.toolData as Record<string, { response?: string }> | undefined)
      ?.apiResponseViewer?.response ?? '';
    aiAssertIncludes({ name: 'ApiResponseViewerOutput' }, output, 'ok');
  });

  it('runs GraphQL queries', async () => {
    setRuntimeHandler('xcalibr-http-request', () => ({
      status: 200,
      statusText: 'OK',
      headers: [],
      body: '{\"data\":{\"ok\":true}}'
    }));
    const root = await mountWithTool('graphqlExplorer', {
      url: 'https://api.example.com/graphql',
      query: '{ ping }',
      variables: '',
      response: '',
      error: ''
    });
    if (!root) return;
    const button = findButtonByText(root, 'Run Query');
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { response?: string }>;
      return (toolData.graphqlExplorer?.response ?? '').includes('data');
    });
    const output = (stored?.toolData as Record<string, { response?: string }> | undefined)
      ?.graphqlExplorer?.response ?? '';
    aiAssertIncludes({ name: 'GraphqlExplorerOutput' }, output, 'data');
  });

  it('sends REST requests', async () => {
    setRuntimeHandler('xcalibr-http-request', () => ({
      status: 200,
      statusText: 'OK',
      headers: [],
      body: 'pong'
    }));
    const root = await mountWithTool('restClient', {
      url: 'https://api.example.com',
      method: 'GET',
      headers: '',
      body: '',
      response: '',
      error: ''
    });
    if (!root) return;
    const button = findButtonByText(root, 'Send Request');
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { response?: string }>;
      return (toolData.restClient?.response ?? '').includes('pong');
    });
    const output = (stored?.toolData as Record<string, { response?: string }> | undefined)
      ?.restClient?.response ?? '';
    aiAssertIncludes({ name: 'RestClientOutput' }, output, 'pong');
  });

  it('inspects OAuth tokens', async () => {
    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
      btoa(JSON.stringify({ scope: 'read' })).replace(/=/g, '') +
      '.sig';
    const root = await mountWithTool('oauthTokenInspector', {
      token,
      output: '',
      error: ''
    });
    if (!root) return;
    const button = findButtonByText(root, 'Inspect Token');
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { output?: string }>;
      return (toolData.oauthTokenInspector?.output ?? '').includes('scope');
    });
    const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
      ?.oauthTokenInspector?.output ?? '';
    aiAssertIncludes({ name: 'OAuthTokenOutput' }, output, 'scope');
  });

  it('sends webhook payloads', async () => {
    setRuntimeHandler('xcalibr-http-request', () => ({
      status: 200,
      statusText: 'OK',
      headers: [],
      body: 'received'
    }));
    const root = await mountWithTool('webhookTester', {
      url: 'https://webhook.site/test',
      body: '',
      response: '',
      error: ''
    });
    if (!root) return;
    const button = findButtonByText(root, 'Send Webhook');
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await waitForState((state) => {
      const toolData = state.toolData as Record<string, { response?: string }>;
      return (toolData.webhookTester?.response ?? '').includes('received');
    });
    const output = (stored?.toolData as Record<string, { response?: string }> | undefined)
      ?.webhookTester?.response ?? '';
    aiAssertIncludes({ name: 'WebhookTesterOutput' }, output, 'received');
  });

  it('manages cookies', async () => {
    document.cookie = 'testcookie=abc';
    const root = await mountWithTool('cookieManager');
    if (!root) return;
    const button = await waitFor(() => findButtonByText(root, 'Refresh'));
    aiAssertTruthy({ name: 'CookieManagerRefresh' }, button);
    button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const entry = await waitFor(() => queryAllByText(root, 'testcookie')[0]);
    aiAssertTruthy({ name: 'CookieManagerEntry' }, entry);
  });
});
