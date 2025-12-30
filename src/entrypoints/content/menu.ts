export type MenuToolItem = { label: string; toolId: string };
export type MenuScraperItem = { label: string; scraperId: string };
export type MenuActionItem = { label: string; action: string };
export type MenuSubMenu = {
  label: string;
  items: (string | MenuToolItem | MenuScraperItem | MenuActionItem)[];
};
export type MenuItem =
  | string
  | MenuToolItem
  | MenuScraperItem
  | MenuActionItem
  | MenuSubMenu;
export type MenuBarItem = {
  label: string;
  items: MenuItem[];
};

export const baseMenuBarItems: MenuBarItem[] = [
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
