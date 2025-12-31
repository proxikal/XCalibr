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
      { label: 'CSS Injector', toolId: 'codeInjector' },
      { label: 'Live Link Preview', toolId: 'liveLinkPreview' },
      { label: 'Debugger', toolId: 'debuggerTool' },
      'Performance Timeline',
      { label: 'Storage Explorer', toolId: 'storageExplorer' },
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
      },
      {
        label: 'Generators',
        items: [
          { label: 'Meta Tag Generator', toolId: 'metaTagGenerator' },
          { label: 'Open Graph Preview', toolId: 'openGraphPreviewer' },
          { label: 'Box Shadow Generator', toolId: 'boxShadowGenerator' },
          { label: 'Border Radius Generator', toolId: 'borderRadiusGenerator' },
          { label: 'Favicon Generator', toolId: 'faviconGenerator' },
          { label: 'CSS Gradient Generator', toolId: 'cssGradientGenerator' },
          { label: 'CSS Filter Generator', toolId: 'cssFilterGenerator' },
          { label: 'CSS Transform Generator', toolId: 'cssTransformGenerator' },
          { label: 'HTML Table Generator', toolId: 'htmlTableGenerator' },
          { label: 'Lorem Ipsum Generator', toolId: 'loremIpsumGenerator' },
          { label: 'Placeholder Image', toolId: 'placeholderImage' },
          { label: 'Clamp Calculator', toolId: 'clampCalculator' }
        ]
      },
      {
        label: 'Converters',
        items: [
          { label: 'Markdown to HTML', toolId: 'markdownToHtml' },
          { label: 'HTML to Markdown', toolId: 'htmlToMarkdown' },
          { label: 'Base64 Image Converter', toolId: 'base64ImageConverter' },
          { label: 'Image Compressor', toolId: 'imageCompressor' },
          { label: 'Color Palette Extractor', toolId: 'colorPaletteExtractor' }
        ]
      },
      { label: 'Keycode Info', toolId: 'keycodeInfo' },
      { label: 'Color Blindness Sim', toolId: 'colorBlindnessSimulator' },
      { label: 'Visual Grid Builder', toolId: 'visualGridBuilder' }
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
          { label: 'Param Analyzer', toolId: 'paramAnalyzer' },
          { label: 'Clickjacking Tester', toolId: 'clickjackingTester' },
          { label: 'IDOR Iterator', toolId: 'idorIterator' },
          { label: 'Directory Buster', toolId: 'directoryBuster' }
        ]
      },
      {
        label: 'Encoding',
        items: [
          { label: 'Base64 Advanced', toolId: 'base64Advanced' },
          { label: 'HTML Entity Encoder', toolId: 'htmlEntityEncoder' },
          { label: 'Hashes Generator', toolId: 'hashesGenerator' },
          { label: 'HMAC Generator', toolId: 'hmacGenerator' },
          { label: 'Password Strength', toolId: 'passwordStrength' },
          { label: 'Password Generator', toolId: 'passwordGenerator' },
          { label: 'CSP Builder', toolId: 'cspBuilder' },
          { label: 'SRI Generator', toolId: 'sriGenerator' },
          { label: 'XSS Payload', toolId: 'xssPayload' },
          { label: 'SQLi Payload', toolId: 'sqliPayload' },
          { label: 'User-Agent Generator', toolId: 'userAgent' },
          { label: 'JWT Cracker', toolId: 'jwtCracker' },
          { label: 'PEM/DER Converter', toolId: 'pemDerConverter' }
        ]
      },
      {
        label: 'Content',
        items: [
          { label: 'Link Extractor', toolId: 'linkExtractor' },
          { label: 'DOM Snapshot', toolId: 'domSnapshot' },
          { label: 'Asset Mapper', toolId: 'assetMapper' },
          { label: 'Metadata Scrubber', toolId: 'metadataScrubber' }
        ]
      },
      {
        label: 'Network',
        items: [
          { label: 'Request Log', toolId: 'requestLog' },
          { label: 'Payload Replay', toolId: 'payloadReplay' },
          { label: 'CORS Check', toolId: 'corsCheck' },
          { label: 'WebSocket Tester', toolId: 'websocketTester' },
          { label: 'CIDR Calculator', toolId: 'cidrCalculator' },
          { label: 'Subnet Cheat Sheet', toolId: 'subnetCheatSheet' },
          { label: 'MAC Vendor Lookup', toolId: 'macVendorLookup' },
          { label: 'Port Reference', toolId: 'portReference' },
          { label: 'HTTP Status Reference', toolId: 'httpStatusReference' }
        ]
      },
      {
        label: 'OSINT',
        items: [
          { label: 'Whois Lookup', toolId: 'whoisLookup' },
          { label: 'DNS Record Viewer', toolId: 'dnsRecordViewer' },
          { label: 'Reverse IP Lookup', toolId: 'reverseIpLookup' },
          { label: 'Username Search', toolId: 'usernameSearch' },
          { label: 'EXIF Metadata Viewer', toolId: 'exifMetadataViewer' },
          { label: 'Email Breach Checker', toolId: 'emailBreachChecker' },
          { label: 'SSL Certificate Decoder', toolId: 'sslCertDecoder' },
          { label: 'Google Dork Generator', toolId: 'googleDorkGenerator' },
          { label: 'Subdomain Finder', toolId: 'subdomainFinder' },
          { label: 'Wayback Machine Viewer', toolId: 'waybackMachineViewer' }
        ]
      },
      {
        label: 'DevOps',
        items: [
          { label: 'Cron Generator', toolId: 'cronGenerator' },
          { label: 'Chmod Calculator', toolId: 'chmodCalculator' },
          { label: 'Dockerfile Linter', toolId: 'dockerfileLinter' },
          { label: 'YAML Validator', toolId: 'yamlValidator' },
          { label: 'Nginx Config Generator', toolId: 'nginxConfigGenerator' },
          { label: 'Htaccess Generator', toolId: 'htaccessGenerator' }
        ]
      }
    ]
  },
  {
    label: 'Extension Dev',
    items: [
      { label: 'Manifest V3 Validator', toolId: 'manifestValidator' },
      { label: 'Permissions Reference', toolId: 'permissionsReference' },
      { label: 'i18n Message Helper', toolId: 'i18nHelper' }
    ]
  },
  {
    label: 'Red Team',
    items: [
      {
        label: 'Discovery',
        items: [
          { label: 'Comment & Secret Scraper', toolId: 'commentSecretScraper' },
          { label: 'Hidden Field Revealer', toolId: 'hiddenFieldRevealer' },
          { label: 'S3 Bucket Finder', toolId: 's3BucketFinder' },
          { label: 'Git Exposure Checker', toolId: 'gitExposureChecker' },
          { label: 'Source Map Detector', toolId: 'sourceMapDetector' },
          { label: 'API Endpoint Scraper', toolId: 'apiEndpointScraper' },
          { label: 'Admin Panel Finder', toolId: 'adminPanelFinder' },
          { label: 'Metafile Scanner', toolId: 'metafileScanner' }
        ]
      },
      {
        label: 'Storage & Secrets',
        items: [
          { label: 'Storage Secret Hunter', toolId: 'storageSecretHunter' },
          { label: 'Cookie Security Auditor', toolId: 'cookieSecurityAuditor' },
          { label: 'Env Variable Scanner', toolId: 'envVariableScanner' },
          { label: 'Default Credential Checker', toolId: 'defaultCredentialChecker' }
        ]
      },
      {
        label: 'Vulnerability Testing',
        items: [
          { label: 'Target="_blank" Auditor', toolId: 'targetBlankAuditor' },
          { label: 'Proto-Pollution Fuzzer', toolId: 'protoPollutionFuzzer' },
          { label: 'Open Redirect Tester', toolId: 'openRedirectTester' },
          { label: 'HTTP Method Tester', toolId: 'httpMethodTester' },
          { label: 'Subdomain Takeover Checker', toolId: 'subdomainTakeoverChecker' },
          { label: 'Broken Link Hijacker', toolId: 'brokenLinkHijacker' },
          { label: 'GraphQL Introspection Tester', toolId: 'graphqlIntrospectionTester' },
          { label: 'WAF Detector', toolId: 'wafDetector' }
        ]
      },
      {
        label: 'Exploit Generation',
        items: [
          { label: 'CSRF PoC Generator', toolId: 'csrfPocGenerator' },
          { label: 'CORS Exploit Generator', toolId: 'corsExploitGenerator' },
          { label: 'XXE Payload Generator', toolId: 'xxePayloadGenerator' },
          { label: 'Command Injection Payload', toolId: 'commandInjectionPayload' }
        ]
      },
      {
        label: 'Token & Auth',
        items: [
          { label: 'JWT Attack Advisor', toolId: 'jwtAttackAdvisor' },
          { label: 'PostMessage Logger', toolId: 'postMessageLogger' }
        ]
      },
      {
        label: 'Email Security',
        items: [
          { label: 'SPF/DMARC Analyzer', toolId: 'spfDmarcAnalyzer' }
        ]
      }
    ]
  },
  {
    label: 'Data & Text',
    items: [
      {
        label: 'Converters',
        items: [
          { label: 'CSV to JSON', toolId: 'csvToJson' },
          { label: 'XML to JSON', toolId: 'xmlToJson' },
          { label: 'YAML to JSON', toolId: 'yamlToJson' },
          { label: 'JSON to YAML', toolId: 'jsonToYaml' },
          { label: 'Python to JSON', toolId: 'pythonToJson' }
        ]
      },
      {
        label: 'Text Processing',
        items: [
          { label: 'Case Converter', toolId: 'caseConverter' },
          { label: 'Text Statistics', toolId: 'textStatistics' },
          { label: 'Line Sorter', toolId: 'lineSorter' },
          { label: 'List Randomizer', toolId: 'listRandomizer' },
          { label: 'Text Diff', toolId: 'textDiff' },
          { label: 'String Obfuscator', toolId: 'stringObfuscator' },
          { label: 'Escaping Tool', toolId: 'escapingTool' }
        ]
      },
      {
        label: 'Binary & Encoding',
        items: [
          { label: 'Text to Binary', toolId: 'textToBinary' },
          { label: 'Hex Viewer', toolId: 'hexViewer' },
          { label: 'Unicode Explorer', toolId: 'unicodeExplorer' },
          { label: 'Regex Highlighter', toolId: 'regexHighlighter' }
        ]
      },
      {
        label: 'Date & Time',
        items: [
          { label: 'Unix Timestamp', toolId: 'unixTimestamp' },
          { label: 'Timezone Converter', toolId: 'timezoneConverter' },
          { label: 'Stopwatch / Timer', toolId: 'stopwatchTimer' },
          { label: 'Pomodoro Timer', toolId: 'pomodoroTimer' }
        ]
      },
      {
        label: 'Calculators',
        items: [
          { label: 'Math Evaluator', toolId: 'mathEvaluator' },
          { label: 'Unit Converter', toolId: 'unitConverter' },
          { label: 'Aspect Ratio Calculator', toolId: 'aspectRatioCalculator' }
        ]
      },
      {
        label: 'ID Generators',
        items: [
          { label: 'UUID Generator', toolId: 'uuidGenerator' },
          { label: 'ObjectId Generator', toolId: 'objectIdGenerator' },
          { label: 'QR Code Generator', toolId: 'qrCodeGenerator' },
          { label: 'Barcode Generator', toolId: 'barcodeGenerator' }
        ]
      },
      {
        label: 'Code Gen',
        items: [
          { label: 'TypeScript Interface', toolId: 'typescriptInterfaceGen' },
          { label: 'Go Struct Generator', toolId: 'goStructGenerator' },
          { label: 'SQL Schema Generator', toolId: 'sqlSchemaGenerator' },
          { label: 'cURL to Fetch', toolId: 'curlToFetch' },
          { label: 'JS Minifier', toolId: 'jsMinifier' },
          { label: 'CSS Minifier', toolId: 'cssMinifier' }
        ]
      },
      {
        label: 'Git & Project',
        items: [
          { label: 'Git Command Builder', toolId: 'gitCommandBuilder' },
          { label: 'GitIgnore Generator', toolId: 'gitignoreGenerator' },
          { label: 'License Generator', toolId: 'licenseGenerator' }
        ]
      },
      {
        label: 'Productivity',
        items: [
          { label: 'Scratchpad', toolId: 'scratchpad' },
          { label: 'Todo List', toolId: 'todoList' }
        ]
      }
    ]
  }
];
