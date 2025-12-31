export type CodeInjectorData = {
  scope?: 'current' | 'all';
  code?: string;
};

export type LiveLinkPreviewData = {
  isActive?: boolean;
};

export type HeaderSeverity = 'pass' | 'warn' | 'fail' | 'info';

export type HeaderFinding = {
  header: string;
  severity: HeaderSeverity;
  message: string;
  recommendation?: string;
  value?: string;
};

export type HeaderInspectorData = {
  url?: string;
  finalUrl?: string;
  status?: number;
  headers?: { name: string; value: string }[];
  requestHeaders?: { name: string; value: string }[];
  redirectChain?: { url: string; status: number }[];
  findings?: HeaderFinding[];
  duplicateHeaders?: string[];
  error?: string;
  updatedAt?: number;
  activeTab?: 'findings' | 'raw';
};

export type TechConfidence = 'high' | 'medium' | 'low';

export type TechSignal = {
  type: 'meta' | 'script' | 'header' | 'global' | 'selector' | 'cookie' | 'favicon' | 'comment';
  evidence: string;
  source?: string;
};

export type TechFinding = {
  label: string;
  value: string;
  version?: string;
  confidence: TechConfidence;
  category: 'framework' | 'library' | 'server' | 'cdn' | 'cms' | 'analytics' | 'other';
  signals: TechSignal[];
};

export type TechFingerprintData = {
  url?: string;
  findings?: TechFinding[];
  updatedAt?: number;
  expandedFinding?: string;
};

export type RobotsUserAgentGroup = {
  userAgent: string;
  rules: { type: 'allow' | 'disallow'; path: string; isHighRisk?: boolean }[];
  crawlDelay?: number;
};

export type RobotsViewerData = {
  url?: string;
  content?: string;
  httpStatus?: number;
  lastModified?: string;
  cacheControl?: string;
  redirectedFrom?: string;
  sitemaps?: string[];
  userAgentGroups?: RobotsUserAgentGroup[];
  highRiskPaths?: string[];
  selectedUserAgent?: string;
  error?: string;
  updatedAt?: number;
};

export type PayloadFieldResult = {
  name: string;
  type: string;
  applied: boolean;
  reason?: string;
};

export type PayloadApplicationResult = {
  success: boolean;
  formFound: boolean;
  totalFields: number;
  appliedCount: number;
  skippedCount: number;
  fields: PayloadFieldResult[];
};

export type FieldPayloadMapping = {
  fieldName: string;
  payload: string;
  enabled: boolean;
};

export type DomMutation = {
  type: 'attribute' | 'childList' | 'characterData';
  target: string;
  attributeName?: string;
  oldValue?: string;
  newValue?: string;
  timestamp: number;
};

export type FormSubmitResponse = {
  status?: number;
  statusText?: string;
  headers?: { name: string; value: string }[];
  body?: string;
  url?: string;
  error?: string;
  duration?: number;
};

export type FormFuzzerData = {
  forms?: {
    index: number;
    action: string;
    method: string;
    inputs: { name: string; type: string; placeholder: string; value?: string; isCsrf?: boolean }[];
  }[];
  selectedFormIndex?: number;
  payloads?: string[];
  selectedPayload?: string;
  customPayload?: string;
  status?: string;
  lastResult?: PayloadApplicationResult;
  submitMode?: 'inject' | 'preview' | 'submit';
  fieldMappings?: FieldPayloadMapping[];
  preserveCsrf?: boolean;
  lastResponse?: FormSubmitResponse;
  domMutations?: DomMutation[];
  validationErrors?: { field: string; message: string }[];
  isSubmitting?: boolean;
};

export type UrlCodecData = {
  input?: string;
  output?: string;
  mode?: 'encode' | 'decode';
  error?: string;
};

export type ParamAnalyzerData = {
  url?: string;
  params?: { key: string; value: string }[];
};

export type LinkExtractorData = {
  internal?: string[];
  external?: string[];
  updatedAt?: number;
};

export type DomSnapshotData = {
  html?: string;
  updatedAt?: number;
};

export type AssetMapperData = {
  images?: string[];
  scripts?: string[];
  styles?: string[];
  updatedAt?: number;
};

export type RequestLogEntry = {
  name: string;
  initiatorType: string;
  duration: number;
  transferSize: number;
  startTime: number;
  // Additional timing details
  fetchStart?: number;
  domainLookupStart?: number;
  domainLookupEnd?: number;
  connectStart?: number;
  connectEnd?: number;
  secureConnectionStart?: number;
  requestStart?: number;
  responseStart?: number;
  responseEnd?: number;
  // Size details
  encodedBodySize?: number;
  decodedBodySize?: number;
  // Protocol info
  nextHopProtocol?: string;
  // Response status (if available)
  responseStatus?: number;
};

export type RequestLogData = {
  entries?: RequestLogEntry[];
  filterCategory?: string;
  page?: number;
};

export type PayloadReplayData = {
  url?: string;
  method?: string;
  headers?: string;
  body?: string;
  responseStatus?: number;
  responseHeaders?: { name: string; value: string }[];
  responseBody?: string;
  error?: string;
};

export type CorsCheckData = {
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

export type JsonMinifierData = {
  input?: string;
  output?: string;
  error?: string;
};

export type JsonPrettifierData = {
  input?: string;
  output?: string;
  error?: string;
};

export type JsonSchemaValidatorData = {
  schema?: string;
  input?: string;
  issues?: string[];
  error?: string;
};

export type JsonPathTesterData = {
  input?: string;
  path?: string;
  output?: string;
  error?: string;
};

export type JsonDiffData = {
  left?: string;
  right?: string;
  diff?: string[];
  error?: string;
};

export type SqlFormatterData = {
  input?: string;
  output?: string;
};

export type SqlQueryBuilderData = {
  table?: string;
  columns?: string;
  where?: string;
  orderBy?: string;
  limit?: string;
  output?: string;
};

export type SqlToCsvData = {
  input?: string;
  output?: string;
  error?: string;
};

export type IndexAdvisorData = {
  table?: string;
  columns?: string;
  unique?: boolean;
  output?: string;
};

export type BsonViewerData = {
  input?: string;
  output?: string;
  error?: string;
};

export type MongoQueryBuilderData = {
  collection?: string;
  filter?: string;
  projection?: string;
  sort?: string;
  limit?: string;
  output?: string;
  error?: string;
};

export type DynamoDbConverterData = {
  input?: string;
  output?: string;
  mode?: 'toDynamo' | 'fromDynamo';
  error?: string;
};

export type FirebaseRulesLinterData = {
  input?: string;
  warnings?: string[];
  error?: string;
};

export type CouchDbDocExplorerData = {
  url?: string;
  output?: string;
  error?: string;
};

export type DebuggerData = {
  entries?: { message: string; source: string; time: number }[];
};

export type StorageExplorerData = {
  local?: { key: string; value: string }[];
  session?: { key: string; value: string }[];
};

export type LighthouseSnapshotData = {
  metrics?: { label: string; value: string }[];
};

export type CssGridGeneratorData = {
  columns?: string;
  rows?: string;
  gap?: string;
  output?: string;
  isActive?: boolean;
  drawnWidth?: number;
  drawnHeight?: number;
};

export type FlexboxInspectorData = {
  selector?: string;
  output?: string[];
};

export type FontCaptureEntry = {
  id: string;
  timestamp: number;
  fontFamily: string;
  fontSize: string;
  fontWeight: string;
  lineHeight: string;
  element?: string;
};

export type FontIdentifierData = {
  isActive?: boolean;
  history?: FontCaptureEntry[];
};

export type ColorHistoryEntry = {
  id: string;
  timestamp: number;
  hex: string;
  rgb: string;
};

export type ColorPickerData = {
  color?: string;
  history?: ColorHistoryEntry[];
};

export type ContrastCheckerData = {
  foreground?: string;
  background?: string;
  ratio?: string;
  status?: string;
};

export type ResponsivePreviewData = {
  width?: string;
  height?: string;
  status?: string;
};

export type AnimationPreviewData = {
  css?: string;
};

export type SvgOptimizerData = {
  input?: string;
  output?: string;
};

export type AccessibilityAuditData = {
  issues?: string[];
};

export type JwtDebuggerData = {
  token?: string;
  header?: string;
  payload?: string;
  error?: string;
};

export type RegexTesterData = {
  pattern?: string;
  flags?: string;
  text?: string;
  matches?: string[];
  error?: string;
};

export type ApiResponseViewerData = {
  url?: string;
  response?: string;
  status?: string;
  error?: string;
};

export type GraphqlExplorerData = {
  url?: string;
  query?: string;
  variables?: string;
  response?: string;
  error?: string;
};

export type RestClientData = {
  url?: string;
  method?: string;
  headers?: string;
  body?: string;
  response?: string;
  error?: string;
};

export type OAuthTokenInspectorData = {
  token?: string;
  output?: string;
  error?: string;
};

export type WebhookTesterData = {
  url?: string;
  body?: string;
  response?: string;
  error?: string;
};

export type CookieManagerData = {
  name?: string;
  value?: string;
  cookies?: { name: string; value: string }[];
};

export type WhoisLookupData = {
  domain?: string;
  loading?: boolean;
  result?: {
    domain: string;
    status: string;
    registrar: string;
    registrant: string;
    createdDate: string;
    expiresDate: string;
    updatedDate: string;
    nameservers: string[];
  };
  error?: string;
};

export type DnsRecordViewerData = {
  domain?: string;
  loading?: boolean;
  records?: {
    type: string;
    name: string;
    value: string;
    ttl?: number;
    priority?: number;
  }[];
  filter?: string;
  error?: string;
};

export type ReverseIpLookupData = {
  ip?: string;
  loading?: boolean;
  domains?: string[];
  search?: string;
  error?: string;
};

export type PlatformResult = {
  platform: string;
  url: string;
  status: 'found' | 'not_found' | 'error';
  statusCode: number;
  error?: string;
};

export type UsernameSearchData = {
  username?: string;
  loading?: boolean;
  results?: PlatformResult[];
  filter?: 'all' | 'found' | 'not_found';
  progress?: { checked: number; total: number };
  error?: string;
};

export type ExifMetadata = {
  make?: string;
  model?: string;
  dateTime?: string;
  dateTimeOriginal?: string;
  exposureTime?: string;
  fNumber?: string;
  iso?: number;
  focalLength?: string;
  gpsLatitude?: number;
  gpsLongitude?: number;
  gpsAltitude?: number;
  software?: string;
  orientation?: number;
  imageWidth?: number;
  imageHeight?: number;
  artist?: string;
  copyright?: string;
};

export type ExifMetadataViewerData = {
  fileName?: string;
  metadata?: ExifMetadata;
  loading?: boolean;
  error?: string;
};

export type BreachInfo = {
  name: string;
  domain: string;
  breachDate: string;
  addedDate: string;
  pwnCount: number;
  description: string;
  dataClasses: string[];
  isVerified: boolean;
  isSensitive: boolean;
};

export type EmailBreachCheckerData = {
  email?: string;
  loading?: boolean;
  breaches?: BreachInfo[];
  checkedAt?: number;
  error?: string;
};

export type CertificateSubject = {
  CN?: string;
  O?: string;
  OU?: string;
  C?: string;
  ST?: string;
  L?: string;
};

export type CertificateInfo = {
  subject: CertificateSubject;
  issuer: CertificateSubject;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  fingerprint: string;
  signatureAlgorithm: string;
  keySize?: number;
  sans?: string[];
  isExpired: boolean;
  daysUntilExpiry: number;
};

export type SslCertDecoderData = {
  domain?: string;
  loading?: boolean;
  certificate?: CertificateInfo;
  fetchedAt?: number;
  error?: string;
};

export type DorkTemplate = {
  name: string;
  template: string;
  description: string;
  category: string;
};

export type DorkHistoryEntry = {
  query: string;
  timestamp: number;
};

export type GoogleDorkGeneratorData = {
  domain?: string;
  keyword?: string;
  filetype?: string;
  selectedTemplate?: string;
  generatedQuery?: string;
  history?: DorkHistoryEntry[];
};

export type SubdomainFinderData = {
  domain?: string;
  loading?: boolean;
  subdomains?: string[];
  filter?: string;
  searchedAt?: number;
  error?: string;
};

export type WaybackSnapshot = {
  timestamp: string;
  original: string;
  statuscode: string;
  mimetype: string;
};

export type WaybackMachineViewerData = {
  url?: string;
  loading?: boolean;
  snapshots?: WaybackSnapshot[];
  yearFilter?: string;
  searchedAt?: number;
  error?: string;
};

export type Base64AdvancedMode = 'standard' | 'urlSafe' | 'hex' | 'image';

export type Base64AdvancedData = {
  input?: string;
  output?: string;
  mode?: Base64AdvancedMode;
  error?: string;
  imagePreview?: string;
};

export type HtmlEntityMode = 'named' | 'decimal' | 'hex';

export type HtmlEntityEncoderData = {
  input?: string;
  output?: string;
  mode?: HtmlEntityMode;
  encodeAll?: boolean;
  error?: string;
};

export type HashesGeneratorData = {
  input?: string;
  hashes?: Record<string, string>;
  loading?: boolean;
  error?: string;
};

export type HmacKeyFormat = 'text' | 'hex';
export type HmacAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';

export type HmacGeneratorData = {
  message?: string;
  key?: string;
  keyFormat?: HmacKeyFormat;
  algorithm?: HmacAlgorithm;
  output?: string;
  loading?: boolean;
  error?: string;
};

export type PasswordStrengthScore = 0 | 1 | 2 | 3 | 4;

export type PasswordAnalysis = {
  score: PasswordStrengthScore;
  label: 'Very Weak' | 'Weak' | 'Fair' | 'Strong' | 'Very Strong';
  length: number;
  entropy: number;
  crackTime: string;
  hasUppercase: boolean;
  hasLowercase: boolean;
  hasNumbers: boolean;
  hasSymbols: boolean;
  isCommon: boolean;
  isDictionary: boolean;
  suggestions: string[];
};

export type PasswordStrengthData = {
  password?: string;
  analysis?: Partial<PasswordAnalysis>;
  showPassword?: boolean;
};

export type PasswordGeneratorData = {
  password?: string;
  length?: number;
  uppercase?: boolean;
  lowercase?: boolean;
  numbers?: boolean;
  symbols?: boolean;
  history?: string[];
  error?: string;
};

export type CspDirectives = Record<string, string[]>;

export type CspBuilderData = {
  input?: string;
  output?: string;
  directives?: CspDirectives;
  warnings?: string[];
  reportOnly?: boolean;
  analyzed?: boolean;
  error?: string;
};

export type SriAlgorithm = 'sha256' | 'sha384' | 'sha512';
export type SriResourceType = 'script' | 'style';

export type SriGeneratorData = {
  content?: string;
  url?: string;
  algorithm?: SriAlgorithm;
  resourceType?: SriResourceType;
  hash?: string;
  scriptTag?: string;
  loading?: boolean;
  error?: string;
};

export type XssPayloadCategory = 'basic' | 'events' | 'encoded' | 'polyglot' | 'filter-bypass';

export type XssPayloadData = {
  category?: XssPayloadCategory;
  selectedPayload?: string;
  customPayload?: string;
  encodedOutput?: string;
  encodeUrl?: boolean;
  encodeHtml?: boolean;
};

export type SqliPayloadCategory = 'union' | 'boolean' | 'time' | 'error' | 'stacked';

export type SqliPayloadData = {
  category?: SqliPayloadCategory;
  selectedPayload?: string;
  customPayload?: string;
  dbType?: 'mysql' | 'postgres' | 'mssql' | 'oracle';
};

export type UserAgentCategory = 'chrome' | 'firefox' | 'safari' | 'edge' | 'mobile' | 'bot';

export type UserAgentData = {
  category?: UserAgentCategory;
  selectedAgent?: string;
  customAgent?: string;
};

export type JwtCrackerData = {
  token?: string;
  wordlist?: string;
  algorithm?: 'HS256' | 'HS384' | 'HS512';
  cracking?: boolean;
  progress?: number;
  attemptCount?: number;
  foundSecret?: string;
  cracked?: boolean;
  error?: string;
};

export type PemDerConverterData = {
  input?: string;
  output?: string;
  inputFormat?: 'pem' | 'der';
  outputFormat?: 'pem' | 'der';
  certInfo?: {
    subject?: string;
    issuer?: string;
    validFrom?: string;
    validTo?: string;
    serialNumber?: string;
  };
  error?: string;
};

export type WebSocketMessage = {
  type: 'sent' | 'received';
  data: string;
  timestamp: number;
};

export type WebSocketTesterData = {
  url?: string;
  status?: 'disconnected' | 'connecting' | 'connected' | 'error';
  message?: string;
  messages?: WebSocketMessage[];
  error?: string;
};

export type MetadataField = {
  key: string;
  value: string;
};

export type MetadataScrubberData = {
  fileName?: string;
  fileSize?: number;
  fileType?: string;
  metadata?: MetadataField[];
  scrubbed?: boolean;
  scrubbedSize?: number;
  scrubbedUrl?: string;
  loading?: boolean;
  error?: string;
};

export type CidrCalculatorData = {
  cidr?: string;
  networkAddress?: string;
  broadcastAddress?: string;
  netmask?: string;
  wildcardMask?: string;
  firstHost?: string;
  lastHost?: string;
  hosts?: number;
  error?: string;
};

export type SubnetCheatSheetData = {
  selectedPrefix?: number;
};

export type MacVendorLookupData = {
  mac?: string;
  vendor?: string;
  loading?: boolean;
  error?: string;
};

export type PortReferenceData = {
  search?: string;
  selectedPort?: number;
};

export type HttpStatusReferenceData = {
  search?: string;
  selectedCode?: number;
};

export type CronGeneratorData = {
  minute?: string;
  hour?: string;
  dayOfMonth?: string;
  month?: string;
  dayOfWeek?: string;
  expression?: string;
  description?: string;
};

export type ChmodCalculatorData = {
  ownerRead?: boolean;
  ownerWrite?: boolean;
  ownerExecute?: boolean;
  groupRead?: boolean;
  groupWrite?: boolean;
  groupExecute?: boolean;
  publicRead?: boolean;
  publicWrite?: boolean;
  publicExecute?: boolean;
  octal?: string;
  symbolic?: string;
};

export type DockerfileLinterData = {
  input?: string;
  warnings?: string[];
  error?: string;
};

export type YamlValidatorData = {
  input?: string;
  valid?: boolean;
  error?: string;
};

export type NginxConfigGeneratorData = {
  serverName?: string;
  port?: string;
  root?: string;
  proxyPass?: string;
  ssl?: boolean;
  output?: string;
};

export type HtaccessGeneratorData = {
  redirects?: boolean;
  compression?: boolean;
  caching?: boolean;
  output?: string;
};

export type MetaTagGeneratorData = {
  title?: string;
  description?: string;
  keywords?: string;
  author?: string;
  viewport?: boolean;
  robots?: string;
  output?: string;
};

export type OpenGraphPreviewerData = {
  title?: string;
  description?: string;
  imageUrl?: string;
  siteName?: string;
  url?: string;
  platform?: 'facebook' | 'twitter' | 'linkedin';
};

export type BoxShadowGeneratorData = {
  horizontalOffset?: number;
  verticalOffset?: number;
  blurRadius?: number;
  spreadRadius?: number;
  color?: string;
  inset?: boolean;
  output?: string;
};

export type BorderRadiusGeneratorData = {
  topLeft?: number;
  topRight?: number;
  bottomRight?: number;
  bottomLeft?: number;
  unit?: 'px' | '%';
  output?: string;
};

export type FaviconGeneratorData = {
  character?: string;
  bgColor?: string;
  textColor?: string;
  size?: 16 | 32 | 64 | 128;
  shape?: 'square' | 'circle';
};

export type ColorStop = {
  color: string;
  position: number;
};

export type CssGradientGeneratorData = {
  type?: 'linear' | 'radial' | 'conic';
  angle?: number;
  colorStops?: ColorStop[];
  output?: string;
};

export type CssFilterGeneratorData = {
  blur?: number;
  brightness?: number;
  contrast?: number;
  grayscale?: number;
  hueRotate?: number;
  invert?: number;
  opacity?: number;
  saturate?: number;
  sepia?: number;
};

export type CssTransformGeneratorData = {
  translateX?: number;
  translateY?: number;
  rotate?: number;
  scaleX?: number;
  scaleY?: number;
  skewX?: number;
  skewY?: number;
};

export type HtmlTableGeneratorData = {
  rows?: number;
  columns?: number;
  includeHeader?: boolean;
  includeBorder?: boolean;
  headerLabels?: string[];
  cellContent?: string;
};

export type MarkdownToHtmlData = {
  input?: string;
  output?: string;
};

export type HtmlToMarkdownData = {
  input?: string;
  output?: string;
};

export type LoremIpsumGeneratorData = {
  count?: number;
  type?: 'paragraphs' | 'sentences' | 'words';
  output?: string;
};

export type PlaceholderImageData = {
  width?: number;
  height?: number;
  bgColor?: string;
  textColor?: string;
  text?: string;
  format?: 'png' | 'jpg' | 'gif' | 'webp';
};

export type Base64ImageConverterData = {
  mode?: 'imageToBase64' | 'base64ToImage';
  input?: string;
  output?: string;
  error?: string;
};

export type KeycodeInfoData = {
  lastKey?: string;
  lastCode?: string;
  lastKeyCode?: number;
  ctrlKey?: boolean;
  shiftKey?: boolean;
  altKey?: boolean;
  metaKey?: boolean;
  history?: Array<{
    key: string;
    code: string;
    keyCode: number;
    timestamp: number;
  }>;
};

export type ClampCalculatorData = {
  minViewport?: number;
  maxViewport?: number;
  minFontSize?: number;
  maxFontSize?: number;
  unit?: 'px' | 'rem';
};

export type ImageCompressorData = {
  quality?: number;
  format?: 'jpeg' | 'png' | 'webp';
  originalSize?: number;
  compressedSize?: number;
  compressedUrl?: string;
  fileName?: string;
};

export type ColorPaletteExtractorData = {
  colorCount?: number;
  colors?: string[];
  imageUrl?: string;
};

export type ManifestValidatorData = {
  input?: string;
  errors?: string[];
  warnings?: string[];
  valid?: boolean;
};

export type PermissionsReferenceData = {
  search?: string;
  selectedPermission?: string;
};

export type I18nHelperData = {
  newKey?: string;
  newMessage?: string;
  newDescription?: string;
  messages?: Array<{
    key: string;
    message: string;
    description?: string;
  }>;
  locale?: string;
};

export type CsvToJsonData = {
  input?: string;
  output?: string;
  delimiter?: string;
  hasHeader?: boolean;
  error?: string;
};

export type CaseConverterData = {
  input?: string;
  outputs?: Record<string, string>;
};

export type TextStatisticsData = {
  input?: string;
  stats?: {
    characters: number;
    charactersNoSpaces: number;
    words: number;
    sentences: number;
    paragraphs: number;
    lines: number;
    readingTime: string;
    speakingTime: string;
  };
};

export type LineSorterData = {
  input?: string;
  output?: string;
  sortType?: 'asc' | 'desc' | 'numeric' | 'random' | 'reverse';
  removeDuplicates?: boolean;
  trimLines?: boolean;
  removeEmpty?: boolean;
};

export type ListRandomizerData = {
  input?: string;
  output?: string;
  winner?: string;
  pickCount?: number;
};

export type TextDiffData = {
  text1?: string;
  text2?: string;
  diffResult?: { type: 'equal' | 'added' | 'removed'; value: string }[];
};

export type XmlToJsonData = {
  input?: string;
  output?: string;
  error?: string;
};

export type YamlToJsonData = {
  input?: string;
  output?: string;
  error?: string;
};

export type JsonToYamlData = {
  input?: string;
  output?: string;
  error?: string;
};

export type StringObfuscatorData = {
  input?: string;
  output?: string;
  method?: 'hex' | 'unicode' | 'octal' | 'base64' | 'charCode';
};

export type TextToBinaryData = {
  input?: string;
  output?: string;
  mode?: 'encode' | 'decode';
  separator?: string;
};

export type HexViewerData = {
  input?: string;
  hexOutput?: string;
  asciiOutput?: string;
  bytesPerLine?: number;
};

export type UnicodeExplorerData = {
  search?: string;
  category?: string;
  selectedChar?: string;
  charCode?: number;
};

export type RegexHighlighterData = {
  pattern?: string;
  text?: string;
  flags?: string;
  matches?: string[];
  matchCount?: number;
  error?: string;
};

export type EscapingToolData = {
  input?: string;
  output?: string;
  language?: 'json' | 'javascript' | 'python' | 'sql' | 'html' | 'url' | 'regex';
  mode?: 'escape' | 'unescape';
};

export type UnixTimestampData = {
  timestamp?: number;
  humanDate?: string;
  inputTimestamp?: string;
  inputDate?: string;
  format?: 'seconds' | 'milliseconds';
};

export type TimezoneConverterData = {
  inputTime?: string;
  sourceTimezone?: string;
  conversions?: { timezone: string; time: string; offset: string }[];
};

export type UnitConverterData = {
  value?: number;
  category?: string;
  fromUnit?: string;
  results?: { unit: string; value: string }[];
};

export type AspectRatioCalculatorData = {
  width?: number;
  height?: number;
  ratio?: string;
  newWidth?: number;
  newHeight?: number;
  mode?: 'calculate' | 'resize';
};

export type UuidGeneratorData = {
  uuid?: string;
  uuids?: string[];
  version?: 'v4' | 'v1';
  count?: number;
  uppercase?: boolean;
};

export type ObjectIdGeneratorData = {
  objectId?: string;
  objectIds?: string[];
  count?: number;
  timestamp?: string;
  showParts?: boolean;
};

export type GitCommandBuilderData = {
  category?: string;
  command?: string;
  options?: Record<string, boolean | string>;
};

export type GitIgnoreGeneratorData = {
  selectedTemplates?: string[];
  output?: string;
  customRules?: string;
};

export type LicenseGeneratorData = {
  license?: string;
  name?: string;
  year?: string;
  output?: string;
};

export type JsMinifierData = {
  input?: string;
  output?: string;
  originalSize?: number;
  minifiedSize?: number;
  error?: string;
};

export type CssMinifierData = {
  input?: string;
  output?: string;
  originalSize?: number;
  minifiedSize?: number;
  error?: string;
};

export type PythonToJsonData = {
  input?: string;
  output?: string;
  error?: string;
};

export type TypescriptInterfaceGenData = {
  input?: string;
  output?: string;
  interfaceName?: string;
  useType?: boolean;
  error?: string;
};

export type GoStructGeneratorData = {
  input?: string;
  output?: string;
  structName?: string;
  includeJsonTags?: boolean;
  omitempty?: boolean;
  error?: string;
};

export type SqlSchemaGeneratorData = {
  input?: string;
  output?: string;
  tableName?: string;
  dialect?: 'mysql' | 'postgresql' | 'sqlite';
  includePrimaryKey?: boolean;
  error?: string;
};

export type CurlToFetchData = {
  input?: string;
  output?: string;
  useAsync?: boolean;
  error?: string;
};

export type QrCodeGeneratorData = {
  text?: string;
  size?: number;
  foreground?: string;
  background?: string;
  generated?: boolean;
};

export type BarcodeGeneratorData = {
  text?: string;
  format?: 'CODE128' | 'CODE39' | 'EAN13' | 'EAN8' | 'UPC';
  height?: number;
  width?: number;
  generated?: boolean;
};

export type StopwatchTimerData = {
  mode?: 'stopwatch' | 'timer';
  elapsedMs?: number;
  timerDurationMs?: number;
  isRunning?: boolean;
  laps?: number[];
};

export type PomodoroTimerData = {
  phase?: 'work' | 'break' | 'longBreak';
  remainingMs?: number;
  isRunning?: boolean;
  sessionsCompleted?: number;
  workDuration?: number;
  breakDuration?: number;
  longBreakDuration?: number;
  sessionsUntilLongBreak?: number;
};

export type ScratchpadData = {
  content?: string;
  lastSaved?: number;
};

export type TodoItem = {
  id: string;
  text: string;
  completed: boolean;
  createdAt: number;
};

export type TodoListData = {
  items?: TodoItem[];
  filter?: 'all' | 'active' | 'completed';
};

export type MathEvaluatorData = {
  expression?: string;
  result?: string;
  history?: { expr: string; result: string }[];
  error?: string;
};

export type ColorBlindnessSimulatorData = {
  simulationType?: 'normal' | 'protanopia' | 'deuteranopia' | 'tritanopia' | 'achromatopsia';
  isActive?: boolean;
};

export type GridCell = {
  id: string;
  row: number;
  col: number;
  rowSpan: number;
  colSpan: number;
  name: string;
};

export type VisualGridBuilderData = {
  rows?: number;
  cols?: number;
  gap?: number;
  cells?: GridCell[];
  selectedCell?: string;
};

export type ClickjackingTesterData = {
  url?: string;
  tested?: boolean;
  isVulnerable?: boolean;
  error?: string;
  opacity?: number;
};

export type IdorResult = {
  id: number | string;
  status: number;
  size?: number;
  url: string;
};

export type IdorIteratorData = {
  urlPattern?: string;
  startId?: number;
  endId?: number;
  results?: IdorResult[];
  isRunning?: boolean;
  progress?: number;
  error?: string;
};

export type DirectoryResult = {
  path: string;
  status: number;
  size?: number;
};

export type DirectoryBusterData = {
  baseUrl?: string;
  customPaths?: string;
  results?: DirectoryResult[];
  isRunning?: boolean;
  progress?: number;
  delay?: number;
};

// === BATCH B: Red Team Tools #11-17 ===

export type PollutionCategory = 'basic' | 'json' | 'framework' | 'url' | 'bypass' | 'advanced';

export type PollutionResult = {
  payload: string;
  vulnerable: boolean;
  propertyChecked: string;
  category?: PollutionCategory;
  description?: string;
  error?: string;
};

export type GadgetInfo = {
  name: string;
  library: string;
  version: string;
  property: string;
  impact: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  payload: string;
};

export type ProtoPollutionFuzzerData = {
  selectedPayload?: string;
  customPayload?: string;
  results?: PollutionResult[];
  isRunning?: boolean;
  filterCategory?: PollutionCategory | 'all';
  activeTab?: 'test' | 'gadgets';
};

export type OpenRedirectTesterData = {
  targetUrl?: string;
  paramName?: string;
  results?: {
    payload: string;
    testUrl: string;
    vulnerable: boolean;
  }[];
  isRunning?: boolean;
};

export type ApiEndpoint = {
  url: string;
  method?: string;
  source: 'script' | 'fetch' | 'xhr' | 'inline' | 'attribute';
};

export type ApiEndpointScraperData = {
  endpoints?: ApiEndpoint[];
  filter?: string;
  showMethods?: boolean;
  scannedAt?: number;
};

export type FormInfo = {
  index: number;
  action: string;
  method: string;
  fields: { name: string; type: string; value: string }[];
};

export type CsrfPocGeneratorData = {
  forms?: FormInfo[];
  selectedFormIndex?: number;
  output?: string;
  autoSubmit?: boolean;
  customAction?: string;
};

export type WafSignature = {
  name: string;
  detected: boolean;
  indicators: string[];
};

export type WafDetectorData = {
  url?: string;
  signatures?: WafSignature[];
  detectedWaf?: string | null;
  isScanning?: boolean;
  scannedAt?: number;
  error?: string;
};

export type TakeoverResult = {
  subdomain: string;
  cname?: string;
  vulnerable: boolean;
  service?: string;
  fingerprint?: string;
  error?: string;
};

export type SubdomainTakeoverCheckerData = {
  subdomains?: string;
  results?: TakeoverResult[];
  isChecking?: boolean;
  checkedAt?: number;
};

export type PostMessageEntry = {
  id: string;
  timestamp: number;
  origin: string;
  data: string;
  dataType: string;
  source: string;
};

export type PostMessageLoggerData = {
  isListening?: boolean;
  messages?: PostMessageEntry[];
  filter?: string;
  expandedId?: string | null;
};

// === BATCH C: Red Team Tools #18-23 ===

export type SourceMapEntry = {
  url: string;
  scriptUrl: string;
  size?: number;
  accessible?: boolean;
};

export type SourceMapDetectorData = {
  sourceMaps?: SourceMapEntry[];
  scannedAt?: number;
  isScanning?: boolean;
  error?: string;
};

export type PathCategory = 'cms' | 'database' | 'api' | 'framework' | 'generic' | 'hosting' | 'security';

export type AdminPathResult = {
  path: string;
  status: number;
  exists: boolean;
  redirectUrl?: string;
  category: PathCategory;
  contentHints?: string[];
};

export type AdminPanelFinderData = {
  baseUrl?: string;
  results?: AdminPathResult[];
  isRunning?: boolean;
  progress?: number;
  scannedAt?: number;
  customPaths?: string;
  delay?: number;
  filterCategory?: PathCategory | 'all';
  concurrent?: number;
};

export type HttpMethodResult = {
  method: string;
  status: number;
  allowed: boolean;
  headers?: Record<string, string>;
  error?: string;
};

export type HttpMethodTesterData = {
  url?: string;
  results?: HttpMethodResult[];
  testedAt?: number;
  isTesting?: boolean;
  error?: string;
};

export type DefaultCredential = {
  vendor: string;
  product: string;
  username: string;
  password: string;
  port?: number;
  notes?: string;
};

export type DefaultCredentialCheckerData = {
  selectedCategory?: string;
  search?: string;
};

export type GraphqlIntrospectionSchema = {
  types?: string[];
  queryFields?: string[];
  mutationFields?: string[];
  subscriptionFields?: string[];
};

export type GraphqlIntrospectionTesterData = {
  url?: string;
  isEnabled?: boolean;
  schema?: GraphqlIntrospectionSchema;
  rawResponse?: string;
  testedAt?: number;
  isTesting?: boolean;
  error?: string;
};

export type CorsExploitType =
  | 'reflected-origin'
  | 'null-origin'
  | 'wildcard-credentials'
  | 'wildcard-subdomain'
  | 'prefix-match'
  | 'suffix-match'
  | 'dot-escape'
  | 'underscore-bypass'
  | 'protocol-bypass'
  | 'port-bypass'
  | 'pre-domain'
  | 'post-domain'
  | 'special-chars'
  | 'dns-rebinding';

export type CorsOutputFormat = 'html' | 'javascript' | 'python' | 'curl' | 'burp';

export type CorsTestResult = {
  acao?: string;
  acac?: string;
  acam?: string;
  status?: number;
  error?: string;
};

export type CorsExploitGeneratorData = {
  targetUrl?: string;
  exploitType?: CorsExploitType;
  generatedCode?: string;
  withCredentials?: boolean;
  customOrigin?: string;
  outputFormat?: CorsOutputFormat;
  httpMethod?: string;
  filterCategory?: 'all' | 'origin' | 'regex' | 'special';
  testResult?: CorsTestResult;
  testRunning?: boolean;
};

// === BATCH A: Red Team Tools #4-10 ===

export type CommentEntry = {
  type: 'html' | 'script' | 'css';
  content: string;
  location?: string;
};

export type SecretEntry = {
  type: string;
  value: string;
  source: string;
  line?: number;
  confidence: 'high' | 'medium' | 'low';
  entropy?: number;
};

export type CommentSecretScraperData = {
  comments?: CommentEntry[];
  secrets?: SecretEntry[];
  scannedAt?: number;
  error?: string;
  filterConfidence?: 'all' | 'high' | 'medium';
};

export type HiddenType = 'input-hidden' | 'css-hidden' | 'css-invisible' | 'css-offscreen' | 'aria-hidden';

export type ValueType = 'token' | 'uuid' | 'json' | 'base64' | 'number' | 'boolean' | 'empty' | 'text';

export type HiddenField = {
  name: string;
  value: string;
  formIndex: number;
  formAction?: string;
  id?: string;
  hiddenType: HiddenType;
  valueType: ValueType;
  element?: string;
};

export type HiddenFieldRevealerData = {
  fields?: HiddenField[];
  scannedAt?: number;
  error?: string;
  watchingMutations?: boolean;
  showCssHidden?: boolean;
};

export type CloudProvider = 'aws' | 'gcp' | 'azure' | 'digitalocean' | 'alibaba';

export type CloudBucket = {
  url: string;
  bucketName: string;
  region?: string;
  provider: CloudProvider;
  source: string;
};

// Legacy alias for backward compatibility
export type S3Bucket = CloudBucket;

export type S3BucketFinderData = {
  buckets?: CloudBucket[];
  scannedAt?: number;
  error?: string;
  filterProvider?: CloudProvider | 'all';
};

export type VcsType = 'git' | 'svn' | 'hg' | 'bzr';

export type VcsCheckResult = {
  path: string;
  status: number;
  accessible: boolean;
  contentType?: string;
  vcsType: VcsType;
  category: string;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
};

// Legacy alias for backward compatibility
export type GitCheckResult = VcsCheckResult;

export type GitExposureCheckerData = {
  checked?: boolean;
  exposed?: boolean;
  results?: VcsCheckResult[];
  domain?: string;
  scannedAt?: number;
  error?: string;
  filterVcs?: VcsType | 'all';
};

export type VulnerableLink = {
  href: string;
  text: string;
  hasNoopener: boolean;
  hasNoreferrer: boolean;
  element?: string;
};

export type TargetBlankAuditorData = {
  vulnerableLinks?: VulnerableLink[];
  totalLinks?: number;
  totalBlankLinks?: number;
  scannedAt?: number;
  error?: string;
};

export type StorageType = 'localStorage' | 'sessionStorage' | 'indexedDB' | 'cacheAPI' | 'cookie';

export type StorageFinding = {
  storage: StorageType;
  key: string;
  value: string;
  secretType: string;
  confidence: 'high' | 'medium' | 'low';
  entropy?: number;
  dbName?: string;
  storeName?: string;
};

export type StorageSecretHunterData = {
  findings?: StorageFinding[];
  totalLocalItems?: number;
  totalSessionItems?: number;
  totalIndexedDBItems?: number;
  totalCacheItems?: number;
  totalCookies?: number;
  scannedAt?: number;
  error?: string;
  filterStorage?: StorageType | 'all';
  filterConfidence?: 'all' | 'high' | 'medium';
};

export type MetafileResult = {
  file: string;
  path: string;
  status: number;
  found: boolean;
  contentPreview?: string;
  contentType?: string;
  size?: number;
};

export type MetafileScannerData = {
  results?: MetafileResult[];
  domain?: string;
  scannedAt?: number;
  scanning?: boolean;
  error?: string;
};

// === BATCH D: Red Team Tools #24-30 ===

export type CookieAuditResult = {
  name: string;
  value: string;
  domain?: string;
  path?: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'Strict' | 'Lax' | 'None' | 'Unknown';
  expires?: string;
  issues: string[];
};

export type CookieSecurityAuditorData = {
  cookies?: CookieAuditResult[];
  scannedAt?: number;
  error?: string;
};

export type LinkCheckResult = {
  url: string;
  domain: string;
  status: 'checking' | 'active' | 'expired' | 'error' | 'potential';
  statusCode?: number;
  message?: string;
};

export type BrokenLinkHijackerData = {
  links?: LinkCheckResult[];
  scannedAt?: number;
  isScanning?: boolean;
  progress?: { checked: number; total: number };
  error?: string;
};

export type SpfAnalysis = {
  valid: boolean;
  version?: string;
  mechanisms: string[];
  modifiers: string[];
  includes: string[];
  allQualifier?: string;
  warnings: string[];
};

export type DmarcAnalysis = {
  valid: boolean;
  version?: string;
  policy?: string;
  subdomainPolicy?: string;
  percentage?: number;
  reportUri?: string;
  reportUriAggregate?: string;
  warnings: string[];
};

export type SpfDmarcAnalyzerData = {
  domain?: string;
  spfRecord?: string;
  dmarcRecord?: string;
  spfAnalysis?: SpfAnalysis;
  dmarcAnalysis?: DmarcAnalysis;
  loading?: boolean;
  error?: string;
  analyzedAt?: number;
};

export type EnvFinding = {
  key: string;
  value: string;
  source: 'window' | 'meta' | 'script' | 'data-attr';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description?: string;
};

export type EnvVariableScannerData = {
  findings?: EnvFinding[];
  scannedAt?: number;
  error?: string;
};

export type XxeCategory = 'basic' | 'file-read' | 'ssrf' | 'oob' | 'blind' | 'parameter-entity' | 'filter-bypass' | 'dos';

export type XxePayloadGeneratorData = {
  category?: XxeCategory;
  selectedPayload?: string;
  customTarget?: string;
  customFile?: string;
  output?: string;
  copiedPayload?: string;
  showDtd?: boolean;
};

export type CmdCategory = 'basic' | 'chained' | 'blind' | 'time-based' | 'oob' | 'filter-bypass';
export type OsType = 'unix' | 'windows' | 'both';

export type CommandInjectionPayloadData = {
  category?: CmdCategory;
  osType?: OsType;
  selectedPayload?: string;
  customCommand?: string;
  output?: string;
};

export type JwtHeader = {
  alg?: string;
  typ?: string;
  kid?: string;
  jku?: string;
  x5u?: string;
  x5c?: string[];
  jwk?: Record<string, unknown>;
  [key: string]: unknown;
};

export type JwtAttack = {
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  payload?: string;
  applicable: boolean;
  reason?: string;
  category: 'algorithm' | 'header' | 'signature' | 'claims' | 'key';
};

export type GeneratedToken = {
  name: string;
  token: string;
  description: string;
};

export type JwtAttackAdvisorData = {
  token?: string;
  header?: JwtHeader;
  payload?: Record<string, unknown>;
  attacks?: JwtAttack[];
  analyzedAt?: number;
  error?: string;
  generatedTokens?: GeneratedToken[];
  activeTab?: 'analyze' | 'generate';
};

// === SSTI Payload Generator ===

export type SstiTemplateEngine =
  | 'jinja2' | 'twig' | 'freemarker' | 'velocity' | 'smarty'
  | 'mako' | 'erb' | 'pebble' | 'thymeleaf' | 'handlebars'
  | 'ejs' | 'pug' | 'nunjucks' | 'blade' | 'generic';

export type SstiPayloadCategory =
  | 'detection' | 'rce' | 'file-read' | 'info-disclosure'
  | 'bypass' | 'blind' | 'sandbox-escape';

export type SstiPayload = {
  name: string;
  payload: string;
  engine: SstiTemplateEngine;
  category: SstiPayloadCategory;
  description: string;
  expectedOutput?: string;
};

export type SstiPayloadGeneratorData = {
  selectedEngine?: SstiTemplateEngine | 'all';
  selectedCategory?: SstiPayloadCategory | 'all';
  customTarget?: string;
  customCommand?: string;
  copiedPayload?: string;
  filterSearch?: string;
};

// === SSRF Tester ===

export type SsrfProtocol = 'http' | 'https' | 'gopher' | 'file' | 'dict' | 'ftp' | 'ldap';

export type SsrfBypassTechnique =
  | 'ip-decimal' | 'ip-hex' | 'ip-octal' | 'ip-overflow'
  | 'dns-rebinding' | 'url-encoding' | 'parser-differential'
  | 'redirect' | 'tld-bypass' | 'localhost-variants';

export type SsrfPayload = {
  name: string;
  payload: string;
  technique: SsrfBypassTechnique;
  protocol: SsrfProtocol;
  description: string;
};

export type SsrfTesterData = {
  targetUrl?: string;
  internalTarget?: string;
  selectedTechnique?: SsrfBypassTechnique | 'all';
  selectedProtocol?: SsrfProtocol | 'all';
  generatedPayloads?: SsrfPayload[];
  customCallbackUrl?: string;
  copiedPayload?: string;
};

// === Deserialization Scanner ===

export type DeserializationLanguage = 'java' | 'php' | 'python' | 'ruby' | 'dotnet' | 'nodejs';

export type DeserializationGadget = {
  name: string;
  language: DeserializationLanguage;
  library: string;
  payload: string;
  description: string;
  severity: 'critical' | 'high' | 'medium';
};

export type DeserializationSignature = {
  name: string;
  pattern: string;
  language: DeserializationLanguage;
  description: string;
};

export type DeserializationScannerData = {
  selectedLanguage?: DeserializationLanguage | 'all';
  scanResults?: {
    found: boolean;
    signatures: string[];
    gadgets: DeserializationGadget[];
  };
  isScanning?: boolean;
  scannedAt?: number;
  activeTab?: 'scan' | 'gadgets' | 'generate';
  customCommand?: string;
  copiedPayload?: string;
};

// === Payload Encoder ===

export type EncodingType =
  | 'url' | 'double-url' | 'unicode' | 'html-entity' | 'hex'
  | 'base64' | 'base32' | 'rot13' | 'binary' | 'octal'
  | 'js-escape' | 'js-unicode' | 'css-escape' | 'sql-char';

export type PayloadEncoderData = {
  input?: string;
  output?: string;
  selectedEncodings?: EncodingType[];
  chainOrder?: EncodingType[];
  mode?: 'encode' | 'decode';
  preserveCase?: boolean;
};

// === Report Generator ===

export type ReportSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ReportFinding = {
  id: string;
  title: string;
  severity: ReportSeverity;
  category: string;
  description: string;
  impact?: string;
  remediation?: string;
  evidence?: string;
  cvss?: string;
  cwe?: string;
  references?: string[];
};

export type ReportTemplate = 'executive' | 'technical' | 'compliance' | 'pentest' | 'bugbounty';

export type ReportFormat = 'markdown' | 'html' | 'json' | 'csv';

export type ReportGeneratorData = {
  projectName?: string;
  targetUrl?: string;
  tester?: string;
  date?: string;
  findings?: ReportFinding[];
  selectedTemplate?: ReportTemplate;
  outputFormat?: ReportFormat;
  generatedReport?: string;
  activeTab?: 'findings' | 'generate' | 'export';
  editingFindingId?: string | null;
};
