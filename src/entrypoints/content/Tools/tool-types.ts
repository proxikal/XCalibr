export type CodeInjectorData = {
  scope?: 'current' | 'all';
  code?: string;
};

export type LiveLinkPreviewData = {
  isActive?: boolean;
};

export type HeaderInspectorData = {
  url?: string;
  status?: number;
  headers?: { name: string; value: string }[];
  error?: string;
  updatedAt?: number;
};

export type TechFingerprintData = {
  url?: string;
  findings?: { label: string; value: string }[];
  updatedAt?: number;
};

export type RobotsViewerData = {
  url?: string;
  content?: string;
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

export type FormFuzzerData = {
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
  lastResult?: PayloadApplicationResult;
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
