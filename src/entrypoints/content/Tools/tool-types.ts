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
