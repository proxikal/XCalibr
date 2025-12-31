import React from 'react';
import {
  faShieldHalved,
  faFingerprint,
  faRobot,
  faFlask,
  faWaveSquare,
  faSliders,
  faLink,
  faFileCode,
  faSitemap,
  faTable,
  faBug,
  faGlobe,
  faCode,
  faLock,
  faNetworkWired,
  faImage,
  faSquare,
  faHashtag,
  faFolder
} from '@fortawesome/free-solid-svg-icons';
import {
  HeaderInspectorTool,
  TechFingerprintTool,
  RobotsViewerTool,
  FormFuzzerTool,
  UrlCodecTool,
  ParamAnalyzerTool,
  LinkExtractorTool,
  DomSnapshotTool,
  AssetMapperTool,
  RequestLogTool,
  PayloadReplayTool,
  CorsCheckTool,
  Base64AdvancedTool,
  HtmlEntityEncoderTool,
  HashesGeneratorTool,
  HmacGeneratorTool,
  PasswordStrengthTool,
  PasswordGeneratorTool,
  CspBuilderTool,
  SriGeneratorTool,
  XssPayloadTool,
  SqliPayloadTool,
  UserAgentTool,
  JwtCrackerTool,
  PemDerConverterTool,
  WebSocketTesterTool,
  MetadataScrubberTool,
  ClickjackingTesterTool,
  IdorIteratorTool,
  DirectoryBusterTool
} from '../Tools';
import type {
  HeaderInspectorData,
  TechFingerprintData,
  RobotsViewerData,
  FormFuzzerData,
  UrlCodecData,
  ParamAnalyzerData,
  LinkExtractorData,
  DomSnapshotData,
  AssetMapperData,
  RequestLogData,
  PayloadReplayData,
  CorsCheckData,
  Base64AdvancedData,
  HtmlEntityEncoderData,
  HashesGeneratorData,
  HmacGeneratorData,
  PasswordStrengthData,
  PasswordGeneratorData,
  CspBuilderData,
  SriGeneratorData,
  XssPayloadData,
  SqliPayloadData,
  UserAgentData,
  JwtCrackerData,
  PemDerConverterData,
  WebSocketTesterData,
  MetadataScrubberData,
  ClickjackingTesterData,
  IdorIteratorData,
  DirectoryBusterData
} from '../Tools/tool-types';
import {
  detectTechnologies,
  getFormsSnapshot,
  applyPayloadToForm,
  parseQueryParams,
  extractLinksFromDocument,
  sanitizeHtmlSnapshot,
  mapAssetsFromDocument
} from '../Tools/helpers';
import type { ToolRegistryEntry } from './types';

export const buildCybersecTools = (): ToolRegistryEntry[] => [
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
    id: 'clickjackingTester',
    title: 'Clickjacking Tester',
    subtitle: 'Test X-Frame-Options',
    category: 'CyberSec',
    icon: faSquare,
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
