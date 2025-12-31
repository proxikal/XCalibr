// === BATCH B: Red Team Tools #11-17 ===
import React from 'react';
import {
  faBug,
  faExternalLinkAlt,
  faPlug,
  faFileCode,
  faShieldAlt,
  faLink,
  faEnvelope
} from '@fortawesome/free-solid-svg-icons';
import {
  ProtoPollutionFuzzerTool,
  OpenRedirectTesterTool,
  ApiEndpointScraperTool,
  CsrfPocGeneratorTool,
  WafDetectorTool,
  SubdomainTakeoverCheckerTool,
  PostMessageLoggerTool
} from '../Tools';
import type {
  ProtoPollutionFuzzerData,
  OpenRedirectTesterData,
  ApiEndpointScraperData,
  CsrfPocGeneratorData,
  WafDetectorData,
  SubdomainTakeoverCheckerData,
  PostMessageLoggerData
} from '../Tools/tool-types';
import type { ToolRegistryEntry } from './types';

export const buildRedTeamBatchBTools = (): ToolRegistryEntry[] => [
  {
    id: 'protoPollutionFuzzer',
    title: 'Proto-Pollution Fuzzer',
    subtitle: 'Test prototype pollution',
    category: 'CyberSec',
    icon: faBug,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 420,
    height: 520,
    render: (data, onChange) => (
      <ProtoPollutionFuzzerTool.Component
        data={data as ProtoPollutionFuzzerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'openRedirectTester',
    title: 'Open Redirect Tester',
    subtitle: 'Test redirect vulnerabilities',
    category: 'CyberSec',
    icon: faExternalLinkAlt,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 450,
    height: 550,
    render: (data, onChange) => (
      <OpenRedirectTesterTool.Component
        data={data as OpenRedirectTesterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'apiEndpointScraper',
    title: 'API Endpoint Scraper',
    subtitle: 'Extract API endpoints',
    category: 'CyberSec',
    icon: faPlug,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 480,
    height: 500,
    render: (data, onChange) => (
      <ApiEndpointScraperTool.Component
        data={data as ApiEndpointScraperData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'csrfPocGenerator',
    title: 'CSRF PoC Generator',
    subtitle: 'Generate CSRF exploits',
    category: 'CyberSec',
    icon: faFileCode,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 500,
    height: 600,
    render: (data, onChange) => (
      <CsrfPocGeneratorTool.Component
        data={data as CsrfPocGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'wafDetector',
    title: 'WAF Detector',
    subtitle: 'Detect web firewalls',
    category: 'CyberSec',
    icon: faShieldAlt,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 420,
    height: 550,
    render: (data, onChange) => (
      <WafDetectorTool.Component
        data={data as WafDetectorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'subdomainTakeoverChecker',
    title: 'Subdomain Takeover Checker',
    subtitle: 'Check CNAME takeover',
    category: 'CyberSec',
    icon: faLink,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 450,
    height: 550,
    render: (data, onChange) => (
      <SubdomainTakeoverCheckerTool.Component
        data={data as SubdomainTakeoverCheckerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'postMessageLogger',
    title: 'PostMessage Logger',
    subtitle: 'Log postMessage events',
    category: 'CyberSec',
    icon: faEnvelope,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 450,
    height: 500,
    render: (data, onChange) => (
      <PostMessageLoggerTool.Component
        data={data as PostMessageLoggerData | undefined}
        onChange={onChange}
      />
    )
  }
];
