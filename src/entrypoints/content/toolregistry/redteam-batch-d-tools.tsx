import React from 'react';
import {
  faCookie,
  faLink,
  faEnvelope,
  faKey,
  faFileCode,
  faTerminal,
  faShieldAlt
} from '@fortawesome/free-solid-svg-icons';
import {
  CookieSecurityAuditorTool,
  BrokenLinkHijackerTool,
  SpfDmarcAnalyzerTool,
  EnvVariableScannerTool,
  XxePayloadGeneratorTool,
  CommandInjectionPayloadTool,
  JwtAttackAdvisorTool
} from '../Tools';
import type {
  CookieSecurityAuditorData,
  BrokenLinkHijackerData,
  SpfDmarcAnalyzerData,
  EnvVariableScannerData,
  XxePayloadGeneratorData,
  CommandInjectionPayloadData,
  JwtAttackAdvisorData
} from '../Tools/tool-types';
import type { ToolRegistryEntry } from './types';

export const buildRedteamBatchDTools = (): ToolRegistryEntry[] => [
  {
    id: 'cookieSecurityAuditor',
    title: 'Cookie Security Auditor',
    subtitle: 'Audit cookie flags',
    category: 'Red Team',
    icon: faCookie,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 450,
    height: 550,
    render: (data, onChange) => (
      <CookieSecurityAuditorTool.Component
        data={data as CookieSecurityAuditorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'brokenLinkHijacker',
    title: 'Broken Link Hijacker',
    subtitle: 'Find hijackable links',
    category: 'Red Team',
    icon: faLink,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 450,
    height: 550,
    render: (data, onChange) => (
      <BrokenLinkHijackerTool.Component
        data={data as BrokenLinkHijackerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'spfDmarcAnalyzer',
    title: 'SPF/DMARC Analyzer',
    subtitle: 'Email security check',
    category: 'Red Team',
    icon: faEnvelope,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 480,
    height: 650,
    render: (data, onChange) => (
      <SpfDmarcAnalyzerTool.Component
        data={data as SpfDmarcAnalyzerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'envVariableScanner',
    title: 'Env Variable Scanner',
    subtitle: 'Find exposed env vars',
    category: 'Red Team',
    icon: faKey,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 450,
    height: 550,
    render: (data, onChange) => (
      <EnvVariableScannerTool.Component
        data={data as EnvVariableScannerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'xxePayloadGenerator',
    title: 'XXE Payload Generator',
    subtitle: 'XML entity payloads',
    category: 'Red Team',
    icon: faFileCode,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 500,
    height: 650,
    render: (data, onChange) => (
      <XxePayloadGeneratorTool.Component
        data={data as XxePayloadGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'commandInjectionPayload',
    title: 'Command Injection Payload',
    subtitle: 'OS command payloads',
    category: 'Red Team',
    icon: faTerminal,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 500,
    height: 650,
    render: (data, onChange) => (
      <CommandInjectionPayloadTool.Component
        data={data as CommandInjectionPayloadData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'jwtAttackAdvisor',
    title: 'JWT Attack Advisor',
    subtitle: 'JWT vuln analysis',
    category: 'Red Team',
    icon: faShieldAlt,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 500,
    height: 700,
    render: (data, onChange) => (
      <JwtAttackAdvisorTool.Component
        data={data as JwtAttackAdvisorData | undefined}
        onChange={onChange}
      />
    )
  }
];
