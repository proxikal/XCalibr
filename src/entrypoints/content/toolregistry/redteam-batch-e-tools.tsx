import React from 'react';
import {
  faFileCode,
  faNetworkWired,
  faLock,
  faSkull,
  faFileAlt
} from '@fortawesome/free-solid-svg-icons';
import {
  SstiPayloadGeneratorTool,
  SsrfTesterTool,
  PayloadEncoderTool,
  DeserializationScannerTool,
  ReportGeneratorTool
} from '../Tools';
import type {
  SstiPayloadGeneratorData,
  SsrfTesterData,
  PayloadEncoderData,
  DeserializationScannerData,
  ReportGeneratorData
} from '../Tools/tool-types';
import type { ToolRegistryEntry } from './types';

export const buildRedteamBatchETools = (): ToolRegistryEntry[] => [
  {
    id: 'sstiPayloadGenerator',
    title: 'SSTI Payload Generator',
    subtitle: 'Template injection payloads',
    category: 'Red Team',
    icon: faFileCode,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 500,
    height: 600,
    render: (data, onChange) => (
      <SstiPayloadGeneratorTool.Component
        data={data as SstiPayloadGeneratorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'ssrfTester',
    title: 'SSRF Tester',
    subtitle: 'SSRF bypass payloads',
    category: 'Red Team',
    icon: faNetworkWired,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 500,
    height: 600,
    render: (data, onChange) => (
      <SsrfTesterTool.Component
        data={data as SsrfTesterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'payloadEncoder',
    title: 'Payload Encoder',
    subtitle: 'Multi-layer encoding',
    category: 'Red Team',
    icon: faLock,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 480,
    height: 650,
    render: (data, onChange) => (
      <PayloadEncoderTool.Component
        data={data as PayloadEncoderData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'deserializationScanner',
    title: 'Deserialization Scanner',
    subtitle: '50+ gadget chains',
    category: 'Red Team',
    icon: faSkull,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 520,
    height: 650,
    render: (data, onChange) => (
      <DeserializationScannerTool.Component
        data={data as DeserializationScannerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'reportGenerator',
    title: 'Report Generator',
    subtitle: 'Security report builder',
    category: 'Red Team',
    icon: faFileAlt,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 550,
    height: 700,
    render: (data, onChange) => (
      <ReportGeneratorTool.Component
        data={data as ReportGeneratorData | undefined}
        onChange={onChange}
      />
    )
  }
];
