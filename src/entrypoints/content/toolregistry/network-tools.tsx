import React from 'react';
import {
  faNetworkWired,
  faTable,
  faFingerprint,
  faServer,
  faGlobe
} from '@fortawesome/free-solid-svg-icons';
import {
  CidrCalculatorTool,
  SubnetCheatSheetTool,
  MacVendorLookupTool,
  PortReferenceTool,
  HttpStatusReferenceTool
} from '../Tools';
import type {
  CidrCalculatorData,
  SubnetCheatSheetData,
  MacVendorLookupData,
  PortReferenceData,
  HttpStatusReferenceData
} from '../Tools/tool-types';
import type { ToolRegistryEntry } from './types';

export const buildNetworkTools = (): ToolRegistryEntry[] => [
  {
    id: 'cidrCalculator',
    title: 'CIDR Calculator',
    subtitle: 'Network calculations',
    category: 'Network',
    icon: faNetworkWired,
    hover: 'group-hover:border-teal-500 group-hover:text-teal-400',
    render: (data, onChange) => (
      <CidrCalculatorTool.Component
        data={data as CidrCalculatorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'subnetCheatSheet',
    title: 'Subnet Cheat Sheet',
    subtitle: 'Subnet mask reference',
    category: 'Network',
    icon: faTable,
    hover: 'group-hover:border-teal-500 group-hover:text-teal-400',
    width: 450,
    render: (data, onChange) => (
      <SubnetCheatSheetTool.Component
        data={data as SubnetCheatSheetData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'macVendorLookup',
    title: 'MAC Vendor Lookup',
    subtitle: 'OUI database',
    category: 'Network',
    icon: faFingerprint,
    hover: 'group-hover:border-teal-500 group-hover:text-teal-400',
    render: (data, onChange) => (
      <MacVendorLookupTool.Component
        data={data as MacVendorLookupData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'portReference',
    title: 'Port Reference',
    subtitle: 'TCP/UDP ports',
    category: 'Network',
    icon: faServer,
    hover: 'group-hover:border-teal-500 group-hover:text-teal-400',
    height: 500,
    render: (data, onChange) => (
      <PortReferenceTool.Component
        data={data as PortReferenceData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'httpStatusReference',
    title: 'HTTP Status Reference',
    subtitle: 'Status codes',
    category: 'Network',
    icon: faGlobe,
    hover: 'group-hover:border-teal-500 group-hover:text-teal-400',
    height: 500,
    render: (data, onChange) => (
      <HttpStatusReferenceTool.Component
        data={data as HttpStatusReferenceData | undefined}
        onChange={onChange}
      />
    )
  }
];
