import React from 'react';
import {
  faMap,
  faUserShield,
  faExchangeAlt,
  faKey,
  faProjectDiagram,
  faGlobe
} from '@fortawesome/free-solid-svg-icons';
import {
  SourceMapDetectorTool,
  AdminPanelFinderTool,
  HttpMethodTesterTool,
  DefaultCredentialCheckerTool,
  GraphqlIntrospectionTesterTool,
  CorsExploitGeneratorTool
} from '../Tools';
import type {
  SourceMapDetectorData,
  AdminPanelFinderData,
  HttpMethodTesterData,
  DefaultCredentialCheckerData,
  GraphqlIntrospectionTesterData,
  CorsExploitGeneratorData
} from '../Tools/tool-types';
import type { ToolRegistryEntry } from './types';

export const buildRedteamBatchCTools = (): ToolRegistryEntry[] => [
  {
    id: 'sourceMapDetector',
    title: 'Source Map Detector',
    subtitle: 'Find exposed .map files',
    category: 'Red Team',
    icon: faMap,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 420,
    height: 500,
    render: (data, onChange) => (
      <SourceMapDetectorTool.Component
        data={data as SourceMapDetectorData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'adminPanelFinder',
    title: 'Admin Panel Finder',
    subtitle: 'Discover admin paths',
    category: 'Red Team',
    icon: faUserShield,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 450,
    height: 550,
    render: (data, onChange) => (
      <AdminPanelFinderTool.Component
        data={data as AdminPanelFinderData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'httpMethodTester',
    title: 'HTTP Method Tester',
    subtitle: 'Test allowed methods',
    category: 'Red Team',
    icon: faExchangeAlt,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 420,
    height: 520,
    render: (data, onChange) => (
      <HttpMethodTesterTool.Component
        data={data as HttpMethodTesterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'defaultCredentialChecker',
    title: 'Default Credentials',
    subtitle: 'Common default logins',
    category: 'Red Team',
    icon: faKey,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 480,
    height: 550,
    render: (data, onChange) => (
      <DefaultCredentialCheckerTool.Component
        data={data as DefaultCredentialCheckerData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'graphqlIntrospectionTester',
    title: 'GraphQL Introspection',
    subtitle: 'Test schema exposure',
    category: 'Red Team',
    icon: faProjectDiagram,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 450,
    height: 600,
    render: (data, onChange) => (
      <GraphqlIntrospectionTesterTool.Component
        data={data as GraphqlIntrospectionTesterData | undefined}
        onChange={onChange}
      />
    )
  },
  {
    id: 'corsExploitGenerator',
    title: 'CORS Exploit Generator',
    subtitle: 'Generate CORS PoC',
    category: 'Red Team',
    icon: faGlobe,
    hover: 'group-hover:border-red-500 group-hover:text-red-400',
    width: 500,
    height: 650,
    render: (data, onChange) => (
      <CorsExploitGeneratorTool.Component
        data={data as CorsExploitGeneratorData | undefined}
        onChange={onChange}
      />
    )
  }
];
